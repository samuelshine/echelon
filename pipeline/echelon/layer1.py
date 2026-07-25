"""Ultra-low-latency heuristic risk analysis with bounded deobfuscation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import time
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

from echelon.automaton import AhoCorasick, PhraseRule
from echelon.contracts import Evidence, InputStats, LayerResult, Route, ThreatCategory

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = ROOT / "configs" / "layer1_rules.json"
CATEGORIES = tuple(category.value for category in ThreatCategory)
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){3,}")


@dataclass(frozen=True, slots=True)
class CompiledRegexRule:
    pattern: re.Pattern[str]
    code: str
    category: ThreatCategory
    weight: float
    correlation_group: str


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return float(value)


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def load_rules(path: Path = DEFAULT_RULES) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Layer 1 rules JSON: {exc.msg}") from exc
    if not isinstance(config, dict):
        raise ValueError("Layer 1 rules must be a JSON object")
    thresholds, limits, scoring = config.get("thresholds", {}), config.get("limits", {}), config.get("scoring", {})
    passed = _number(thresholds.get("pass_below"), "pass_below", 0, 1)
    blocked = _number(thresholds.get("block_at_or_above"), "block_at_or_above", 0, 1)
    if passed >= blocked:
        raise ValueError("pass_below must be lower than block_at_or_above")
    _integer(limits.get("max_scan_chars"), "max_scan_chars", 256, 1_000_000)
    _integer(limits.get("entropy_sample_chars"), "entropy_sample_chars", 64, 65_536)
    _integer(limits.get("max_encoded_token_chars"), "max_encoded_token_chars", 16, 65_536)
    _integer(limits.get("max_decoded_bytes"), "max_decoded_bytes", 16, 65_536)
    _integer(limits.get("max_decoded_candidates"), "max_decoded_candidates", 1, 32)
    _number(scoring.get("secondary_category_factor"), "secondary_category_factor", 0, 1)
    _number(scoring.get("obfuscation_corroboration_bonus"), "obfuscation_corroboration_bonus", 0, 1)
    _number(scoring.get("repeat_factor"), "repeat_factor", 0, 1)
    _number(scoring.get("max_repeat_bonus"), "max_repeat_bonus", 0, 1)
    seen_codes: set[str] = set()
    for family in ("phrases", "regex_rules"):
        rules = config.get(family)
        if not isinstance(rules, list) or not rules:
            raise ValueError(f"{family} must be a non-empty list")
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"{family}[{index}] must be an object")
            code = rule.get("code")
            if not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{3,64}", code):
                raise ValueError(f"{family}[{index}] has invalid code")
            if code in seen_codes:
                raise ValueError(f"duplicate rule code: {code}")
            seen_codes.add(code)
            try:
                ThreatCategory(rule.get("category"))
            except ValueError as exc:
                raise ValueError(f"{family}[{index}] has invalid category") from exc
            _number(rule.get("weight"), f"{family}[{index}].weight", 0.01, 1)
            field = "phrase" if family == "phrases" else "pattern"
            if not isinstance(rule.get(field), str) or not rule[field]:
                raise ValueError(f"{family}[{index}] has invalid {field}")
            if family == "regex_rules":
                try:
                    re.compile(rule[field], re.IGNORECASE | re.DOTALL)
                except re.error as exc:
                    raise ValueError(f"invalid regex for {code}: {exc}") from exc
            group = rule.get("group", code)
            if not isinstance(group, str) or not re.fullmatch(r"[a-z0-9_]{3,64}", group):
                raise ValueError(f"{family}[{index}] has invalid group")
    return config, hashlib.sha256(raw).hexdigest()


def normalize_text(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in Counter(text).values())


def printable_text(raw: bytes, limit: int) -> str | None:
    if not raw or len(raw) > limit:
        return None
    text = raw.decode("utf-8", errors="replace")
    printable = sum(character.isprintable() or character.isspace() for character in text)
    if printable / max(1, len(text)) < 0.75:
        return None
    return text


class HeuristicAnalyzer:
    def __init__(self, rules_path: Path = DEFAULT_RULES):
        self.config, self.ruleset_sha256 = load_rules(rules_path)
        phrase_rules = [
            PhraseRule(
                phrase=normalize_text(rule["phrase"]), code=rule["code"],
                category=rule["category"], weight=float(rule["weight"]),
                correlation_group=rule.get("group", rule["code"]),
            )
            for rule in self.config["phrases"]
        ]
        self.automaton = AhoCorasick(phrase_rules)
        self.regex_rules = tuple(
            CompiledRegexRule(
                pattern=re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL),
                code=rule["code"], category=ThreatCategory(rule["category"]),
                weight=float(rule["weight"]), correlation_group=rule.get("group", rule["code"]),
            )
            for rule in self.config["regex_rules"]
        )

    def _bounded_view(self, text: str) -> tuple[str, bool]:
        maximum = self.config["limits"]["max_scan_chars"]
        if len(text) <= maximum:
            return text, False
        marker = "\n[bounded-middle-omitted]\n"
        remaining = maximum - len(marker)
        head = remaining // 2
        tail = remaining - head
        return text[:head] + marker + text[-tail:], True

    def _scan(self, text: str, *, decoded: bool) -> list[Evidence]:
        normalized = normalize_text(text)
        results: list[Evidence] = []
        repeat_factor = self.config["scoring"]["repeat_factor"]
        repeat_cap = self.config["scoring"]["max_repeat_bonus"]
        for rule, occurrences in self.automaton.find(normalized).values():
            bonus = min(repeat_cap, max(0, occurrences - 1) * repeat_factor)
            weight = min(1.0, rule.weight * (0.92 if decoded else 1.0) + bonus)
            results.append(Evidence(
                code=rule.code, category=ThreatCategory(rule.category), weight=weight,
                source="phrase", correlation_group=rule.correlation_group,
                occurrences=occurrences, decoded=decoded,
            ))
        for rule in self.regex_rules:
            occurrences = 0
            for _ in rule.pattern.finditer(normalized):
                occurrences += 1
                if occurrences >= 3:
                    break
            if occurrences:
                bonus = min(repeat_cap, max(0, occurrences - 1) * repeat_factor)
                weight = min(1.0, rule.weight * (0.92 if decoded else 1.0) + bonus)
                results.append(Evidence(
                    code=rule.code, category=rule.category, weight=weight,
                    source="regex", correlation_group=rule.correlation_group,
                    occurrences=occurrences, decoded=decoded,
                ))
        return results

    def _decoded_candidates(self, text: str) -> tuple[list[tuple[str, str]], list[Evidence]]:
        limits = self.config["limits"]
        token_limit, byte_limit = limits["max_encoded_token_chars"], limits["max_decoded_bytes"]
        maximum = limits["max_decoded_candidates"]
        candidates: list[tuple[str, str]] = []
        evidence: list[Evidence] = []
        seen: set[str] = set()

        def admit(kind: str, decoded: str | None, weight: float) -> None:
            if decoded is None or len(candidates) >= maximum:
                return
            normalized = normalize_text(decoded)
            if not normalized or normalized in seen:
                return
            seen.add(normalized)
            candidates.append((kind, decoded))
            evidence.append(Evidence(
                code=f"obf_{kind}_payload", category=ThreatCategory.ADVERSARIAL_OBFUSCATION,
                weight=weight, source="decoder", correlation_group=f"obf_{kind}_payload", decoded=False,
            ))

        for match in BASE64_TOKEN.finditer(text):
            token = match.group(0)
            if len(token) > token_limit or len(candidates) >= maximum:
                continue
            try:
                padded = token + "=" * (-len(token) % 4)
                admit("base64", printable_text(base64.b64decode(padded, validate=True), byte_limit), 0.10)
            except (binascii.Error, ValueError):
                continue
        for match in HEX_TOKEN.finditer(text):
            token = match.group(0)
            if len(token) > token_limit or len(candidates) >= maximum:
                continue
            try:
                admit("hex", printable_text(bytes.fromhex(token), byte_limit), 0.10)
            except ValueError:
                continue
        percent_bytes = re.findall(r"%[0-9A-Fa-f]{2}", text)
        if len(percent_bytes) >= 2 and len(text) <= token_limit:
            admit("url", printable_text(unquote_to_bytes(text), byte_limit), 0.08)
        for match in UNICODE_ESCAPE.finditer(text):
            token = match.group(0)
            if len(token) <= token_limit:
                try:
                    admit("unicode_escape", token.encode("ascii").decode("unicode_escape"), 0.08)
                except UnicodeDecodeError:
                    pass
        reversed_text = text[::-1]
        if len(text) >= 20 and len(text) <= token_limit:
            reversed_matches = self.automaton.find(normalize_text(reversed_text))
            if reversed_matches:
                admit("reversed", reversed_text, 0.20)
        return candidates, evidence

    @staticmethod
    def _score(evidence: list[Evidence], config: dict[str, Any]) -> tuple[dict[str, float], float]:
        weights: dict[str, dict[str, float]] = defaultdict(dict)
        for item in evidence:
            group_weights = weights[item.category.value]
            group_weights[item.correlation_group] = max(group_weights.get(item.correlation_group, 0.0), item.weight)
        category_scores = {category: 0.0 for category in CATEGORIES}
        for category, grouped_values in weights.items():
            complement = 1.0
            for value in grouped_values.values():
                complement *= 1.0 - value
            category_scores[category] = round(min(1.0, 1.0 - complement), 6)
        ranked = sorted(category_scores.values(), reverse=True)
        overall = ranked[0] + config["scoring"]["secondary_category_factor"] * ranked[1]
        obfuscation = category_scores[ThreatCategory.ADVERSARIAL_OBFUSCATION.value]
        non_obfuscation = max(
            score for category, score in category_scores.items()
            if category != ThreatCategory.ADVERSARIAL_OBFUSCATION.value
        )
        if obfuscation >= 0.08 and non_obfuscation >= 0.35:
            overall += config["scoring"]["obfuscation_corroboration_bonus"]
        return category_scores, round(min(1.0, overall), 6)

    def analyze(self, text: str) -> LayerResult:
        if not isinstance(text, str):
            raise TypeError("prompt must be a string")
        started = time.perf_counter_ns()
        view, truncated = self._bounded_view(text)
        sample = view[: self.config["limits"]["entropy_sample_chars"]]
        entropy = shannon_entropy(sample)
        controls = sum(
            unicodedata.category(character) in {"Cc", "Cf"} and not character.isspace()
            for character in sample
        )
        control_ratio = controls / max(1, len(sample))
        evidence = self._scan(view, decoded=False)
        decoded, decoder_evidence = self._decoded_candidates(view)
        evidence.extend(decoder_evidence)
        for _, candidate in decoded:
            evidence.extend(self._scan(candidate, decoded=True))
        if len(text) > self.config["limits"]["max_scan_chars"]:
            evidence.append(Evidence(
                code="input_scan_truncated", category=ThreatCategory.ADVERSARIAL_OBFUSCATION,
                weight=0.12, source="structural", correlation_group="input_scan_truncated",
            ))
        if len(sample) >= 64 and entropy >= 5.2:
            evidence.append(Evidence(
                code="input_high_entropy", category=ThreatCategory.ADVERSARIAL_OBFUSCATION,
                weight=0.06, source="structural", correlation_group="input_high_entropy",
            ))
        if control_ratio >= 0.02:
            evidence.append(Evidence(
                code="input_control_characters", category=ThreatCategory.ADVERSARIAL_OBFUSCATION,
                weight=min(0.35, 0.08 + control_ratio), source="structural",
                correlation_group="input_control_characters",
            ))
        evidence.sort(key=lambda item: (item.category.value, item.code, item.decoded))
        scores, risk = self._score(evidence, self.config)
        thresholds = self.config["thresholds"]
        if risk < thresholds["pass_below"]:
            route = Route.PASS
        elif risk >= thresholds["block_at_or_above"]:
            route = Route.BLOCK
        else:
            route = Route.ESCALATE
        duration = max(1, (time.perf_counter_ns() - started) // 1_000)
        return LayerResult(
            layer="heuristic_v1", risk_score=risk, category_scores=scores, route=route,
            evidence=tuple(evidence),
            stats=InputStats(
                original_chars=len(text), scanned_chars=len(view), truncated=truncated,
                entropy_bits_per_char=round(entropy, 6),
                control_character_ratio=round(control_ratio, 6), decoded_candidates=len(decoded),
            ),
            duration_us=duration, ruleset_sha256=self.ruleset_sha256,
        )
