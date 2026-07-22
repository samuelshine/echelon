"""Compact Aho–Corasick implementation built once per ruleset."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class PhraseRule:
    phrase: str
    code: str
    category: str
    weight: float
    correlation_group: str


class AhoCorasick:
    def __init__(self, rules: Iterable[PhraseRule]):
        self._next: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._output: list[list[PhraseRule]] = [[]]
        for rule in rules:
            state = 0
            for character in rule.phrase:
                target = self._next[state].get(character)
                if target is None:
                    target = len(self._next)
                    self._next[state][character] = target
                    self._next.append({})
                    self._fail.append(0)
                    self._output.append([])
                state = target
            self._output[state].append(rule)
        queue = deque(self._next[0].values())
        while queue:
            state = queue.popleft()
            for character, target in self._next[state].items():
                queue.append(target)
                fallback = self._fail[state]
                while fallback and character not in self._next[fallback]:
                    fallback = self._fail[fallback]
                self._fail[target] = self._next[fallback].get(character, 0)
                self._output[target].extend(self._output[self._fail[target]])

    def find(self, text: str) -> dict[str, tuple[PhraseRule, int]]:
        """Return one rule object and occurrence count per rule code."""
        state = 0
        matches: dict[str, tuple[PhraseRule, int]] = {}
        for character in text:
            while state and character not in self._next[state]:
                state = self._fail[state]
            state = self._next[state].get(character, 0)
            for rule in self._output[state]:
                previous = matches.get(rule.code)
                matches[rule.code] = (rule, 1 if previous is None else previous[1] + 1)
        return matches
