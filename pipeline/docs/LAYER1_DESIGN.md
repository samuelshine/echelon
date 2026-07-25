# Echelon Layer 1: Heuristic Risk Engine

Layer 1 is a deterministic, dependency-free first-pass detector. It returns calibrated-looking risk values only as heuristic evidence; the values are not statistically calibrated probabilities. Production enforcement remains disabled until thresholds are fitted and validated on approved, group-isolated human-reviewed data.

## Contract

`HeuristicAnalyzer.analyze(text)` returns an immutable `LayerResult` containing:

- Overall risk score in `[0, 1]`.
- One score per threat category.
- `pass`, `escalate`, or `block` routing.
- Content-free evidence codes, weights, sources, counts, and decoded flags.
- Content-free input statistics and execution time.
- SHA-256 of the exact ruleset.

It never returns or logs prompt text, decoded content, or matched substrings.

## Detection path

1. Bound scanning to exactly 100,000 characters using equal head and tail views.
2. Normalize Unicode with NFKC, case-fold, and collapse whitespace.
3. Match literal phrases using one prebuilt Aho–Corasick automaton.
4. Apply precompiled, bounded regex rules.
5. Measure entropy and Unicode control/format-character density.
6. Extract at most six encoded candidates.
7. Decode Base64, hex, URL-percent encoding, Unicode escapes, and full reversal under strict size and printability limits.
8. Scan decoded text once with a small weight discount.

Isolated encoding is weak evidence because benign encoded content is common. Encoding plus decoded malicious evidence receives a small corroboration bonus. Decoder output is never executed.

## Scoring

Rules declare a category, base weight, and correlation group. Literal and regex rules describing the same behavior share a group, so overlapping matches cannot masquerade as independent evidence. Repetition adds at most `0.16` to a rule before grouping.

For category `c`, retain the maximum weight in every correlation group and combine distinct groups with noisy-or:

```text
category_risk(c) = 1 - product(1 - max_group_weight)
```

Let `s1` and `s2` be the two highest category risks:

```text
overall = min(1, s1 + 0.12 * s2 + obfuscation_corroboration)
```

The corroboration term is `0.08` only when obfuscation is at least `0.08` and another category is at least `0.35`.

Current shadow thresholds are explicit and non-overlapping:

- `risk < 0.35`: pass.
- `0.35 <= risk < 0.90`: escalate.
- `risk >= 0.90`: block.

These boundaries are configuration scaffolding, not approved production operating points.

## Defensive cybersecurity policy

Generic dual-use terminology has deliberately weak weight. For example, an authorized incident-response request about detecting a reverse shell scores `0.24` and passes. An action-plus-capability request to write a reverse shell scores in the escalation range. Explicit malware generation combined with credential theft or defense evasion reaches the block range. Layer 1 does not trust claims of authorization and does not attempt a semantic allowlist; ambiguous dual-use cases route to later layers.

## Resource controls

- Maximum scan: 100,000 characters, preserving both ends.
- Entropy sample: 4,096 characters.
- Encoded token: 4,096 characters.
- Decoded output: 8,192 bytes.
- Decoded candidates: six.
- Regex repetitions counted only to three.
- One deobfuscation pass; no recursive expansion.

Configuration loading fails closed on invalid thresholds, limits, categories, rule codes, duplicate codes, weights, groups, or regex syntax.

## Benchmark

The content-free local microbenchmark runs the complete analyzer path over six short fixtures. With 2,000 warm-up and 30,000 measured iterations it produced:

- Median: `27.958 us`.
- p95: `38.750 us`.
- p99: `40.083 us`.
- Maximum: `340.083 us`.
- Throughput: `33,572 prompts/second`.

The result is stored in `data/reports/layer1_benchmark.json`. It is a development-machine microbenchmark, not a production SLO guarantee. CI and deployment hardware need separate regression bounds.

## Known limits

- Rule evidence is not a probability and will not generalize like a semantic classifier.
- Quoted or educational attack phrases may still escalate.
- NFKC handles compatibility forms but not every cross-script homoglyph.
- Head/tail bounding can miss content hidden only in a very long middle section.
- Toxicity, nuanced intent, multilingual attacks, and novel social engineering primarily require Layers 2 and 3.
- Ruleset and thresholds require reviewed false-positive, recall, and latency evaluation before enforcement.
