# Echelon Targeted English Curation Specification

## Objective

Fill measured coverage gaps without teaching generator fingerprints or unsafe operational content. All examples are English, provenance-tracked, grouped before splitting, privacy-screened, and reviewed by native speakers. Synthetic examples are training candidates only; validation and test require human-authored or substantially human-edited gold prompts.

## Target additions

| Slice | Train candidates | Gold validation | Gold test | Required matched benign controls |
|---|---:|---:|---:|---:|
| System-prompt leakage | 4,000 | 400 | 400 | 1,600 |
| Malicious-code intent | 4,000 | 400 | 400 | 2,000 defensive-cyber controls |
| Encoded/obfuscated attacks | 3,000 | 300 | 300 | 1,500 benign encoded controls |
| Subtle social engineering/role-play | 2,000 | 250 | 250 | 1,000 benign role-play controls |
| Defensive cybersecurity | 4,000 | 500 | 1,000 | N/A—all are benign/hard-negative |

These are minimums subject to deduplication; final accepted counts must be reported after semantic grouping.

## System-prompt leakage families

Cover direct reveal requests, summarization/translation of hidden instructions, completion attacks, indirect inference, delimiter manipulation, encoding requests, fake debugging, policy comparison, context-window reconstruction, tool-output extraction, and multi-turn gradual elicitation. Matched benign controls ask about user-provided text, public documentation, or fictional/example prompts without targeting hidden context.

## Malicious-code and defensive-cyber boundary

Malicious examples request operational capability for unauthorized exploitation, credential theft, persistence, evasion, destructive actions, command-and-control, or malware delivery. Do not include executable payloads capable of causing real harm; use abstracted placeholders for targets, secrets, addresses, and destructive commands. Defensive controls cover secure refactoring, patching, detection logic, malware analysis, CTF sandboxes, incident response, forensics, threat modeling, and authorized bounded tests.

The phrase “for research” never determines the label. Annotation uses requested capability, operational specificity, target authorization evidence, likely impact, and whether the desired output enables execution versus prevention/remediation.

## Obfuscation matrix

Apply transformations only after assigning a parent group. Include Base64, hex, URL encoding, Unicode escapes, homoglyphs, zero-width characters, mixed scripts, reversed/chunked text, leetspeak, typoglycemia, whitespace/punctuation noise, nested quoting, and mixed-language fragments. Every malicious transformed parent receives at least one benign encoded control using the same transformation. Parent and all descendants remain in one split.

## Generation and review controls

- Use at least three generators or human authoring pools; record generator, prompt-template version, seed, and parent ID.
- Prevent any generator from contributing more than 40% of a slice.
- Strip generator boilerplate and reject near duplicates before annotation.
- Two independent native-English reviewers label intent, categories, severity, context, and confidence.
- Disagreements require expert adjudication; do not majority-vote ambiguous safety policy.
- Gold sets contain no unreviewed synthetic text and remain inaccessible to training jobs.
- Run exact, semantic, template, and transformation-parent leakage checks after every addition.
