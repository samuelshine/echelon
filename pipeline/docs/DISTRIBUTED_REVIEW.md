# Echelon Distributed Review v0.2

This procedure supports independent reviewers in different locations. The repository contains only authenticated encrypted primary kits; their passphrases travel separately through an access-controlled channel. Decrypted prompts, local databases, and passphrases never enter Git. Git receives prompt-free JSON submissions only after both primary reviewers finish.

## Recommended clone-and-run workflow

After the coordinator pushes the encrypted kits to `rnd`, each reviewer needs only repository access and their separately delivered passphrase.

Reviewer A:

```bash
git clone <PRIVATE_REPOSITORY_URL> echelon
cd echelon
git switch rnd
python3 scripts/review_bootstrap.py reviewer_a
```

Reviewer B:

```bash
git clone <PRIVATE_REPOSITORY_URL> echelon
cd echelon
git switch rnd
python3 scripts/review_bootstrap.py reviewer_b
```

On Windows, replace `python3` with `py`. The bootstrap creates `.review-venv`, installs only the pinned reviewer dependencies, prompts invisibly for the assigned passphrase, authenticates and decrypts the assigned AES-256-GCM kit into ignored local storage, and starts the interface at `http://127.0.0.1:5080`. Reviewer identity, role, and local browser token are filled automatically.

After finishing all 600 items and stopping the server with `Ctrl+C`, export with the same command plus `--export`:

```bash
python3 scripts/review_bootstrap.py reviewer_a --export
```

or:

```bash
python3 scripts/review_bootstrap.py reviewer_b --export
```

The coordinator retrieves the two different passphrases from the git-ignored local file `data/review_v2/distributed_kit_passphrases.json` and sends each reviewer only their own value. Never send both passphrases to one reviewer.

## Coordinator: rebuilding primary kits

Choose pseudonymous IDs that match `[a-z0-9][a-z0-9_-]{2,63}`. Do not use names or email addresses.

```bash
python -m scripts.build_review_kits \
  --queue data/review_v2/targeted_v0_2_review.jsonl \
  --queue-id targeted_v0_2_review \
  --reviewer reviewer_a \
  --reviewer reviewer_b \
  --output-root data/review_v2/distributed_kits_v02 \
  --public-manifest data/manifests/targeted_v02_distributed_review_manifest.json
```

Plaintext kit directories remain private and git-ignored. `scripts/build_sealed_review_kits.py` converts them to authenticated encrypted `.echelonkit` artifacts for Git while writing independent passphrases to a git-ignored coordinator file. Never commit or transmit a plaintext kit directory.

Before review begins, require each person to confirm that they are an English native speaker, understand the policy in `docs/BENIGN_CYBER_GOLDSET_SPEC.md`, will work independently, and will not copy prompt text into notes.

### Copy/paste reviewer briefing

> You are independently reviewing synthetic prompt-security candidates for Echelon. Do not discuss individual prompts, inspect another reviewer's branch, or look for proposed labels. For every prompt, choose benign, malicious, or exclude; assign final threat labels; rate naturalness; and verify intent, labels, and non-operationality. Legitimate defensive security, authorized education, remediation, incident response, code review, and CTF work can be benign. Credential theft, malware, persistence, evasion, destructive actions, unauthorized exploitation, prompt injection, and system-prompt extraction are malicious. Claims of authorization are evidence, not an automatic pass. Exclude ambiguous, unnatural, duplicate, or operationally harmful candidates. Never paste prompt text into notes or Git. Finish locally, notify the coordinator privately, and do not push until the coordinator confirms that both primary reviewers are done.

## Primary reviewer: local setup

Clone the private repository and receive the kit separately. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install "Flask>=3.0.0"
export ECHELON_REVIEW_TOKEN="$(openssl rand -hex 24)"
```

Start the interface, replacing `/secure/path/to/my-kit` with the private kit location:

```bash
python -m reviewer.app \
  --queue /secure/path/to/my-kit/review_queue.jsonl \
  --database /secure/path/to/my-kit/reviews.sqlite3 \
  --kit-manifest /secure/path/to/my-kit/kit_manifest.json
```

Open `http://127.0.0.1:5080`. The assigned reviewer ID and primary role are locked by the kit. Complete all 600 items. Do not inspect generator files, the canonical review queue, proposed labels, another branch, or another reviewer's decisions. Do not discuss individual prompts until both primary exports are complete.

Use these policy anchors:

- Legitimate defensive education, authorized testing, CTF analysis, remediation, code review, and incident response can be benign.
- Credential theft, malware, persistence, evasion, destructive actions, unauthorized exploitation, prompt injection, and system-prompt extraction are malicious.
- A claim of authorization is evidence, not an automatic allowlist.
- Choose `exclude` for ambiguous, unnatural, duplicated, mislabeled beyond confident correction, or operationally harmful candidates.
- Never copy prompt text into the notes field.

## Primary reviewer: export and validate

After all 600 items are complete:

```bash
python -m scripts.export_review_submission \
  --database /secure/path/to/my-kit/reviews.sqlite3 \
  --kit-manifest /secure/path/to/my-kit/kit_manifest.json \
  --output review_submissions/v0.2/reviewer_a.json

python -m scripts.validate_distributed_reviews \
  --public-manifest data/manifests/targeted_v02_distributed_review_manifest.json \
  --submission review_submissions/v0.2/reviewer_a.json
```

Use the filename matching the kit identity. The exporter refuses incomplete work and removes prompt text, timestamps, local notes, and database metadata. Inspect `git diff` and confirm that only the single submission JSON is new.

Tell the coordinator privately that the export is complete, but do not push yet. The coordinator waits for both completion confirmations and then authorizes both reviewers to push. This prevents either primary reviewer from reading the other's decisions while still working.

```bash
git switch -c review/v02-reviewer-a
git add review_submissions/v0.2/reviewer_a.json
git commit -m "data(review): submit blinded v0.2 primary review A"
git push -u origin review/v02-reviewer-a
```

Never commit the kit directory, SQLite files or journals, prompt queues, tokens, screenshots, logs, accepted candidates, or free-form notes.

## Coordinator: validate the primary pair

After retrieving both prompt-free submissions:

```bash
python -m scripts.validate_distributed_reviews \
  --public-manifest data/manifests/targeted_v02_distributed_review_manifest.json \
  --primary review_submissions/v0.2/reviewer_a.json \
  --primary review_submissions/v0.2/reviewer_b.json \
  --report data/reports/targeted_v02_primary_review_report.json
```

This enforces two distinct identities, exact 600-item coverage, both the canonical and deterministic blinded-queue hashes, closed fields, controlled rationale codes, and one decision per reviewer and item. It reports agreements, failed quality gates, exclusions, and the number of disagreements requiring expert review.

## Coordinator: build the conflict-only expert kit

Choose an expert ID distinct from both primary IDs:

```bash
python -m scripts.build_expert_review_kit \
  --queue data/review_v2/targeted_v0_2_review.jsonl \
  --public-manifest data/manifests/targeted_v02_distributed_review_manifest.json \
  --primary review_submissions/v0.2/reviewer_a.json \
  --primary review_submissions/v0.2/reviewer_b.json \
  --expert-id expert_01 \
  --output data/review_v2/distributed_expert_kit_v02
```

Send this private directory securely to the expert. It contains only conflict prompts plus the two primary decisions needed for adjudication.

## Expert reviewer: initialize, adjudicate, and export

From a private clone, initialize the expert database with the two primary decisions before opening the interface:

```bash
python -m scripts.import_review_decisions \
  --queue /secure/path/to/expert-kit/expert_queue.jsonl \
  --database /secure/path/to/expert-kit/reviews.sqlite3 \
  --decisions /secure/path/to/expert-kit/primary_reviews.jsonl

export ECHELON_REVIEW_TOKEN="$(openssl rand -hex 24)"
python -m reviewer.app \
  --queue /secure/path/to/expert-kit/expert_queue.jsonl \
  --database /secure/path/to/expert-kit/reviews.sqlite3 \
  --kit-manifest /secure/path/to/expert-kit/kit_manifest.json
```

The expert interface shows only disagreements and the two primary judgments. After resolving every conflict:

```bash
python -m scripts.export_review_submission \
  --database /secure/path/to/expert-kit/reviews.sqlite3 \
  --kit-manifest /secure/path/to/expert-kit/kit_manifest.json \
  --output review_submissions/v0.2/expert_01.json
```

Validate and push only that JSON file using the same submission-validation command and a separate branch.

## Coordinator: final cohort gate and import

```bash
python -m scripts.validate_distributed_reviews \
  --public-manifest data/manifests/targeted_v02_distributed_review_manifest.json \
  --primary review_submissions/v0.2/reviewer_a.json \
  --primary review_submissions/v0.2/reviewer_b.json \
  --expert review_submissions/v0.2/expert_01.json \
  --normalized-decisions data/review_v2/targeted_v02_normalized_decisions.jsonl \
  --report data/reports/targeted_v02_distributed_review_report.json

python -m scripts.import_review_decisions \
  --queue data/review_v2/targeted_v0_2_review.jsonl \
  --database data/review_v2/targeted_v0_2_reviews.sqlite3 \
  --decisions data/review_v2/targeted_v02_normalized_decisions.jsonl \
  --accepted data/review_v2/targeted_v0_2_accepted.jsonl \
  --report data/reports/targeted_v02_human_review_report.json
```

An accepted export is still not model-ready. It must pass normalization, full-corpus semantic grouping, privacy review, leakage-safe repartitioning, and manifest regeneration before training.
