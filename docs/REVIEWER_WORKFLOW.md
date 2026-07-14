# Echelon Local Human-Review Workflow

This workflow keeps prompt text, reviewer decisions, and accepted candidates in `data/review_v2/`, which is excluded from Git. Only content-free aggregate reports belong in version control. It does not create human judgments and it cannot admit an unreviewed candidate.

## Policy

- Two distinct primary reviewers independently label every candidate. Primary reviewers cannot see proposed labels, nearest-neighbor text, or another reviewer's decision.
- Exact agreement includes both the benign/malicious/exclude decision and the complete final label set.
- An agreed non-excluded item passes only when both reviews rate naturalness at least 4/5 and affirm correct intent, correct labels, and non-operational content.
- A disagreement remains quarantined until a third, distinct expert adjudicates it. Expert acceptance must pass the same quality fields.
- Exclusion, failed quality checks, incomplete review, and unresolved disagreement never produce a training-eligible row.
- Reviewer IDs must identify people, not browsers or shared accounts. Human coordinators must assign the two primary roles independently.

## Start the local interface

Install the project requirements in the intended environment, then set two distinct secrets of at least 16 characters. Do not put the secrets in Git or shell history. Start the service from the repository root:

```bash
export ECHELON_REVIEW_TOKEN='<primary-review-secret>'
export ECHELON_EXPERT_TOKEN='<different-expert-secret>'
python -m reviewer.app \
  --queue data/review_v2/targeted_v0_2_review.jsonl \
  --database data/review_v2/targeted_v0_2_reviews.sqlite3
```

Open `http://127.0.0.1:5080`. The server deliberately binds only to loopback, disables debug mode, requires a token on every API call, returns no-store and browser hardening headers, and never enables cross-origin access. Do not reverse-proxy or expose this R&D interface to a network.

Primary reviewers choose a final decision and label set without seeing candidate labels. Experts select the expert role and receive only disagreements after two primary decisions exist. Notes should use concise rationale and must not copy prompt text.

## Import offline decisions and apply the gate

Review JSONL must match `schemas/adjudication_review.schema.json`. Files are applied in order, so primary decisions must precede expert decisions for the same item. Do not re-import decisions already stored in the database.

```bash
python -m scripts.import_review_decisions \
  --queue data/review_v2/targeted_v0_2_review.jsonl \
  --database data/review_v2/targeted_v0_2_reviews.sqlite3 \
  --decisions data/review_v2/reviewer_a.jsonl \
  --decisions data/review_v2/reviewer_b.jsonl \
  --decisions data/review_v2/expert.jsonl \
  --accepted data/review_v2/targeted_v0_2_accepted.jsonl \
  --report data/reports/targeted_v02_human_review_report.json
```

The database is cryptographically bound to the queue SHA-256 and rejects a changed queue. The accepted JSONL contains only candidates resolved by agreement or expert adjudication and records resolution provenance without reviewer identities. It is still an intermediate private artifact: accepted rows must be normalized, re-grouped semantically, and repartitioned before any training job can consume them.
