# Encrypted reviewer kits v0.2

The `.echelonkit` files in this directory are authenticated AES-256-GCM ciphertext. Their passphrases are distributed separately by the coordinator and never stored in Git.

Reviewers should not open these files manually. From the repository root, run `python3 scripts/review_bootstrap.py reviewer_a` or `python3 scripts/review_bootstrap.py reviewer_b` as assigned.
