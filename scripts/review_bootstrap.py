#!/usr/bin/env python3
"""One-command bootstrap for a repository-distributed Echelon review assignment."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".review-venv"
REQUIREMENTS = ROOT / "reviewer-requirements.txt"


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def dependencies_ready(python: Path) -> bool:
    result = subprocess.run(
        [str(python), "-c", "import flask, cryptography"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reviewer_id", choices=("reviewer_a", "reviewer_b"))
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--port", type=int, default=5080)
    args = parser.parse_args()
    python = venv_python()
    if not python.exists():
        print("Creating isolated reviewer environment...")
        venv.EnvBuilder(with_pip=True).create(VENV)
    if not dependencies_ready(python):
        print("Installing pinned reviewer dependencies...")
        subprocess.run(
            [str(python), "-m", "pip", "install", "--requirement", str(REQUIREMENTS)], check=True,
        )
    command = [str(python), "-m", "scripts.review_runner", args.reviewer_id, "--port", str(args.port)]
    if args.export:
        command.append("--export")
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
