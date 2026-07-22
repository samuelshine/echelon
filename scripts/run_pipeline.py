#!/usr/bin/env python3
"""Run the three-fold cascade without echoing the input prompt."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from echelon.contracts import Route, ThresholdPolicy
from echelon.layer1 import HeuristicAnalyzer
from echelon.layer2 import Layer2Classifier, Layer2Config, StaticModelAdapter, TransformersModelAdapter
from echelon.layer3 import Layer3Judge, MockJudge
from echelon.pipeline import EchelonPipeline, PipelineConfig


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", help="prompt text; stdin is preferred to avoid shell history")
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--model-dir", type=Path, help="local Hugging Face model directory")
    parser.add_argument("--fixture-risk", type=float, help="development-only static Layer 2 risk")
    parser.add_argument("--judge", choices=("none", "mock"), default="none")
    parser.add_argument("--mode", choices=("shadow", "enforce"), default="shadow")
    parser.add_argument("--short-circuit-layer1-blocks", action="store_true")
    args = parser.parse_args()
    prompt = args.text if args.text is not None else sys.stdin.read()
    policy = ThresholdPolicy()
    analyzer = HeuristicAnalyzer(args.rules) if args.rules else HeuristicAnalyzer()
    if args.model_dir:
        adapter = TransformersModelAdapter(args.model_dir)
    elif args.fixture_risk is not None:
        if not 0.0 <= args.fixture_risk <= 1.0:
            parser.error("--fixture-risk must be between 0 and 1")
        adapter = StaticModelAdapter({"prompt_injection": args.fixture_risk}, calibrated=False)
    else:
        parser.error("provide --model-dir or the explicit development-only --fixture-risk")
    classifier = Layer2Classifier(adapter, Layer2Config(thresholds=policy))
    judge = Layer3Judge(MockJudge()) if args.judge == "mock" else None
    pipeline = EchelonPipeline(
        analyzer, classifier, judge,
        PipelineConfig(
            mode=args.mode, short_circuit_layer1_blocks=args.short_circuit_layer1_blocks,
        ),
    )
    print(json.dumps(pipeline.analyze(prompt).to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
