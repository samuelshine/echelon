# Echelon Three-Fold Ingress Pipeline

The implementation is split into three typed stages:

1. `echelon.layer1.HeuristicAnalyzer` performs bounded, deterministic phrase/regex, Unicode, entropy, and deobfuscation analysis.
2. `echelon.layer2.Layer2Classifier` consumes a local semantic model through a provider-neutral adapter and returns category scores marked calibrated or uncalibrated.
3. `echelon.layer3.Layer3Judge` is a strict JSON judge boundary for gray-area prompts. It can use the deterministic mock in development or an explicitly configured HTTPS JSON endpoint.

`echelon.pipeline.EchelonPipeline` orchestrates the cascade. A Layer 1 block can short-circuit only when configured in enforcement mode. Otherwise Layer 2 runs; Layer 2 pass returns pass, Layer 2 block returns block, and the uncertainty band invokes Layer 3. Missing models, malformed judge responses, timeouts, and unavailable layers fail to the configured escalation route.

## Risk and routing

Every layer uses the same explicit boundaries: `risk < 0.35` passes, `0.35 <= risk < 0.90` escalates, and `risk >= 0.90` blocks. These are shadow-mode scaffolding, not calibrated production thresholds. Layer 2 scores must be marked calibrated only after validation-time calibration and slice evaluation; raw softmax confidence is not automatically a probability of harm.

The default pipeline mode is `shadow`, which reports the policy route but sets `enforced_route=pass`. This permits latency, recall, and false-positive measurement on approved data. `enforce` mode is a deliberate deployment choice and should remain disabled until the reviewed English gold set and defensive-cyber hard negatives have passed leakage, calibration, and operating-point gates.

## Layer 2 model boundary

`TransformersModelAdapter` loads only a local model directory with `local_files_only=True`. It never downloads weights implicitly. The current binary artifacts map their positive class to `prompt_injection`; production training should replace this with a category-aware multi-label artifact covering system leakage, malicious code, toxicity/harm, and obfuscation. `TemperatureCalibrator` provides a deterministic validation-time binary temperature fit; its output must be versioned with the model and validation manifest.

## Layer 3 safety boundary

The judge receives the raw prompt only inside a structured untrusted-data field plus content-free layer evidence. It must return exactly five fields and no arbitrary rationale text. The HTTPS adapter enforces a timeout and bearer token without logging prompt or response content. The judge's supplied route is validated but the pipeline recomputes the route from its risk and the shared threshold policy.

## Development smoke run

No reviewed dataset is required for a fixture smoke run:

```bash
printf '%s' 'Summarize this meeting agenda.' | python -m scripts.run_pipeline --fixture-risk 0.10 --judge mock
```

A real local model must be selected explicitly:

```bash
python -m scripts.run_pipeline \
  --model-dir models/prompt-injection-distilbert/best \
  --judge none \
  --mode shadow < prompt.txt
```

The CLI output contains scores and content-free evidence only; it does not echo `prompt.txt`.

The fixture-only end-to-end benchmark is run as a module:

```bash
python -m scripts.benchmark_pipeline \
  --iterations 5000 \
  --report data/reports/pipeline_benchmark.json
```

The resulting latency numbers describe this development machine and fixture adapters only. They are not Layer 2 model latency, judge-provider latency, or a production SLO.
