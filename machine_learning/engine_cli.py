#!/usr/bin/env python3
"""
ThreatOps Python ML Engine JSON-RPC Bridge (`machine_learning/engine_cli.py`)
-----------------------------------------------------------------------------
Provides a fast command-line JSON interface so both Python and Node.js services
can invoke the separated `machine_learning/` package (`datasets/` + `models/`)
directly.
"""

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from machine_learning.dataset_loader import append_custom_feedback_sample
from machine_learning.ensemble_classifier import get_singleton_model


def main() -> None:
    raw_input = sys.stdin.read().strip()
    if not raw_input and len(sys.argv) > 1:
        raw_input = sys.argv[1]
    payload = json.loads(raw_input) if raw_input else {"command": "status"}
    cmd = payload.get("command", "status")

    model = get_singleton_model()

    if cmd == "status":
        print(json.dumps(model.get_model_summary()))
    elif cmd == "train":
        options = payload.get("options") or {}
        extra_mal = payload.get("extra_malicious_iocs") or []
        summary = model.train_and_evaluate(options=options, extra_malicious_iocs=extra_mal, persist_artifacts=True)
        print(json.dumps(summary))
    elif cmd == "predict":
        ioc_val = payload.get("ioc_value", "")
        conf = float(payload.get("feed_confidence", 50.0))
        res = model.predict_single_ioc(ioc_val, feed_confidence=conf)
        print(json.dumps(res))
    elif cmd == "add_samples":
        samples = payload.get("samples") or []
        added_by = payload.get("added_by", "lead_analyst@threatops.io")
        source = payload.get("source", "analyst_active_learning")
        added_count = 0
        for s in samples:
            ioc_v = str(s.get("ioc_value", "")).strip()
            lbl = 1 if int(s.get("label", 0)) == 1 else 0
            if len(ioc_v) >= 3:
                append_custom_feedback_sample(ioc_v, lbl, source=source, added_by=added_by)
                added_count += 1
        summary = model.train_and_evaluate(
            options=model.state["hyperparameters"] if model.state else {},
            persist_artifacts=True,
        )
        print(json.dumps({"samples_added": added_count, "model_summary": summary}))
    else:
        print(json.dumps({"error": f"Unknown command: {cmd}"}))


if __name__ == "__main__":
    main()
