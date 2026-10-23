#!/usr/bin/env python3
"""
ThreatOps Machine Learning Inference CLI (`machine_learning/predict.py`)
------------------------------------------------------------------------
Loads the separated models from `machine_learning/models/` (`xgboost_model.py`,
`random_forest_model.py`, `neural_network_model.py`, `isolation_forest_model.py`)
and performs 18-feature lexical/entropy extraction + 4-model hybrid inference on any IOC.
"""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from machine_learning.ensemble_classifier import get_singleton_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Score an IOC using the ThreatOps Python ML Models")
    parser.add_argument("ioc", type=str, help="URL, IPv4, or Domain indicator to score")
    parser.add_argument("--confidence", type=float, default=50.0, help="Prior OSINT feed confidence (0-100)")
    args = parser.parse_args()

    model = get_singleton_model()
    result = model.predict_single_ioc(args.ioc, feed_confidence=args.confidence)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
