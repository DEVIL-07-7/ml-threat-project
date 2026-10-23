#!/usr/bin/env python3
"""
ThreatOps Machine Learning Training CLI (`machine_learning/train.py`)
---------------------------------------------------------------------
Trains the 4 separated models in `machine_learning/models/`:
  - `xgboost_model.py`
  - `random_forest_model.py`
  - `neural_network_model.py`
  - `isolation_forest_model.py`
using the single dataset file `machine_learning/datasets/training_dataset.csv`.
"""

import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from machine_learning.ensemble_classifier import ThreatOpsEnsembleModel


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the ThreatOps 4-Tier Hybrid ML Models")
    parser.add_argument("--test-split", type=float, default=0.20, help="Stratified holdout test split (0.10 - 0.40)")
    parser.add_argument("--learning-rate", type=float, default=0.12, help="XGBoost & MLP learning rate (0.01 - 0.50)")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of trees / boosting rounds (30 - 300)")
    args = parser.parse_args()

    model = ThreatOpsEnsembleModel()
    summary = model.train_and_evaluate(
        options={
            "test_split": args.test_split,
            "learning_rate": args.learning_rate,
            "n_estimators": args.n_estimators,
        },
        persist_artifacts=True,
    )

    print("=================================================================")
    print(" ThreatOps Python ML Studio — Training Complete")
    print("=================================================================")
    print(f" Trained At        : {summary['trained_at']}")
    print(f" Duration          : {summary['training_duration_ms']} ms")
    print(f" Dataset File      : {summary['dataset_file']}")
    print(
        f" Total Samples     : {summary['dataset']['total_samples']} "
        f"(Train: {summary['dataset']['train_size']}, Test: {summary['dataset']['test_size']})"
    )
    print(f" Accuracy          : {summary['metrics']['accuracy']}%")
    print(f" Precision         : {summary['metrics']['precision']}%")
    print(f" Recall            : {summary['metrics']['recall']}%")
    print(f" F1-Score          : {summary['metrics']['f1_score']}%")
    print(f" False Positive Rt : {summary['metrics']['false_positive_rate']}%")
    print(" Models Trained    :")
    for mf in summary["model_files"]:
        print(f"   - {mf}")
    print("=================================================================")


if __name__ == "__main__":
    main()
