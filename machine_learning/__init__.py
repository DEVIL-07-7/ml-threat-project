"""
ThreatOps Machine Learning Package (`machine_learning/`)
--------------------------------------------------------
Separated Machine Learning architecture:
  - `machine_learning/datasets/training_dataset.csv` (Single unified training dataset CSV)
  - `machine_learning/models/` (One file for each model):
      * `xgboost_model.py`
      * `random_forest_model.py`
      * `neural_network_model.py`
      * `isolation_forest_model.py`
"""

import sys

sys.dont_write_bytecode = True

from .dataset_loader import (
    DATASETS_DIR,
    TRAINING_DATASET_CSV_PATH,
    append_custom_feedback_sample,
    export_unified_training_dataset_csv,
    load_combined_training_corpus,
    load_custom_feedback_samples,
    load_osint_seed_iocs,
)
from .ensemble_classifier import (
    MODELS_DIR,
    ThreatOpsEnsembleModel,
    get_singleton_model,
)
from .feature_extractor import (
    FEATURE_NAMES,
    calculate_shannon_entropy,
    extract_ioc_features,
    feature_map_to_vector,
)
from .ml_studio import ARTIFACT_FILES, MLStudioController
from .models.isolation_forest_model import IsolationForestAnomalyDetector
from .models.neural_network_model import NeuralNetworkMLPClassifier
from .models.random_forest_model import RandomForestIOCClassifier
from .models.xgboost_model import XGBoostIOCClassifier

__all__ = [
    "DATASETS_DIR",
    "MODELS_DIR",
    "TRAINING_DATASET_CSV_PATH",
    "ARTIFACT_FILES",
    "MLStudioController",
    "FEATURE_NAMES",
    "calculate_shannon_entropy",
    "extract_ioc_features",
    "feature_map_to_vector",
    "load_osint_seed_iocs",
    "load_custom_feedback_samples",
    "append_custom_feedback_sample",
    "export_unified_training_dataset_csv",
    "load_combined_training_corpus",
    "XGBoostIOCClassifier",
    "RandomForestIOCClassifier",
    "NeuralNetworkMLPClassifier",
    "IsolationForestAnomalyDetector",
    "ThreatOpsEnsembleModel",
    "get_singleton_model",
]
