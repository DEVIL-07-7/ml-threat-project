"""
ThreatOps ML Studio Engine (`machine_learning/ml_studio.py`)
------------------------------------------------------------
Dedicated Python controller for the ThreatOps ML Studio (Chapter 02).
Connects:
  - Dataset (1 file): `machine_learning/datasets/training_dataset.csv`
  - Models (1 file per model):
      * `machine_learning/models/xgboost_model.py`
      * `machine_learning/models/random_forest_model.py`
      * `machine_learning/models/neural_network_model.py`
      * `machine_learning/models/isolation_forest_model.py`
"""

import csv
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.dont_write_bytecode = True

from machine_learning.dataset_loader import (
    TRAINING_DATASET_CSV_PATH,
    append_custom_feedback_sample,
    export_unified_training_dataset_csv,
)
from machine_learning.ensemble_classifier import (
    MODELS_DIR,
    ThreatOpsEnsembleModel,
    get_singleton_model,
)
from machine_learning.feature_extractor import (
    FEATURE_NAMES,
    extract_ioc_features,
    feature_map_to_vector,
)

ARTIFACT_FILES: Dict[str, Tuple[Path, str, str]] = {
    "training_dataset.csv": (
        TRAINING_DATASET_CSV_PATH,
        "text/csv; charset=utf-8",
        "training_dataset.csv",
    ),
    "xgboost_model.py": (
        MODELS_DIR / "xgboost_model.py",
        "text/x-python; charset=utf-8",
        "xgboost_model.py",
    ),
    "random_forest_model.py": (
        MODELS_DIR / "random_forest_model.py",
        "text/x-python; charset=utf-8",
        "random_forest_model.py",
    ),
    "neural_network_model.py": (
        MODELS_DIR / "neural_network_model.py",
        "text/x-python; charset=utf-8",
        "neural_network_model.py",
    ),
    "isolation_forest_model.py": (
        MODELS_DIR / "isolation_forest_model.py",
        "text/x-python; charset=utf-8",
        "isolation_forest_model.py",
    ),
}


class MLStudioController:
    """High-level interface used by ML Studio for training, dataset inspection, and inference."""

    def __init__(self, model: ThreatOpsEnsembleModel | None = None) -> None:
        self.model = model or get_singleton_model()
        export_unified_training_dataset_csv()

    def get_studio_summary(self) -> Dict[str, Any]:
        """Returns the ML Studio model summary plus dataset and model files metadata."""
        summary = self.model.get_summary()
        summary["ml_folder"] = {
            "root": "machine_learning/",
            "datasets_dir": "machine_learning/datasets/",
            "models_dir": "machine_learning/models/",
            "training_dataset_file": "machine_learning/datasets/training_dataset.csv",
            "model_files": [
                "machine_learning/models/xgboost_model.py",
                "machine_learning/models/random_forest_model.py",
                "machine_learning/models/neural_network_model.py",
                "machine_learning/models/isolation_forest_model.py",
            ],
            "available_downloads": list(ARTIFACT_FILES.keys()),
        }
        return summary

    def get_training_dataset_records(self, limit: int = 250) -> Dict[str, Any]:
        """Returns the rows and metadata of `machine_learning/datasets/training_dataset.csv`."""
        export_unified_training_dataset_csv()
        rows: List[Dict[str, Any]] = []
        malicious_count = 0
        benign_count = 0
        source_breakdown: Dict[str, int] = {}

        if TRAINING_DATASET_CSV_PATH.exists():
            with open(TRAINING_DATASET_CSV_PATH, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    lbl = int(row.get("label", 0))
                    if lbl == 1:
                        malicious_count += 1
                    else:
                        benign_count += 1
                    src = row.get("source") or "osint_threat_feed"
                    source_breakdown[src] = source_breakdown.get(src, 0) + 1
                    if len(rows) < limit:
                        rows.append(
                            {
                                "sample_id": int(row.get("sample_id", len(rows) + 1)),
                                "ioc_value": row.get("ioc_value", ""),
                                "label": lbl,
                                "class_name": row.get("class_name", "malicious" if lbl == 1 else "benign"),
                                "source": src,
                                "length": float(row.get("length", 0)),
                                "shannon_entropy": float(row.get("shannon_entropy", 0)),
                                "suspicious_keyword_count": float(row.get("suspicious_keyword_count", 0)),
                                "uses_ip_host": float(row.get("uses_ip_host", 0)),
                                "has_suspicious_tld": float(row.get("has_suspicious_tld", 0)),
                            }
                        )

        return {
            "dataset_path": "machine_learning/datasets/training_dataset.csv",
            "total_records": malicious_count + benign_count,
            "malicious_records": malicious_count,
            "benign_records": benign_count,
            "feature_columns": FEATURE_NAMES,
            "source_breakdown": source_breakdown,
            "records": rows,
        }

    def train_studio_model(self, options: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Retrains the 4 models (`xgboost_model.py`, `random_forest_model.py`, `neural_network_model.py`, `isolation_forest_model.py`)."""
        export_unified_training_dataset_csv()
        return self.model.train_and_evaluate(options=options or {}, persist_artifacts=True)

    def add_ground_truth_sample(
        self,
        ioc_value: str,
        label: int,
        source: str = "analyst_active_learning",
        added_by: str = "lead_analyst@threatops.io",
    ) -> Dict[str, Any]:
        """Adds a new labeled ground-truth sample to `training_dataset.csv` and retrains."""
        sample_info = append_custom_feedback_sample(
            ioc_value=ioc_value,
            label=label,
            source=source,
            added_by=added_by,
        )
        summary = self.model.train_and_evaluate(persist_artifacts=True)
        return {
            "message": "Sample added to machine_learning/datasets/training_dataset.csv and models retrained.",
            "sample": sample_info,
            "summary": summary,
        }

    def predict_single(self, ioc_value: str, feed_confidence: float = 80.0) -> Dict[str, Any]:
        """Scores a single IOC using the trained models in `machine_learning/models/`."""
        pred = self.model.predict(ioc_value, feed_confidence=feed_confidence)
        feat_dict = extract_ioc_features(ioc_value)
        pred["extracted_features"] = feat_dict
        pred["feature_vector"] = feature_map_to_vector(feat_dict)
        return pred

    def predict_batch(self, iocs: List[str], feed_confidence: float = 80.0) -> List[Dict[str, Any]]:
        """Scores a batch of IOCs using the trained models."""
        return [
            self.model.predict(str(ioc).strip(), feed_confidence=feed_confidence)
            for ioc in iocs
            if str(ioc).strip()
        ]

    @staticmethod
    def resolve_downloadable_artifact(artifact_name: str) -> Tuple[Path, str, str] | None:
        """Resolves `training_dataset.csv` or any of the 4 model files inside `machine_learning/models/`."""
        export_unified_training_dataset_csv()
        clean_name = Path(str(artifact_name or "").strip()).name
        return ARTIFACT_FILES.get(clean_name)
