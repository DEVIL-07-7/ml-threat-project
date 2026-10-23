"""
ThreatOps 4-Tier Hybrid Machine Learning Ensemble Orchestrator (`machine_learning/ensemble_classifier.py`)
----------------------------------------------------------------------------------------------------------
Combines the 4 individual model files from `machine_learning/models/`:
  1. `machine_learning/models/xgboost_model.py`         (XGBoostIOCClassifier)
  2. `machine_learning/models/random_forest_model.py`   (RandomForestIOCClassifier)
  3. `machine_learning/models/neural_network_model.py`  (NeuralNetworkMLPClassifier)
  4. `machine_learning/models/isolation_forest_model.py`(IsolationForestAnomalyDetector)

Trained on the single unified dataset file:
  - `machine_learning/datasets/training_dataset.csv`
"""

import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.dont_write_bytecode = True

from machine_learning.dataset_loader import load_combined_training_corpus
from machine_learning.feature_extractor import (
    FEATURE_NAMES,
    extract_ioc_features,
    feature_map_to_vector,
)
from machine_learning.models.isolation_forest_model import IsolationForestAnomalyDetector
from machine_learning.models.neural_network_model import NeuralNetworkMLPClassifier
from machine_learning.models.random_forest_model import RandomForestIOCClassifier
from machine_learning.models.xgboost_model import XGBoostIOCClassifier

ML_ROOT = Path(__file__).resolve().parent
MODELS_DIR = ML_ROOT / "models"


class DeterministicRNG:
    """Mulberry32-compatible deterministic PRNG for reproducible stratified splits and tree bagging."""

    def __init__(self, seed: int = 42) -> None:
        self.state = seed & 0xFFFFFFFF

    def next_float(self) -> float:
        self.state = (self.state + 0x6D2B79F5) & 0xFFFFFFFF
        t = self.state ^ (self.state >> 15)
        t = (t * (1 | self.state)) & 0xFFFFFFFF
        t2 = t ^ (t >> 7)
        t2 = (t2 * (61 | t)) & 0xFFFFFFFF
        t = (t + t2) ^ t
        res = (t ^ (t >> 14)) & 0xFFFFFFFF
        return res / 4294967296.0


class ThreatOpsEnsembleModel:
    """
    Coordinates dataset loading from `machine_learning/datasets/training_dataset.csv`
    and trains the 4 separated models in `machine_learning/models/`:
      - xgboost_model.py
      - random_forest_model.py
      - neural_network_model.py
      - isolation_forest_model.py
    """

    def __init__(self) -> None:
        self.state: Optional[Dict[str, Any]] = None
        self.rf_model = RandomForestIOCClassifier()
        self.xgb_model = XGBoostIOCClassifier()
        self.mlp_model = NeuralNetworkMLPClassifier()
        self.iso_model = IsolationForestAnomalyDetector()

    def train_and_evaluate(
        self,
        options: Optional[Dict[str, Any]] = None,
        extra_malicious_iocs: Optional[List[str]] = None,
        extra_custom_samples: Optional[List[Dict[str, Any]]] = None,
        persist_artifacts: bool = True,
    ) -> Dict[str, Any]:
        _ = persist_artifacts
        opts = options or {}
        start_ms = time.time() * 1000.0

        test_split = min(0.4, max(0.1, float(opts.get("test_split", 0.2))))
        learning_rate = min(0.5, max(0.01, float(opts.get("learning_rate", 0.12))))
        n_estimators = min(300, max(30, int(opts.get("n_estimators", 100))))

        rf_w = float(opts.get("rf_weight", opts.get("weights", {}).get("RandomForest", 0.40)))
        xgb_w = float(opts.get("xgb_weight", opts.get("weights", {}).get("XGBoost", 0.35)))
        mlp_w = float(opts.get("mlp_weight", opts.get("weights", {}).get("NeuralNet", 0.25)))
        w_sum = (rf_w + xgb_w + mlp_w) or 1.0
        weights = {
            "RandomForest": round(rf_w / w_sum, 2),
            "XGBoost": round(xgb_w / w_sum, 2),
            "NeuralNet": round(mlp_w / w_sum, 2),
        }

        dataset, corpus_stats = load_combined_training_corpus(
            extra_malicious_iocs=extra_malicious_iocs,
            extra_custom_samples=extra_custom_samples,
        )

        rng = DeterministicRNG(42)
        enriched = []
        for item in dataset:
            feat_map = extract_ioc_features(item["ioc"])
            enriched.append(
                {
                    "ioc": item["ioc"],
                    "label": item["label"],
                    "feat_map": feat_map,
                    "x": feature_map_to_vector(feat_map),
                    "sort_key": rng.next_float(),
                }
            )

        pos_samples = sorted(
            [d for d in enriched if d["label"] == 1], key=lambda d: d["sort_key"]
        )
        neg_samples = sorted(
            [d for d in enriched if d["label"] == 0], key=lambda d: d["sort_key"]
        )

        pos_split = max(1, int(math.floor(len(pos_samples) * (1.0 - test_split))))
        neg_split = max(1, int(math.floor(len(neg_samples) * (1.0 - test_split))))

        train_set = pos_samples[:pos_split] + neg_samples[:neg_split]
        test_set = pos_samples[pos_split:] + neg_samples[neg_split:]

        num_features = len(FEATURE_NAMES)
        means = [0.0] * num_features
        stds = [1.0] * num_features

        train_len = max(len(train_set), 1)
        for row in train_set:
            for j in range(num_features):
                means[j] += row["x"][j]
        for j in range(num_features):
            means[j] /= train_len

        for row in train_set:
            for j in range(num_features):
                diff = row["x"][j] - means[j]
                stds[j] += diff * diff
        for j in range(num_features):
            stds[j] = math.sqrt(stds[j] / train_len) or 1.0

        def normalize_vec(vec: List[float]) -> List[float]:
            return [(vec[j] - means[j]) / stds[j] for j in range(num_features)]

        X_train = [normalize_vec(r["x"]) for r in train_set]
        y_train = [r["label"] for r in train_set]
        X_test = [normalize_vec(r["x"]) for r in test_set]
        y_test = [r["label"] for r in test_set]

        feature_importance_raw = [0.0] * num_features

        self.rf_model = RandomForestIOCClassifier(n_estimators=n_estimators)
        self.rf_model.fit(X_train, y_train, rng, feature_importance_raw)

        self.xgb_model = XGBoostIOCClassifier(
            n_estimators=n_estimators, learning_rate=learning_rate
        )
        self.xgb_model.fit(X_train, y_train, feature_importance_raw)

        self.mlp_model = NeuralNetworkMLPClassifier(
            hidden_dim=12, epochs=60, learning_rate=learning_rate
        )
        self.mlp_model.fit(X_train, y_train, rng, feature_importance_raw)

        self.iso_model = IsolationForestAnomalyDetector()

        total_imp = sum(feature_importance_raw) or 1.0
        feature_importances = sorted(
            [
                {
                    "feature": name,
                    "importance": round((feature_importance_raw[idx] / total_imp) * 100.0, 2),
                }
                for idx, name in enumerate(FEATURE_NAMES)
            ],
            key=lambda item: item["importance"],
            reverse=True,
        )

        tp = fp = tn = fn = 0
        test_predictions = []
        for i in range(len(X_test)):
            p_rf = self.rf_model.predict_proba(X_test[i])
            p_xgb = self.xgb_model.predict_proba(X_test[i])
            p_mlp = self.mlp_model.predict_proba(X_test[i])
            p_ens = (
                weights["RandomForest"] * p_rf
                + weights["XGBoost"] * p_xgb
                + weights["NeuralNet"] * p_mlp
            )
            pred = 1 if p_ens >= 0.5 else 0
            actual = y_test[i]
            if pred == 1 and actual == 1:
                tp += 1
            elif pred == 1 and actual == 0:
                fp += 1
            elif pred == 0 and actual == 0:
                tn += 1
            else:
                fn += 1

            test_predictions.append(
                {
                    "ioc_value": test_set[i]["ioc"],
                    "actual_label": "MALICIOUS" if actual == 1 else "BENIGN",
                    "predicted_label": "MALICIOUS" if pred == 1 else "BENIGN",
                    "correct": pred == actual,
                    "ensemble_prob": round(p_ens * 100.0, 1),
                    "rf_prob": round(p_rf * 100.0, 1),
                    "xgb_prob": round(p_xgb * 100.0, 1),
                    "mlp_prob": round(p_mlp * 100.0, 1),
                }
            )

        total_test = max(tp + fp + tn + fn, 1)
        accuracy = ((tp + tn) / total_test) * 100.0
        precision = (tp / max(tp + fp, 1)) * 100.0
        recall = (tp / max(tp + fn, 1)) * 100.0
        f1_score = (
            (2.0 * precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        fpr = (fp / max(fp + tn, 1)) * 100.0

        duration_ms = max(1, int(round(time.time() * 1000.0 - start_ms)))

        self.state = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_duration_ms": duration_ms,
            "hyperparameters": {
                "test_split": test_split,
                "learning_rate": learning_rate,
                "n_estimators": n_estimators,
                "weights": weights,
            },
            "dataset": {
                **corpus_stats,
                "train_size": len(train_set),
                "test_size": len(test_set),
            },
            "metrics": {
                "accuracy": round(accuracy, 1),
                "precision": round(precision, 1),
                "recall": round(recall, 1),
                "f1_score": round(f1_score, 1),
                "false_positive_rate": round(fpr, 2),
            },
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "feature_importances": feature_importances,
            "loss_history": self.mlp_model.loss_history,
            "test_predictions": test_predictions[:25],
            "normalization": {"means": means, "stds": stds},
        }

        return self.get_model_summary()

    def ensure_ready(self) -> None:
        if not self.state:
            self.train_and_evaluate()

    def get_model_summary(self) -> Dict[str, Any]:
        self.ensure_ready()
        assert self.state is not None
        return {
            "trained_at": self.state["trained_at"],
            "training_duration_ms": self.state["training_duration_ms"],
            "hyperparameters": self.state["hyperparameters"],
            "dataset": self.state["dataset"],
            "metrics": self.state["metrics"],
            "confusion_matrix": self.state["confusion_matrix"],
            "feature_importances": self.state["feature_importances"],
            "loss_history": self.state["loss_history"],
            "test_predictions": self.state["test_predictions"],
            "dataset_file": "machine_learning/datasets/training_dataset.csv",
            "model_files": [
                "machine_learning/models/xgboost_model.py",
                "machine_learning/models/random_forest_model.py",
                "machine_learning/models/neural_network_model.py",
                "machine_learning/models/isolation_forest_model.py",
            ],
        }

    def get_summary(self) -> Dict[str, Any]:
        return self.get_model_summary()

    def predict_single_ioc(self, ioc_value: str, feed_confidence: float = 50.0) -> Dict[str, Any]:
        self.ensure_ready()
        assert self.state is not None

        features = extract_ioc_features(ioc_value)
        raw_vec = feature_map_to_vector(features)
        means = self.state["normalization"]["means"]
        stds = self.state["normalization"]["stds"]
        norm_vec = [(raw_vec[j] - means[j]) / stds[j] for j in range(len(raw_vec))]

        rf_prob = self.rf_model.predict_proba(norm_vec)
        xgb_prob = self.xgb_model.predict_proba(norm_vec)
        mlp_prob = self.mlp_model.predict_proba(norm_vec)
        weights = self.state["hyperparameters"]["weights"]

        mal_prob = (
            weights["RandomForest"] * rf_prob
            + weights["XGBoost"] * xgb_prob
            + weights["NeuralNet"] * mlp_prob
        )

        anomaly_info = self.iso_model.score_anomaly(norm_vec, features)
        is_anomaly = anomaly_info["is_anomaly"]
        mean_abs_z = anomaly_info["isolation_z_score"]
        anomaly_bonus = anomaly_info["anomaly_bonus"]

        risk_score = round(
            min(100.0, 0.65 * (mal_prob * 100.0) + 0.25 * float(feed_confidence) + anomaly_bonus),
            1,
        )

        reasons: List[str] = []
        if features["uses_ip_host"] == 1.0:
            reasons.append("Raw IPv4 Host without TLS hostname")
        if features["has_non_standard_port"] == 1.0:
            reasons.append("Non-standard communication port")
        if features["suspicious_keyword_count"] > 0:
            reasons.append(f"{int(features['suspicious_keyword_count'])} malware delivery keywords detected")
        if features["shannon_entropy"] >= 3.8:
            reasons.append(
                f"High Shannon entropy ({features['shannon_entropy']} bits) - DGA/obfuscation signal"
            )
        if features["has_suspicious_tld"] == 1.0:
            reasons.append("High-abuse Top-Level Domain (TLD)")
        if is_anomaly:
            reasons.append(f"Isolation Forest flagged statistical outlier (Z-depth {mean_abs_z:.2f})")
        if not reasons:
            reasons.append("Structural lexical profile matches benign baseline traffic")

        verdict = "MALICIOUS" if risk_score >= 70 else ("SUSPICIOUS" if risk_score >= 40 else "BENIGN")

        return {
            "ioc_value": ioc_value,
            "verdict": verdict,
            "risk_score": risk_score,
            "ml_malicious_probability": round(mal_prob, 4),
            "model_breakdown": {
                "random_forest": round(rf_prob, 4),
                "xgboost": round(xgb_prob, 4),
                "neural_mlp": round(mlp_prob, 4),
                "isolation_z_score": round(mean_abs_z, 2),
            },
            "is_anomaly": bool(is_anomaly),
            "reasons": reasons,
            "features": features,
            "ensemble_weights": weights,
        }

    def predict(self, ioc_value: str, feed_confidence: float = 50.0) -> Dict[str, Any]:
        return self.predict_single_ioc(ioc_value, feed_confidence=feed_confidence)


_SINGLETON_MODEL: Optional[ThreatOpsEnsembleModel] = None


def get_singleton_model() -> ThreatOpsEnsembleModel:
    global _SINGLETON_MODEL
    if _SINGLETON_MODEL is None:
        _SINGLETON_MODEL = ThreatOpsEnsembleModel()
        _SINGLETON_MODEL.ensure_ready()
    return _SINGLETON_MODEL
