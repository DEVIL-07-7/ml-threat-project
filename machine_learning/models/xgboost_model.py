"""
ThreatOps XGBoost Model (`machine_learning/models/xgboost_model.py`)
--------------------------------------------------------------------
Tier-2 Model: Sequential Gradient Boosted Regression Stumps on Log-Odds Residuals (XGBoost-style).
"""

import math
import sys
from typing import Any, Dict, List

sys.dont_write_bytecode = True


def _sigmoid(z: float) -> float:
    if z > 20.0:
        return 1.0
    if z < -20.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-z))


class XGBoostIOCClassifier:
    """XGBoost-style sequential gradient boosted regression stumps on log-odds residuals."""

    def __init__(self, n_estimators: int = 100, learning_rate: float = 0.12) -> None:
        self.boost_rounds = min(120, n_estimators)
        self.learning_rate = learning_rate
        self.base_logit: float = 0.0
        self.stumps: List[Dict[str, Any]] = []

    def fit(
        self,
        X_train: List[List[float]],
        y_train: List[int],
        feature_importance_raw: List[float],
    ) -> None:
        self.stumps = []
        num_samples = len(X_train)
        num_features = len(feature_importance_raw)
        pos_count = sum(1 for y in y_train if y == 1)
        self.base_logit = math.log((pos_count + 1.0) / (num_samples - pos_count + 1.0))
        f_train = [self.base_logit] * num_samples
        thresholds = [-0.5, 0.0, 0.5, 1.0]

        for _ in range(self.boost_rounds):
            residuals = [y_train[i] - _sigmoid(f_train[i]) for i in range(num_samples)]
            best_f = 0
            best_thresh = 0.0
            best_loss = float("inf")
            best_left_val = 0.0
            best_right_val = 0.0

            for f_idx in range(num_features):
                for thresh in thresholds:
                    l_sum = 0.0
                    l_cnt = 0
                    r_sum = 0.0
                    r_cnt = 0
                    for i in range(num_samples):
                        if X_train[i][f_idx] <= thresh:
                            l_sum += residuals[i]
                            l_cnt += 1
                        else:
                            r_sum += residuals[i]
                            r_cnt += 1
                    if l_cnt == 0 or r_cnt == 0:
                        continue
                    l_val = l_sum / l_cnt
                    r_val = r_sum / r_cnt
                    mse = 0.0
                    for i in range(num_samples):
                        pred = l_val if X_train[i][f_idx] <= thresh else r_val
                        diff = residuals[i] - pred
                        mse += diff * diff
                    if mse < best_loss:
                        best_loss = mse
                        best_f = f_idx
                        best_thresh = thresh
                        best_left_val = l_val * 2.2
                        best_right_val = r_val * 2.2

            for i in range(num_samples):
                step_val = best_left_val if X_train[i][best_f] <= best_thresh else best_right_val
                f_train[i] += self.learning_rate * step_val

            feature_importance_raw[best_f] += abs(best_right_val - best_left_val) * 0.4
            self.stumps.append(
                {
                    "fIdx": best_f,
                    "thresh": best_thresh,
                    "leftVal": round(best_left_val, 6),
                    "rightVal": round(best_right_val, 6),
                    "lr": self.learning_rate,
                }
            )

    def predict_proba(self, norm_x: List[float]) -> float:
        logit = self.base_logit
        for s in self.stumps:
            val = s["leftVal"] if norm_x[s["fIdx"]] <= s["thresh"] else s["rightVal"]
            logit += s["lr"] * val
        return _sigmoid(logit)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_type": "XGBoostIOCClassifier",
            "boost_rounds": self.boost_rounds,
            "learning_rate": self.learning_rate,
            "base_logit": self.base_logit,
            "stumps": self.stumps,
        }

    def load_dict(self, data: Dict[str, Any]) -> None:
        self.boost_rounds = int(data.get("boost_rounds", self.boost_rounds))
        self.learning_rate = float(data.get("learning_rate", self.learning_rate))
        self.base_logit = float(data.get("base_logit", 0.0))
        self.stumps = list(data.get("stumps", []))
