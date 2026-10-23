"""
ThreatOps Random Forest Model (`machine_learning/models/random_forest_model.py`)
--------------------------------------------------------------------------------
Tier-1 Model: Bootstrap-Aggregated Gini Impurity Decision Forest Classifier.
"""

import sys
from typing import Any, Dict, List

sys.dont_write_bytecode = True


class RandomForestIOCClassifier:
    """Bootstrap-aggregated Gini impurity decision forest for lexical IOC classification."""

    def __init__(self, n_estimators: int = 100) -> None:
        self.n_estimators = n_estimators
        self.trees: List[Dict[str, Any]] = []

    def fit(
        self,
        X_train: List[List[float]],
        y_train: List[int],
        rng: Any,
        feature_importance_raw: List[float],
    ) -> None:
        self.trees = []
        num_samples = len(X_train)
        num_features = len(feature_importance_raw)
        thresholds = [-0.6, -0.2, 0.0, 0.3, 0.75, 1.2]

        for _ in range(self.n_estimators):
            boot_indices = [int(rng.next_float() * num_samples) for _ in range(num_samples)]
            candidate_features: List[int] = []
            while len(candidate_features) < 5:
                f_idx = int(rng.next_float() * num_features)
                if f_idx not in candidate_features:
                    candidate_features.append(f_idx)

            best_f = candidate_features[0]
            best_thresh = 0.0
            best_gini_gain = -1.0
            best_left_prob = 0.5
            best_right_prob = 0.5

            for f_idx in candidate_features:
                for thresh in thresholds:
                    l_pos = 0
                    l_tot = 0
                    r_pos = 0
                    r_tot = 0
                    for idx in boot_indices:
                        if X_train[idx][f_idx] <= thresh:
                            l_tot += 1
                            if y_train[idx] == 1:
                                l_pos += 1
                        else:
                            r_tot += 1
                            if y_train[idx] == 1:
                                r_pos += 1
                    if l_tot == 0 or r_tot == 0:
                        continue
                    p_l = l_pos / l_tot
                    p_r = r_pos / r_tot
                    gini_l = 1.0 - p_l * p_l - (1.0 - p_l) * (1.0 - p_l)
                    gini_r = 1.0 - p_r * p_r - (1.0 - p_r) * (1.0 - p_r)
                    gain = 0.5 - (l_tot * gini_l + r_tot * gini_r) / len(boot_indices)
                    if gain > best_gini_gain:
                        best_gini_gain = gain
                        best_f = f_idx
                        best_thresh = thresh
                        best_left_prob = (l_pos + 1.0) / (l_tot + 2.0)
                        best_right_prob = (r_pos + 1.0) / (r_tot + 2.0)

            if best_gini_gain > 0:
                feature_importance_raw[best_f] += best_gini_gain * 2.0

            self.trees.append(
                {
                    "fIdx": best_f,
                    "thresh": best_thresh,
                    "leftProb": round(best_left_prob, 6),
                    "rightProb": round(best_right_prob, 6),
                }
            )

    def predict_proba(self, norm_x: List[float]) -> float:
        if not self.trees:
            return 0.5
        total = 0.0
        for tree in self.trees:
            total += tree["leftProb"] if norm_x[tree["fIdx"]] <= tree["thresh"] else tree["rightProb"]
        return total / len(self.trees)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_type": "RandomForestIOCClassifier",
            "n_estimators": self.n_estimators,
            "trees": self.trees,
        }

    def load_dict(self, data: Dict[str, Any]) -> None:
        self.n_estimators = int(data.get("n_estimators", self.n_estimators))
        self.trees = list(data.get("trees", []))
