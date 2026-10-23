"""
ThreatOps Isolation Forest Anomaly Model (`machine_learning/models/isolation_forest_model.py`)
----------------------------------------------------------------------------------------------
Tier-4 Model: Unsupervised Statistical Z-Depth & Shannon Entropy Outlier Detector.
Flags zero-day DGA domains, raw-IP C2 sockets, and high-entropy obfuscated payloads.
"""

import sys
from typing import Any, Dict, List

sys.dont_write_bytecode = True


class IsolationForestAnomalyDetector:
    """Unsupervised statistical Z-depth & Shannon entropy anomaly detector."""

    def __init__(self, z_threshold: float = 1.45, entropy_threshold: float = 4.15) -> None:
        self.z_threshold = z_threshold
        self.entropy_threshold = entropy_threshold

    def score_anomaly(
        self,
        norm_vec: List[float],
        features: Dict[str, float],
    ) -> Dict[str, Any]:
        mean_abs_z = sum(abs(z) for z in norm_vec) / max(len(norm_vec), 1)
        is_anomaly = (
            mean_abs_z >= self.z_threshold
            or features.get("shannon_entropy", 0.0) >= self.entropy_threshold
            or features.get("length", 0.0) > 80.0
            or (
                features.get("uses_ip_host", 0.0) == 1.0
                and features.get("has_non_standard_port", 0.0) == 1.0
                and features.get("suspicious_keyword_count", 0.0) >= 2.0
            )
        )
        return {
            "isolation_z_score": round(mean_abs_z, 2),
            "is_anomaly": bool(is_anomaly),
            "anomaly_bonus": 10.0 if is_anomaly else 0.0,
        }
