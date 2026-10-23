"""
ThreatOps Neural Network MLP Model (`machine_learning/models/neural_network_model.py`)
--------------------------------------------------------------------------------------
Tier-3 Model: 2-Layer Feedforward Multi-Layer Perceptron (LeakyReLU + L2 Regularization).
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


class NeuralNetworkMLPClassifier:
    """2-Layer Feedforward Neural Network (LeakyReLU hidden layer + L2 regularization)."""

    def __init__(self, hidden_dim: int = 12, epochs: int = 60, learning_rate: float = 0.12) -> None:
        self.hidden_dim = hidden_dim
        self.epochs = epochs
        self.learning_rate = learning_rate
        self.W1: List[List[float]] = []
        self.b1: List[float] = []
        self.W2: List[float] = []
        self.b2: float = 0.0
        self.loss_history: List[Dict[str, float]] = []

    def fit(
        self,
        X_train: List[List[float]],
        y_train: List[int],
        rng: Any,
        feature_importance_raw: List[float],
    ) -> None:
        num_features = len(feature_importance_raw)
        num_samples = max(len(X_train), 1)
        self.W1 = [
            [(rng.next_float() - 0.5) * 0.35 for _ in range(num_features)]
            for _ in range(self.hidden_dim)
        ]
        self.b1 = [0.05] * self.hidden_dim
        self.W2 = [(rng.next_float() - 0.5) * 0.4 for _ in range(self.hidden_dim)]
        self.b2 = 0.0
        self.loss_history = []

        mlp_lr = self.learning_rate * 1.15
        step = mlp_lr / num_samples

        for ep in range(self.epochs):
            epoch_loss = 0.0
            for i in range(len(X_train)):
                x = X_train[i]
                y = y_train[i]

                h = [0.0] * self.hidden_dim
                for k in range(self.hidden_dim):
                    z1 = self.b1[k]
                    w1_row = self.W1[k]
                    for j in range(num_features):
                        z1 += w1_row[j] * x[j]
                    h[k] = z1 if z1 > 0.0 else 0.01 * z1

                z2 = self.b2
                for k in range(self.hidden_dim):
                    z2 += self.W2[k] * h[k]
                p = _sigmoid(z2)

                epoch_loss += -(y * math.log(p + 1e-7) + (1 - y) * math.log(1.0 - p + 1e-7))

                dz2 = p - y
                self.b2 -= step * dz2
                for k in range(self.hidden_dim):
                    dh = self.W2[k] * dz2
                    dz1 = dh if h[k] > 0.0 else 0.01 * dh
                    self.W2[k] -= step * (dz2 * h[k] + 0.002 * self.W2[k])
                    self.b1[k] -= step * dz1
                    w1_row = self.W1[k]
                    for j in range(num_features):
                        w1_row[j] -= step * (dz1 * x[j] + 0.002 * w1_row[j])

            if ep % 10 == 0 or ep == self.epochs - 1:
                self.loss_history.append(
                    {
                        "epoch": ep + 1,
                        "loss": round(epoch_loss / num_samples, 4),
                    }
                )

        for j in range(num_features):
            w_mag = sum(abs(self.W1[k][j] * self.W2[k]) for k in range(self.hidden_dim))
            feature_importance_raw[j] += w_mag * 0.5

    def predict_proba(self, norm_x: List[float]) -> float:
        if not self.W1 or not self.W2:
            return 0.5
        num_features = len(norm_x)
        h = [0.0] * self.hidden_dim
        for k in range(self.hidden_dim):
            z1 = self.b1[k]
            w1_row = self.W1[k]
            for j in range(num_features):
                z1 += w1_row[j] * norm_x[j]
            h[k] = z1 if z1 > 0.0 else 0.01 * z1
        z2 = self.b2
        for k in range(self.hidden_dim):
            z2 += self.W2[k] * h[k]
        return _sigmoid(z2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_type": "NeuralNetworkMLPClassifier",
            "hidden_dim": self.hidden_dim,
            "epochs": self.epochs,
            "learning_rate": self.learning_rate,
            "W1": self.W1,
            "b1": self.b1,
            "W2": self.W2,
            "b2": self.b2,
            "loss_history": self.loss_history,
        }

    def load_dict(self, data: Dict[str, Any]) -> None:
        self.hidden_dim = int(data.get("hidden_dim", self.hidden_dim))
        self.epochs = int(data.get("epochs", self.epochs))
        self.learning_rate = float(data.get("learning_rate", self.learning_rate))
        self.W1 = list(data.get("W1", []))
        self.b1 = list(data.get("b1", []))
        self.W2 = list(data.get("W2", []))
        self.b2 = float(data.get("b2", 0.0))
        self.loss_history = list(data.get("loss_history", []))
