"""Baseline models: Persistence, Logistic Regression, Random Forest, and LSTM sequence classifier."""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression


class PersistenceForecaster:
    """
    Persistence Baseline: Predicts that the future state equals the current observed state:
    S_hat[t+k] = S[t] for all horizons k = 1..K.
    """

    def __init__(self, forecast_horizon: int = 6):
        self.forecast_horizon = forecast_horizon

    def predict(self, x: np.ndarray | torch.Tensor) -> np.ndarray:
        """
        x: [batch, context_length, feature_dim]
        Returns: [batch, forecast_horizon, feature_dim] where every future step equals x[:, -1, :]
        """
        if isinstance(x, torch.Tensor):
            arr = x.detach().cpu().numpy()
        else:
            arr = np.asarray(x)

        current_state = arr[:, -1, :]  # [batch, feature_dim]
        # Repeat across horizons
        forecast = np.repeat(current_state[:, np.newaxis, :], self.forecast_horizon, axis=1)
        return forecast


class StaticLogisticBaseline:
    """
    Static Feature Baseline: Logistic Regression trained strictly on current-window
    aggregated features S[t], without temporal context or transition modeling.
    """

    def __init__(self, max_iter: int = 1000):
        self.risk_model = LogisticRegression(max_iter=max_iter, class_weight="balanced")
        self.stage_model = LogisticRegression(max_iter=max_iter, class_weight="balanced")
        self.fitted = False

    def fit(self, x_train: np.ndarray, y_stage_train: np.ndarray, y_risk_train: np.ndarray) -> None:
        """
        x_train: [N, context_length, D] -> extracts current window S[t] = x[:, -1, :]
        """
        x_current = x_train[:, -1, :]
        self.risk_model.fit(x_current, y_risk_train[:, 0])
        self.stage_model.fit(x_current, y_stage_train[:, 0])
        self.fitted = True

    def predict(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Returns predicted risk probabilities and stage predictions for horizon 1."""
        if not self.fitted:
            raise RuntimeError("StaticLogisticBaseline must be fitted first.")
        x_current = x[:, -1, :]
        risk_probs = self.risk_model.predict_proba(x_current)[:, 1]
        stages = self.stage_model.predict(x_current)
        return risk_probs, stages


class StaticRandomForestBaseline:
    """
    Static Feature Baseline: Random Forest trained on current-window features S[t].
    """

    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.risk_model = RandomForestClassifier(
            n_estimators=n_estimators, random_state=random_state, class_weight="balanced"
        )
        self.stage_model = RandomForestClassifier(
            n_estimators=n_estimators, random_state=random_state, class_weight="balanced"
        )
        self.fitted = False

    def fit(self, x_train: np.ndarray, y_stage_train: np.ndarray, y_risk_train: np.ndarray) -> None:
        x_current = x_train[:, -1, :]
        self.risk_model.fit(x_current, y_risk_train[:, 0])
        self.stage_model.fit(x_current, y_stage_train[:, 0])
        self.fitted = True

    def predict(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        if not self.fitted:
            raise RuntimeError("StaticRandomForestBaseline must be fitted first.")
        x_current = x[:, -1, :]
        risk_probs = self.risk_model.predict_proba(x_current)[:, 1]
        stages = self.stage_model.predict(x_current)
        return risk_probs, stages


class LSTMClassificationBaseline(nn.Module):
    """
    Temporal Classification Baseline: Standard LSTM sequence classifier without explicit
    next-state transition loss or recursive rollout. Encodes context [t-m+1..t] directly
    to multi-horizon stage/risk predictions.
    """

    def __init__(
        self,
        feature_dim: int = 36,
        hidden_dim: int = 64,
        num_layers: int = 2,
        num_stages: int = 9,
        forecast_horizon: int = 6,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.forecast_horizon = forecast_horizon
        self.num_stages = num_stages

        self.lstm = nn.LSTM(
            input_size=feature_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        # Direct multi-horizon prediction heads (without state transition dynamics)
        self.risk_head = nn.Linear(hidden_dim, forecast_horizon)
        self.stage_head = nn.Linear(hidden_dim, forecast_horizon * num_stages)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Input x: [batch, context_length, feature_dim]
        Returns:
            risk_probs: [batch, forecast_horizon] (sigmoid probabilities)
            stage_logits: [batch, forecast_horizon, num_stages]
        """
        lstm_out, _ = self.lstm(x)
        last_hidden = lstm_out[:, -1, :]  # [batch, hidden_dim]

        risk_logits = self.risk_head(last_hidden)  # [batch, K]
        risk_probs = torch.sigmoid(risk_logits)

        stage_raw = self.stage_head(last_hidden)  # [batch, K * num_stages]
        stage_logits = stage_raw.view(-1, self.forecast_horizon, self.num_stages)

        return risk_probs, stage_logits
