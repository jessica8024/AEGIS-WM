"""Unit tests for baseline models."""

import numpy as np
import pytest
import torch
from aegis_wm.models.baselines import (
    LSTMClassificationBaseline,
    PersistenceForecaster,
    StaticLogisticBaseline,
    StaticRandomForestBaseline,
)


def test_persistence_forecaster():
    x = np.random.randn(5, 12, 36)
    forecaster = PersistenceForecaster(forecast_horizon=6)
    pred = forecaster.predict(x)

    assert pred.shape == (5, 6, 36)
    # Every horizon step must equal the last observed window x[:, -1, :]
    for h in range(6):
        np.testing.assert_array_equal(pred[:, h, :], x[:, -1, :])


def test_static_baselines_fit_predict():
    x_train = np.random.randn(30, 12, 36)
    y_stage_train = np.random.randint(0, 3, size=(30, 6))
    y_risk_train = np.random.randint(0, 2, size=(30, 6)).astype(float)

    # Logistic regression
    lr = StaticLogisticBaseline()
    lr.fit(x_train, y_stage_train, y_risk_train)
    risk_probs, stages = lr.predict(x_train)
    assert len(risk_probs) == 30
    assert len(stages) == 30

    # Random forest
    rf = StaticRandomForestBaseline(n_estimators=10)
    rf.fit(x_train, y_stage_train, y_risk_train)
    rf_risk_probs, rf_stages = rf.predict(x_train)
    assert len(rf_risk_probs) == 30
    assert len(rf_stages) == 30


def test_lstm_classification_baseline():
    x = torch.randn(8, 12, 36)
    lstm = LSTMClassificationBaseline(
        feature_dim=36, hidden_dim=32, num_layers=1, forecast_horizon=6, num_stages=9
    )
    risk_probs, stage_logits = lstm(x)

    assert risk_probs.shape == (8, 6)
    assert stage_logits.shape == (8, 6, 9)
    assert torch.all(risk_probs >= 0.0) and torch.all(risk_probs <= 1.0)
