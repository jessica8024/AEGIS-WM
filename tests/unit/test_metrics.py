"""Unit tests for evaluation metrics suite."""

import numpy as np
import pytest
from aegis_wm.evaluation.metrics import (
    compute_expected_calibration_error,
    compute_forecast_state_metrics,
    compute_infiltration_prediction_metrics,
    compute_lead_time_metrics,
    compute_stage_classification_metrics,
)


def test_ece_computation():
    y_true = np.array([0, 0, 1, 1])
    y_prob = np.array([0.1, 0.2, 0.8, 0.9])
    ece = compute_expected_calibration_error(y_true, y_prob)
    assert 0.0 <= ece <= 1.0
    # Well-calibrated predictions have low ECE
    assert ece < 0.25


def test_stage_metrics_computation():
    y_true = np.array([0, 1, 2, 0, 1, 2])
    y_pred = np.array([0, 1, 2, 0, 1, 0])
    metrics = compute_stage_classification_metrics(y_true, y_pred, num_classes=3)

    assert "macro_f1" in metrics
    assert "weighted_f1" in metrics
    assert "confusion_matrix" in metrics
    assert metrics["macro_f1"] > 0.5


def test_infiltration_metrics():
    y_true = np.array([0, 0, 1, 1, 1])
    y_prob = np.array([0.05, 0.1, 0.85, 0.9, 0.95])
    metrics = compute_infiltration_prediction_metrics(y_true, y_prob, threshold=0.5)

    assert metrics["auroc"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["brier_score"] < 0.05


def test_forecast_state_metrics():
    y_true = np.ones((10, 6, 36))
    y_pred = np.ones((10, 6, 36)) * 1.5
    metrics = compute_forecast_state_metrics(y_true, y_pred)

    assert abs(metrics["overall_mae"] - 0.5) < 1e-5
    assert len(metrics["mae_by_horizon"]) == 6


def test_lead_time_metrics():
    # Attack happens at index 10
    y_true_series = [0] * 10 + [1] * 5
    # Forecasts at index 7 predict risk at horizons 1..6
    forecasts = [[0.1] * 6 for _ in range(7)]
    forecasts.append([0.2, 0.4, 0.85, 0.9, 0.95, 0.95])  # index 7: horizon 3 lands on index 10

    res = compute_lead_time_metrics(y_true_series, forecasts, window_duration_seconds=5.0)
    assert res["attacks_observed"] is True
    assert res["mean_lead_time_windows"] == 3.0
    assert res["mean_lead_time_seconds"] == 15.0
