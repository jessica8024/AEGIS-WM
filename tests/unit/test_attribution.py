"""Unit tests for feature attribution and explanation stability."""

import pytest
import torch
from aegis_wm.explainability.attribution import AttributionEngine
from aegis_wm.models.world_model import TemporalWorldModel


def test_integrated_gradients_attribution():
    model = TemporalWorldModel(
        feature_dim=36,
        d_model=32,
        latent_dim=16,
        num_layers=1,
        num_heads=2,
        context_length=8,
        forecast_horizon=4,
    )
    engine = AttributionEngine(model)

    x = torch.randn(1, 8, 36)
    features, temporal = engine.attribute_features(x)

    assert len(features) == 36
    # Top features must be sorted descending by relative importance
    assert features[0].relative_importance >= features[1].relative_importance
    assert features[0].direction in ["increases_risk", "decreases_risk"]

    assert len(temporal) == 8
    for t_attr in temporal:
        assert t_attr.relative_window_offset <= 0


def test_explanation_stability_metric():
    model = TemporalWorldModel(
        feature_dim=36,
        d_model=32,
        latent_dim=16,
        num_layers=1,
        num_heads=2,
        context_length=8,
        forecast_horizon=4,
    )
    engine = AttributionEngine(model)

    x = torch.randn(1, 8, 36)
    stability = engine.test_explanation_stability(x, noise_std=0.01, num_trials=3)

    assert -1.0 <= stability <= 1.0
    # Low noise should yield high rank stability
    assert stability > 0.3
