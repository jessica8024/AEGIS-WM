"""Unit tests for recursive rollout and Monte Carlo uncertainty estimation."""

import pytest
import torch
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.state import NetworkWindowState
from aegis_wm.state.preprocessor import StateFeatureScaler
from aegis_wm.forecasting.rollout import RecursiveForecaster


def make_dummy_window(idx: int, t: float) -> NetworkWindowState:
    prov = ProvenanceMetadata(
        source_file_hash="0" * 64,
        extraction_config_hash="0" * 64,
        start_timestamp=t,
        end_timestamp=t + 5.0,
        provenance_reference="test",
    )
    return NetworkWindowState(
        window_index=idx,
        start_timestamp=t,
        end_timestamp=t + 5.0,
        duration_seconds=5.0,
        provenance=prov,
        feature_vector=[float(idx)] * 36,
        feature_names=[f"f_{i}" for i in range(36)],
    )


def test_recursive_rollout_deterministic():
    model = TemporalWorldModel(
        feature_dim=36,
        d_model=32,
        latent_dim=16,
        num_layers=1,
        num_heads=2,
        context_length=12,
        forecast_horizon=6,
    )
    scaler = StateFeatureScaler()
    scaler.fit(torch.randn(10, 12, 36))

    forecaster = RecursiveForecaster(
        model=model, scaler=scaler, forecast_horizon=6, window_duration_seconds=5.0
    )

    context = [make_dummy_window(i, 100.0 + i * 5.0) for i in range(12)]
    traj = forecaster.forecast(context, rollout_mode="deterministic")

    assert traj.horizon_count == 6
    assert len(traj.points) == 6
    for i, pt in enumerate(traj.points):
        assert pt.horizon_step == i + 1
        assert len(pt.predicted_state) == 36
        assert 0.0 <= pt.infiltration_probability <= 1.0
        assert pt.uncertainty_lower <= pt.infiltration_probability <= pt.uncertainty_upper + 1e-4
        assert len(pt.stage_probabilities) == 9


def test_recursive_rollout_monte_carlo():
    model = TemporalWorldModel(
        feature_dim=36,
        d_model=32,
        latent_dim=16,
        num_layers=1,
        num_heads=2,
        context_length=12,
        forecast_horizon=6,
    )
    scaler = StateFeatureScaler()
    scaler.fit(torch.randn(10, 12, 36))

    forecaster = RecursiveForecaster(
        model=model, scaler=scaler, forecast_horizon=6, window_duration_seconds=5.0
    )

    context = [make_dummy_window(i, 100.0 + i * 5.0) for i in range(12)]
    traj = forecaster.forecast(context, rollout_mode="monte_carlo", mc_trajectories=10)

    assert traj.rollout_mode == "monte_carlo"
    assert len(traj.points) == 6
    # In Monte Carlo rollout, uncertainty bounds must be well-formed
    for pt in traj.points:
        assert pt.uncertainty_lower <= pt.uncertainty_upper
