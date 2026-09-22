"""Unit tests for detection policy engine."""

import tempfile
from pathlib import Path
import pytest
from aegis_wm.detection.policy import DetectionPolicyEngine
from aegis_wm.schemas.alert import AlertSeverityEnum
from aegis_wm.schemas.forecast import ForecastPoint, ForecastTrajectory
from aegis_wm.schemas.labels import AttackStageEnum
from aegis_wm.storage.sqlite import SQLiteMetadataStore


def make_test_trajectory(risk: float, uncert_range: float = 0.1) -> ForecastTrajectory:
    pt = ForecastPoint(
        horizon_step=1,
        target_timestamp=100.0,
        predicted_state=[0.0] * 36,
        infiltration_probability=risk,
        uncertainty_lower=max(0.0, risk - uncert_range / 2),
        uncertainty_upper=min(1.0, risk + uncert_range / 2),
        predicted_stage=AttackStageEnum.LATERAL_MOVEMENT,
        stage_probabilities={"LATERAL_MOVEMENT": 0.9, "BENIGN": 0.1},
    )
    return ForecastTrajectory(
        forecast_id=f"fc_{risk}",
        analysis_id="an_test",
        base_window_index=10,
        base_timestamp=95.0,
        horizon_count=1,
        points=[pt],
        max_risk_in_horizon=risk,
        peak_stage_predicted=AttackStageEnum.LATERAL_MOVEMENT,
    )


def test_policy_engine_persistence_and_alerting():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_policy.db"
        store = SQLiteMetadataStore(db_path=db_path)

        engine = DetectionPolicyEngine(
            metadata_store=store,
            risk_threshold_warning=0.45,
            risk_threshold_critical=0.70,
            min_persistence_windows=2,
            max_uncertainty_threshold=0.35,
        )

        # Window 1: Risk = 0.8 (elevated), but persistence is 1 -> no alert yet
        traj1 = make_test_trajectory(risk=0.80)
        alert1 = engine.evaluate_forecast(traj1, analysis_id="an_01")
        assert alert1 is None

        # Window 2: Risk = 0.82 (elevated), persistence is 2 -> alert triggers!
        traj2 = make_test_trajectory(risk=0.82)
        alert2 = engine.evaluate_forecast(traj2, analysis_id="an_01")
        assert alert2 is not None
        assert alert2.severity == AlertSeverityEnum.CRITICAL
        assert alert2.predicted_stage == AttackStageEnum.LATERAL_MOVEMENT

        # Verify alert is persisted in SQLite
        stored_alerts = store.list_alerts("an_01")
        assert len(stored_alerts) == 1
        assert stored_alerts[0].alert_id == alert2.alert_id


def test_policy_engine_filters_excessive_uncertainty():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_policy.db"
        store = SQLiteMetadataStore(db_path=db_path)

        engine = DetectionPolicyEngine(
            metadata_store=store,
            risk_threshold_warning=0.45,
            max_uncertainty_threshold=0.30,
            min_persistence_windows=1,
        )

        # High risk (0.8), but wide uncertainty range (0.50) -> should be suppressed
        traj = make_test_trajectory(risk=0.80, uncert_range=0.50)
        alert = engine.evaluate_forecast(traj, analysis_id="an_02")
        assert alert is None
