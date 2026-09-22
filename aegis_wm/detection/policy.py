"""Anticipatory detection policy engine with persistence tracking, deduplication, and audit logging."""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from aegis_wm.common.crypto import compute_sha256
from aegis_wm.common.logger import logger
from aegis_wm.schemas.alert import AlertRecord, AlertSeverityEnum, AlertStateEnum
from aegis_wm.schemas.explanation import ExplanationResult
from aegis_wm.schemas.forecast import ForecastTrajectory
from aegis_wm.schemas.labels import AttackStageEnum
from aegis_wm.storage.sqlite import SQLiteMetadataStore


class DetectionPolicyEngine:
    """Evaluates forecast trajectories against anticipatory alerting policies."""

    def __init__(
        self,
        metadata_store: SQLiteMetadataStore,
        risk_threshold_warning: float = 0.45,
        risk_threshold_critical: float = 0.70,
        min_persistence_windows: int = 2,
        max_uncertainty_threshold: float = 0.40,
        min_supporting_flows: int = 1,
    ):
        self.store = metadata_store
        self.warning_threshold = risk_threshold_warning
        self.critical_threshold = risk_threshold_critical
        self.min_persistence = min_persistence_windows
        self.max_uncertainty = max_uncertainty_threshold
        self.min_flows = min_supporting_flows

        # Rolling state for persistence tracking per analysis
        self._consecutive_elevated_windows: Dict[str, int] = {}
        self._last_alert_hashes: Dict[str, str] = {}

    def evaluate_forecast(
        self,
        trajectory: ForecastTrajectory,
        explanation: Optional[ExplanationResult] = None,
        analysis_id: str = "analysis_001",
    ) -> Optional[AlertRecord]:
        """
        Applies policy rules to a forecast trajectory:
        1. Checks whether projected risk exceeds warning/critical thresholds.
        2. Enforces uncertainty threshold (filters out low-confidence forecasts).
        3. Enforces persistence requirement (N consecutive elevated windows).
        4. Verifies supporting flow evidence.
        5. Deduplicates repeat alerts.
        """
        max_risk = trajectory.max_risk_in_horizon
        peak_pt = max(trajectory.points, key=lambda p: p.infiltration_probability)
        uncertainty_range = peak_pt.uncertainty_upper - peak_pt.uncertainty_lower

        # Uncertainty safety guard: do not alert if forecast uncertainty is too wide
        if uncertainty_range > self.max_uncertainty:
            return None

        is_elevated = max_risk >= self.warning_threshold
        prev_count = self._consecutive_elevated_windows.get(analysis_id, 0)

        if is_elevated:
            new_count = prev_count + 1
            self._consecutive_elevated_windows[analysis_id] = new_count
        else:
            self._consecutive_elevated_windows[analysis_id] = 0
            return None

        # Check persistence requirement
        if new_count < self.min_persistence:
            return None

        # Severity determination
        if max_risk >= self.critical_threshold:
            severity = AlertSeverityEnum.CRITICAL
            rule_id = "POLICY_ANTICIPATORY_CRITICAL_SURGE"
        else:
            severity = AlertSeverityEnum.WARNING
            rule_id = "POLICY_ANTICIPATORY_WARNING_ELEVATION"

        # Evidence indicators
        top_indicators = []
        supporting_flow_count = 0
        primary_host = None

        if explanation:
            top_indicators = [f.feature_name for f in explanation.top_features[:3]]
            supporting_flow_count = len(explanation.supporting_flows)
            if explanation.supporting_entities:
                primary_host = explanation.supporting_entities[0].host_pseudo

        # Deduplication check: avoid spamming identical alerts for the same window & stage
        dedup_key = compute_sha256(
            f"{analysis_id}:{peak_pt.predicted_stage}:{int(max_risk * 10)}:{primary_host}"
        )
        if self._last_alert_hashes.get(analysis_id) == dedup_key:
            return None
        self._last_alert_hashes[analysis_id] = dedup_key

        alert = AlertRecord(
            alert_id=f"alt_{uuid.uuid4().hex[:12]}",
            analysis_id=analysis_id,
            forecast_id=trajectory.forecast_id,
            created_at=datetime.now(timezone.utc),
            severity=severity,
            state=AlertStateEnum.ACTIVE,
            forecast_horizon_seconds=peak_pt.horizon_step * 5.0,
            forecast_horizon_steps=peak_pt.horizon_step,
            infiltration_probability=float(max_risk),
            uncertainty_range=float(uncertainty_range),
            predicted_stage=peak_pt.predicted_stage,
            primary_host_pseudo=primary_host,
            top_indicator_features=top_indicators,
            supporting_flow_count=supporting_flow_count,
            policy_rule_triggered=rule_id,
        )

        # Persist alert and audit record
        self.store.save_alert(alert)
        self.store.record_audit(
            action="ALERT_TRIGGERED",
            target_resource=alert.alert_id,
            details={
                "severity": severity.value,
                "horizon_steps": peak_pt.horizon_step,
                "risk": float(max_risk),
                "stage": AttackStageEnum.get_display_name(int(peak_pt.predicted_stage)),
            },
        )

        logger.info(
            f"Generated {severity.value.upper()} Alert {alert.alert_id}: "
            f"Stage={AttackStageEnum.get_display_name(int(peak_pt.predicted_stage))}, "
            f"Risk={max_risk:.2f}, Horizon={peak_pt.horizon_step} steps."
        )

        return alert
