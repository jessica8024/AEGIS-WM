"""Evidence linker connecting forecast attributions to underlying network flows and host entities."""

from typing import Any, Dict, List, Optional
import numpy as np
import torch
from aegis_wm.explainability.attribution import AttributionEngine
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.schemas.explanation import (
    EntityAttribution,
    ExplanationResult,
    SupportingFlowReference,
)
from aegis_wm.schemas.forecast import ForecastTrajectory
from aegis_wm.schemas.labels import AttackStageEnum, EvidenceConfidenceEnum
from aegis_wm.schemas.state import NetworkWindowState
from aegis_wm.storage.telemetry import TelemetryStore


class EvidenceLinker:
    """Extracts entity attributions and supporting flow records backing a forecast trajectory."""

    def __init__(
        self,
        model: TemporalWorldModel,
        telemetry_store: TelemetryStore,
        scaler: Optional[Any] = None,
    ):
        self.attribution_engine = AttributionEngine(model)
        self.telemetry_store = telemetry_store
        self.scaler = scaler

    def build_explanation(
        self,
        trajectory: ForecastTrajectory,
        context_windows: List[NetworkWindowState],
        flow_parquet_path: Optional[str] = None,
        x_norm_tensor: Optional[torch.Tensor] = None,
    ) -> ExplanationResult:
        """
        Synthesizes complete evidence package:
        1. Runs Integrated Gradients on input context.
        2. Tests explanation ranking stability under perturbation.
        3. Identifies driving historical windows.
        4. Queries genuine supporting flows from those driving windows.
        5. Formulates entity attributions (top anomalous hosts/ports).
        """
        if x_norm_tensor is None:
            raw_feats = [w.feature_vector for w in context_windows]
            if self.scaler is not None:
                x_scaled = self.scaler.transform(np.array([raw_feats], dtype=np.float32))
                x_norm_tensor = torch.tensor(x_scaled, dtype=torch.float32)
            else:
                x_norm_tensor = torch.tensor([raw_feats], dtype=torch.float32)

        # 1. Feature and temporal attributions
        top_features, temporal_attrs = self.attribution_engine.attribute_features(x_norm_tensor)

        # Update timestamps in temporal attributions
        for t_attr in temporal_attrs:
            idx = t_attr.window_index
            if idx < len(context_windows):
                t_attr.timestamp = context_windows[idx].start_timestamp
                t_attr.active_flow_count = context_windows[idx].active_flow_count

        # 2. Stability check
        stability = self.attribution_engine.test_explanation_stability(x_norm_tensor)

        # 3. Retrieve driving historical window with highest attribution
        driving_window_idx = max(temporal_attrs, key=lambda t: t.contribution).window_index
        driving_window = (
            context_windows[driving_window_idx]
            if driving_window_idx < len(context_windows)
            else context_windows[-1]
        )

        # 4. Query supporting flows from Parquet for the driving window
        supporting_flows: List[SupportingFlowReference] = []
        entity_map: Dict[str, EntityAttribution] = {}

        if flow_parquet_path:
            try:
                t_start = driving_window.start_timestamp
                t_end = driving_window.end_timestamp
                filter_sql = f"start_timestamp <= {t_end} AND end_timestamp >= {t_start}"
                flow_records = self.telemetry_store.query_flows(
                    flow_parquet_path, sql_filter=filter_sql, limit=20
                )

                for r in flow_records:
                    anomalies = []
                    if r.get("rst_syn_ratio", 0) > 0.5:
                        anomalies.append("high_rst_rate")
                    if r.get("syn_ack_ratio", 0) > 2.0:
                        anomalies.append("syn_burst")
                    if r.get("fwd_packets", 0) > 50:
                        anomalies.append("high_volume")

                    supporting_flows.append(
                        SupportingFlowReference(
                            flow_id=str(r.get("flow_id", "")),
                            src_ip_pseudo=str(r.get("src_ip_pseudo", "")),
                            dst_ip_pseudo=str(r.get("dst_ip_pseudo", "")),
                            dst_port=int(r.get("dst_port", 0)),
                            protocol=int(r.get("protocol", 6)),
                            packets=int(r.get("fwd_packets", 0) + r.get("bwd_packets", 0)),
                            bytes=int(r.get("fwd_bytes", 0) + r.get("bwd_bytes", 0)),
                            timestamp=float(r.get("start_timestamp", 0.0)),
                            anomaly_flags=anomalies,
                        )
                    )

                    # Host entity tracking
                    src_host = str(r.get("src_ip_pseudo", ""))
                    if src_host and src_host not in entity_map:
                        entity_map[src_host] = EntityAttribution(
                            host_pseudo=src_host,
                            role="source_initiator",
                            risk_score=float(trajectory.max_risk_in_horizon),
                            unique_peers_contacted=1,
                            top_dst_ports=[int(r.get("dst_port", 0))],
                            top_protocols=[str(r.get("protocol", 6))],
                        )
            except Exception as e:
                # Log without crashing
                pass

        # Select target horizon point (horizon 1 or peak risk horizon)
        peak_pt = max(trajectory.points, key=lambda p: p.infiltration_probability)

        return ExplanationResult(
            forecast_id=trajectory.forecast_id,
            forecast_horizon=peak_pt.horizon_step,
            infiltration_probability=peak_pt.infiltration_probability,
            predicted_stage=peak_pt.predicted_stage,
            uncertainty_bounds={
                "lower": peak_pt.uncertainty_lower,
                "upper": peak_pt.uncertainty_upper,
                "entropy": peak_pt.predictive_entropy,
            },
            top_features=top_features[:8],
            temporal_attributions=temporal_attrs,
            supporting_entities=list(entity_map.values())[:5],
            supporting_flows=supporting_flows[:15],
            evidence_level=EvidenceConfidenceEnum.BEHAVIOURALLY_CONSISTENT,
            explanation_stability_score=stability,
        )
