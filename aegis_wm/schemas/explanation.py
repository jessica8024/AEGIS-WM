"""Schemas for multi-level model explainability and evidence linking."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from aegis_wm.schemas.labels import AttackStageEnum, EvidenceConfidenceEnum


class FeatureAttribution(BaseModel):
    """Attribution score for an individual state feature."""

    feature_name: str
    contribution: float = Field(..., description="Attribution value (signed magnitude)")
    direction: str = Field(..., description="'increases_risk' or 'decreases_risk'")
    relative_importance: float = Field(..., ge=0.0, le=1.0, description="Normalized absolute weight")


class TemporalAttribution(BaseModel):
    """Importance of a historical context window [t-m+1, ..., t]."""

    window_index: int
    relative_window_offset: int = Field(..., description="Offset relative to forecast origin (e.g. -5)")
    timestamp: float
    contribution: float
    active_flow_count: int


class EntityAttribution(BaseModel):
    """High-risk entity associated with the forecast."""

    host_pseudo: str
    role: str
    risk_score: float
    unique_peers_contacted: int
    top_dst_ports: List[int] = Field(default_factory=list)
    top_protocols: List[str] = Field(default_factory=list)


class SupportingFlowReference(BaseModel):
    """Pointer to authentic underlying telemetry flow record."""

    flow_id: str
    src_ip_pseudo: str
    dst_ip_pseudo: str
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    timestamp: float
    anomaly_flags: List[str] = Field(default_factory=list)


class ExplanationResult(BaseModel):
    """Complete evidence package backing a forecast."""

    forecast_id: str
    forecast_horizon: int
    infiltration_probability: float
    predicted_stage: AttackStageEnum
    uncertainty_bounds: Dict[str, float] = Field(default_factory=dict)
    top_features: List[FeatureAttribution] = Field(default_factory=list)
    temporal_attributions: List[TemporalAttribution] = Field(default_factory=list)
    supporting_entities: List[EntityAttribution] = Field(default_factory=list)
    supporting_flows: List[SupportingFlowReference] = Field(default_factory=list)
    evidence_level: EvidenceConfidenceEnum = EvidenceConfidenceEnum.BEHAVIOURALLY_CONSISTENT
    explanation_stability_score: float = Field(
        1.0, description="Spearman rank correlation under non-critical feature perturbation"
    )
