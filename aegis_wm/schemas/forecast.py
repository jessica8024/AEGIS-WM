"""Schemas for multi-step forecasts and rollout trajectories."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from aegis_wm.schemas.labels import AttackStageEnum


class ForecastPoint(BaseModel):
    """Prediction for a single future horizon window (t+k)."""

    horizon_step: int = Field(..., ge=1, description="Future step k (e.g. 1 to K)")
    target_timestamp: float = Field(..., description="Projected epoch timestamp")
    predicted_state: List[float] = Field(..., description="Projected state vector S_hat[t+k]")
    state_variance: List[float] = Field(default_factory=list, description="Diagonal variance sigma^2[t+k]")

    # Infiltration Risk & Uncertainty
    infiltration_probability: float = Field(..., ge=0.0, le=1.0)
    uncertainty_lower: float = Field(..., ge=0.0, le=1.0, description="95% CI lower bound")
    uncertainty_upper: float = Field(..., ge=0.0, le=1.0, description="95% CI upper bound")
    predictive_entropy: float = Field(0.0, description="Predictive entropy across stage distribution")

    # Stage Classification
    predicted_stage: AttackStageEnum = Field(..., description="Most likely attack stage")
    stage_probabilities: Dict[str, float] = Field(
        ..., description="Full probability distribution over all 9 stages"
    )

    # Progression Slope
    risk_velocity: float = Field(0.0, description="Rate of risk change (p[t+k] - p[t+k-1])")


class ForecastTrajectory(BaseModel):
    """Complete K-step autoregressive rollout trajectory."""

    forecast_id: str = Field(..., description="Unique forecast execution identifier")
    analysis_id: str = Field(..., description="Associated analysis job ID")
    base_window_index: int = Field(..., description="Origin window t from which rollout began")
    base_timestamp: float = Field(..., description="Timestamp of origin window t")
    horizon_count: int = Field(..., description="Total rolled out steps K")
    rollout_mode: str = Field("deterministic", description="'deterministic' or 'monte_carlo'")
    points: List[ForecastPoint] = Field(..., description="List of K forecast points")
    max_risk_in_horizon: float = Field(0.0)
    peak_stage_predicted: AttackStageEnum = Field(AttackStageEnum.BENIGN)
