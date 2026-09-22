"""Schema for model versioning and evaluation metadata."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ModelMetadata(BaseModel):
    """Metadata and performance benchmarks of a trained AEGIS-WM checkpoint."""

    model_id: str
    model_name: str = "TemporalWorldModel"
    architecture: str = "Transformer-GaussianNLL"
    checkpoint_sha256: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_feature_dim: int = 36
    context_length: int = 12
    forecast_horizon: int = 6
    feature_names: List[str] = Field(default_factory=list)

    # Training Provenance
    train_dataset_name: str
    train_dataset_hash: str
    train_epochs_completed: int
    train_loss: float
    validation_loss: float

    # Frozen Validation Evaluation Metrics
    optimal_detection_threshold: float = 0.50
    macro_f1_stage: float = 0.0
    auroc_infiltration: float = 0.0
    auprc_infiltration: float = 0.0
    brier_score: float = 0.0
    expected_calibration_error: float = 0.0
    lead_time_mean_seconds: float = 0.0
    k_step_rmse_state: float = 0.0

    # Safety & Preprocessing Artifacts
    scaler_artifact_path: str
    preprocessing_version: str = "1.0.0"
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
