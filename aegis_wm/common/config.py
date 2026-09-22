"""Configuration loading and validation using Pydantic."""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field


class IngestionConfig(BaseModel):
    active_timeout_seconds: float = 120.0
    inactive_timeout_seconds: float = 15.0
    max_packets_per_flow: int = 10000
    bpf_filter: str = ""
    max_queue_size: int = 50000
    capture_buffer_size_mb: int = 128


class WindowConfig(BaseModel):
    window_size_seconds: float = 5.0
    context_length: int = 12  # number of past windows observed (m)
    forecast_horizon: int = 6  # number of future windows rolled out (K)
    slide_step_seconds: float = 5.0
    pseudonym_salt: str = "aegis_wm_secure_local_salt_2026"


class ModelConfig(BaseModel):
    name: str = "TemporalWorldModel"
    feature_dim: int = 36
    latent_dim: int = 64
    hidden_dim: int = 128
    num_layers: int = 2
    num_heads: int = 4
    dropout: float = 0.1
    encoder_type: str = "transformer"  # "transformer" or "gru"
    log_var_min: float = -7.0
    log_var_max: float = 2.0


class TrainingConfig(BaseModel):
    batch_size: int = 32
    learning_rate: float = 0.001
    weight_decay: float = 1e-4
    epochs: int = 30
    early_stopping_patience: int = 5
    scheduled_sampling_k: float = 10.0  # inverse sigmoid decay for scheduled sampling
    lambda_state: float = 1.0
    lambda_stage: float = 1.0
    lambda_risk: float = 1.0
    lambda_consistency: float = 0.5
    device: str = "auto"


class PolicyConfig(BaseModel):
    risk_threshold_warning: float = 0.45
    risk_threshold_critical: float = 0.70
    min_persistence_windows: int = 2
    max_uncertainty_threshold: float = 0.40
    min_supporting_flows: int = 1


class SystemConfig(BaseModel):
    version: str = "0.1.0"
    storage_dir: str = "data"
    model_checkpoint_dir: str = "models"
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    windowing: WindowConfig = Field(default_factory=WindowConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    training: TrainingConfig = Field(default_factory=TrainingConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)


def load_config(config_path: Optional[Path | str] = None) -> SystemConfig:
    """Loads configuration from a YAML file or returns default configuration."""
    if config_path and Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}
        return SystemConfig.model_validate(raw_data)
    return SystemConfig()
