"""Unit tests for TemporalWorldModel architecture and multi-task loss."""

import pytest
import torch
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.training.losses import MultiTaskWorldModelLoss


def test_temporal_world_model_forward():
    batch_size = 4
    context_len = 12
    feature_dim = 36
    num_stages = 9

    model = TemporalWorldModel(
        feature_dim=feature_dim,
        d_model=64,
        latent_dim=32,
        num_layers=1,
        num_heads=2,
        num_stages=num_stages,
        context_length=context_len,
        forecast_horizon=6,
    )

    x = torch.randn(batch_size, context_len, feature_dim)
    s_mu, s_log_var, stage_logits, risk = model(x)

    assert s_mu.shape == (batch_size, feature_dim)
    assert s_log_var.shape == (batch_size, feature_dim)
    assert stage_logits.shape == (batch_size, num_stages)
    assert risk.shape == (batch_size,)
    assert torch.all(risk >= 0.0) and torch.all(risk <= 1.0)


def test_multitask_loss_computation():
    batch_size = 4
    feature_dim = 36
    num_stages = 9

    loss_fn = MultiTaskWorldModelLoss()

    pred_mu = torch.randn(batch_size, feature_dim)
    pred_log_var = torch.zeros(batch_size, feature_dim)
    pred_stage_logits = torch.randn(batch_size, num_stages)
    pred_risk = torch.sigmoid(torch.randn(batch_size))

    target_state = torch.randn(batch_size, feature_dim)
    target_stage = torch.randint(0, num_stages, (batch_size,))
    target_risk = torch.randint(0, 2, (batch_size,)).float()

    total_loss, components = loss_fn(
        pred_mu=pred_mu,
        pred_log_var=pred_log_var,
        pred_stage_logits=pred_stage_logits,
        pred_risk_probs=pred_risk,
        target_state=target_state,
        target_stage=target_stage,
        target_risk=target_risk,
    )

    assert total_loss.item() > 0.0
    assert "loss_state_nll" in components
    assert "loss_stage_focal" in components
    assert "loss_risk_bce" in components
