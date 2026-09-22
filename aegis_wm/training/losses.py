"""Loss functions for Temporal World Model: Gaussian NLL, Focal Loss, and Rollout Consistency."""

import math
from typing import Dict, Optional, Tuple
import torch
import torch.nn as nn
import torch.nn.functional as F


class GaussianNLLLoss(nn.Module):
    """
    Gaussian Negative Log-Likelihood loss for continuous state vectors:
    NLL = 0.5 * sum( log(sigma^2) + (y - mu)^2 / sigma^2 )
    Log-variance is clamped to [log_var_min, log_var_max] to guarantee numerical stability.
    """

    def __init__(self, log_var_min: float = -7.0, log_var_max: float = 2.0):
        super().__init__()
        self.log_var_min = log_var_min
        self.log_var_max = log_var_max

    def forward(
        self, mu: torch.Tensor, log_var: torch.Tensor, target: torch.Tensor
    ) -> torch.Tensor:
        clamped_log_var = torch.clamp(log_var, min=self.log_var_min, max=self.log_var_max)
        var = torch.exp(clamped_log_var)
        nll = 0.5 * (clamped_log_var + ((target - mu) ** 2) / (var + 1e-6))
        return torch.mean(torch.sum(nll, dim=-1))


class FocalStageLoss(nn.Module):
    """
    Focal Loss for multi-class attack stage classification:
    FL(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t)
    Addresses severe imbalance where BENIGN vastly outnumbers specific attack stages.
    """

    def __init__(
        self,
        gamma: float = 2.0,
        weights: Optional[torch.Tensor] = None,
        reduction: str = "mean",
    ):
        super().__init__()
        self.gamma = gamma
        self.weights = weights
        self.reduction = reduction

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        logits: [N, num_classes]
        targets: [N] (long class indices)
        """
        ce_loss = F.cross_entropy(logits, targets, weight=self.weights, reduction="none")
        p_t = torch.exp(-ce_loss)
        focal_loss = ((1.0 - p_t) ** self.gamma) * ce_loss

        if self.reduction == "mean":
            return torch.mean(focal_loss)
        elif self.reduction == "sum":
            return torch.sum(focal_loss)
        return focal_loss


class MultiTaskWorldModelLoss(nn.Module):
    """
    Combines state transition NLL, stage classification focal loss,
    horizon infiltration BCE loss, and rollout consistency loss:
    L = lambda_state * L_nll + lambda_stage * L_focal + lambda_risk * L_bce + lambda_consistency * L_consist
    """

    def __init__(
        self,
        lambda_state: float = 1.0,
        lambda_stage: float = 1.0,
        lambda_risk: float = 1.0,
        lambda_consistency: float = 0.5,
        stage_weights: Optional[torch.Tensor] = None,
    ):
        super().__init__()
        self.lambda_state = lambda_state
        self.lambda_stage = lambda_stage
        self.lambda_risk = lambda_risk
        self.lambda_consistency = lambda_consistency

        self.state_loss_fn = GaussianNLLLoss()
        self.stage_loss_fn = FocalStageLoss(gamma=2.0, weights=stage_weights)
        self.risk_loss_fn = nn.BCELoss()

    def forward(
        self,
        pred_mu: torch.Tensor,
        pred_log_var: torch.Tensor,
        pred_stage_logits: torch.Tensor,
        pred_risk_probs: torch.Tensor,
        target_state: torch.Tensor,
        target_stage: torch.Tensor,
        target_risk: torch.Tensor,
        rollout_states: Optional[torch.Tensor] = None,
        target_future_states: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        """Computes total multi-task loss and returns loss components dictionary."""
        # 1. State transition NLL
        l_state = self.state_loss_fn(pred_mu, pred_log_var, target_state)

        # 2. Attack stage focal loss
        l_stage = self.stage_loss_fn(pred_stage_logits, target_stage)

        # 3. Infiltration risk BCE loss
        l_risk = self.risk_loss_fn(pred_risk_probs, target_risk)

        # 4. Multi-step rollout consistency loss (if rolling forward during scheduled sampling)
        l_consist = torch.tensor(0.0, device=pred_mu.device)
        if rollout_states is not None and target_future_states is not None:
            l_consist = F.mse_loss(rollout_states, target_future_states)

        total_loss = (
            self.lambda_state * l_state
            + self.lambda_stage * l_stage
            + self.lambda_risk * l_risk
            + self.lambda_consistency * l_consist
        )

        loss_dict = {
            "loss_total": float(total_loss.item()),
            "loss_state_nll": float(l_state.item()),
            "loss_stage_focal": float(l_stage.item()),
            "loss_risk_bce": float(l_risk.item()),
            "loss_rollout_consistency": float(l_consist.item()),
        }

        return total_loss, loss_dict
