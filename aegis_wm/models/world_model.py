"""TemporalWorldModel: Probabilistic State Transition and Multi-Step Autoregressive Rollout."""

import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encoding for temporal sequences."""

    def __init__(self, d_model: int, max_len: int = 500):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: [batch, seq_len, d_model]"""
        seq_len = x.size(1)
        return x + self.pe[:, :seq_len, :]


class TemporalWorldModel(nn.Module):
    """
    AEGIS-WM Network World Model:
    Learns P(S[t+1] | S[t-m+1], ..., S[t]) through a distributional latent state transition
    model and performs recursive autoregressive K-step rollouts.
    """

    def __init__(
        self,
        feature_dim: int = 36,
        d_model: int = 128,
        latent_dim: int = 64,
        num_layers: int = 2,
        num_heads: int = 4,
        num_stages: int = 9,
        context_length: int = 12,
        forecast_horizon: int = 6,
        dropout: float = 0.1,
        encoder_type: str = "transformer",  # "transformer" or "gru"
        log_var_min: float = -7.0,
        log_var_max: float = 2.0,
    ):
        super().__init__()
        self.feature_dim = feature_dim
        self.d_model = d_model
        self.latent_dim = latent_dim
        self.num_stages = num_stages
        self.context_length = context_length
        self.forecast_horizon = forecast_horizon
        self.encoder_type = encoder_type
        self.log_var_min = log_var_min
        self.log_var_max = log_var_max

        # 1. Feature Projection & Embedding
        self.feature_proj = nn.Linear(feature_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model=d_model, max_len=context_length + forecast_horizon + 10)
        self.layer_norm = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)

        # 2. Temporal Context Encoder
        if encoder_type == "transformer":
            encoder_layer = nn.TransformerEncoderLayer(
                d_model=d_model,
                nhead=num_heads,
                dim_feedforward=d_model * 2,
                dropout=dropout,
                batch_first=True,
                activation="gelu",
            )
            self.temporal_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        else:
            self.temporal_encoder = nn.GRU(
                input_size=d_model,
                hidden_size=d_model,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0.0,
            )

        # 3. Latent State Projection z[t]
        self.to_latent = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, latent_dim),
        )

        # 4. Probabilistic State Transition Model P(z[t+1] | z[t])
        self.transition_net = nn.Sequential(
            nn.Linear(latent_dim, d_model),
            nn.GELU(),
            nn.Linear(d_model, d_model),
            nn.GELU(),
        )
        self.transition_mu = nn.Linear(d_model, latent_dim)
        self.transition_log_var = nn.Linear(d_model, latent_dim)

        # 5. Multi-Task Decoders
        # Next-state reconstruction head: z[t+1] -> S_hat[t+1]
        self.state_decoder_mu = nn.Sequential(
            nn.Linear(latent_dim, d_model),
            nn.GELU(),
            nn.Linear(d_model, feature_dim),
        )
        self.state_decoder_log_var = nn.Sequential(
            nn.Linear(latent_dim, d_model),
            nn.GELU(),
            nn.Linear(d_model, feature_dim),
        )

        # Attack stage prediction head: z[t+1] -> softmax over 9 stages
        self.stage_head = nn.Sequential(
            nn.Linear(latent_dim, d_model // 2),
            nn.GELU(),
            nn.Linear(d_model // 2, num_stages),
        )

        # Infiltration risk head: z[t+1] -> sigmoid risk probability
        self.risk_head = nn.Sequential(
            nn.Linear(latent_dim, d_model // 2),
            nn.GELU(),
            nn.Linear(d_model // 2, 1),
            nn.Sigmoid(),
        )

        # Epistemic uncertainty head
        self.uncertainty_head = nn.Sequential(
            nn.Linear(latent_dim, d_model // 4),
            nn.GELU(),
            nn.Linear(d_model // 4, 1),
            nn.Sigmoid(),
        )

    def encode_context(self, x: torch.Tensor) -> torch.Tensor:
        """
        Encodes observed context window sequence into current latent state z[t].
        x: [batch, seq_len, feature_dim]
        Returns: z[t] of shape [batch, latent_dim]
        """
        h = self.feature_proj(x)
        h = self.pos_encoder(h)
        h = self.layer_norm(h)
        h = self.dropout(h)

        if self.encoder_type == "transformer":
            encoded = self.temporal_encoder(h)
            last_hidden = encoded[:, -1, :]
        else:
            out, _ = self.temporal_encoder(h)
            last_hidden = out[:, -1, :]

        z_t = self.to_latent(last_hidden)
        return z_t

    def step_transition(
        self, z_t: torch.Tensor, sample_stochastic: bool = False
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Computes single-step probabilistic transition P(z[t+1] | z[t]).
        Returns:
            z_next: [batch, latent_dim] (mean or sampled)
            mu: [batch, latent_dim]
            log_var: [batch, latent_dim]
        """
        trans_h = self.transition_net(z_t)
        mu = self.transition_mu(trans_h)
        raw_log_var = self.transition_log_var(trans_h)
        log_var = torch.clamp(raw_log_var, min=self.log_var_min, max=self.log_var_max)

        if sample_stochastic:
            std = torch.exp(0.5 * log_var)
            eps = torch.randn_like(std)
            z_next = mu + eps * std
        else:
            z_next = mu

        return z_next, mu, log_var

    def decode_predictions(
        self, z: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Decodes state z into continuous state, stage logits, risk probability, and uncertainty.
        Returns:
            pred_state_mu: [batch, feature_dim]
            pred_state_log_var: [batch, feature_dim]
            stage_logits: [batch, num_stages]
            risk_prob: [batch]
            uncertainty: [batch]
        """
        state_mu = self.state_decoder_mu(z)
        raw_state_log_var = self.state_decoder_log_var(z)
        state_log_var = torch.clamp(raw_state_log_var, min=self.log_var_min, max=self.log_var_max)

        stage_logits = self.stage_head(z)
        risk_prob = self.risk_head(z).squeeze(-1)
        uncertainty = self.uncertainty_head(z).squeeze(-1)

        return state_mu, state_log_var, stage_logits, risk_prob, uncertainty

    def forward(
        self, x: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Standard 1-step forward pass for training:
        Input x: [batch, context_length, feature_dim]
        Returns:
            pred_state_mu: [batch, feature_dim]
            pred_state_log_var: [batch, feature_dim]
            stage_logits: [batch, num_stages]
            risk_prob: [batch]
        """
        z_t = self.encode_context(x)
        z_next, _, _ = self.step_transition(z_t, sample_stochastic=False)
        state_mu, state_log_var, stage_logits, risk_prob, _ = self.decode_predictions(z_next)
        return state_mu, state_log_var, stage_logits, risk_prob

    def recursive_rollout(
        self,
        context: torch.Tensor,
        horizon: Optional[int] = None,
        sample_stochastic: bool = False,
        monte_carlo_samples: int = 1,
    ) -> Dict[str, torch.Tensor]:
        """
        Executes true autoregressive rollout for K steps:
        1. Encodes observed context [t-m+1..t].
        2. Predicts P(S[t+1]).
        3. Appends predicted state to rolling context, sliding forward.
        4. Predicts P(S[t+2]) ... repeats for K steps.
        If monte_carlo_samples > 1, simulates M distinct trajectories to compute
        trajectory divergence and 95% predictive uncertainty confidence intervals.
        """
        k_steps = horizon or self.forecast_horizon
        batch_size = context.size(0)

        if monte_carlo_samples > 1:
            # Multi-trajectory Monte Carlo Rollout
            all_states = []
            all_risks = []
            all_stages = []

            for _ in range(monte_carlo_samples):
                traj_res = self._single_rollout(context, k_steps, sample_stochastic=True)
                all_states.append(traj_res["states"].unsqueeze(0))
                all_risks.append(traj_res["risks"].unsqueeze(0))
                all_stages.append(traj_res["stage_logits"].unsqueeze(0))

            stacked_states = torch.cat(all_states, dim=0)  # [M, batch, K, D]
            stacked_risks = torch.cat(all_risks, dim=0)    # [M, batch, K]
            stacked_stages = torch.cat(all_stages, dim=0)  # [M, batch, K, num_stages]

            mean_states = torch.mean(stacked_states, dim=0)
            state_var = torch.var(stacked_states, dim=0)
            mean_risks = torch.mean(stacked_risks, dim=0)
            risk_std = torch.std(stacked_risks, dim=0)

            # 95% CI: [mean - 1.96*std, mean + 1.96*std]
            risk_lower = torch.clamp(mean_risks - 1.96 * risk_std, 0.0, 1.0)
            risk_upper = torch.clamp(mean_risks + 1.96 * risk_std, 0.0, 1.0)

            mean_stage_logits = torch.mean(stacked_stages, dim=0)
            stage_probs = F.softmax(mean_stage_logits, dim=-1)

            return {
                "states": mean_states,
                "state_variance": state_var,
                "risks": mean_risks,
                "risk_lower": risk_lower,
                "risk_upper": risk_upper,
                "uncertainty_spread": risk_upper - risk_lower,
                "stage_logits": mean_stage_logits,
                "stage_probs": stage_probs,
            }
        else:
            return self._single_rollout(context, k_steps, sample_stochastic=sample_stochastic)

    def _single_rollout(
        self, context: torch.Tensor, k_steps: int, sample_stochastic: bool = False
    ) -> Dict[str, torch.Tensor]:
        """Single trajectory recursive rollout."""
        current_context = context.clone()
        rolled_states = []
        rolled_state_vars = []
        rolled_risks = []
        rolled_stage_logits = []
        rolled_uncertainties = []

        for step in range(k_steps):
            z_t = self.encode_context(current_context)
            z_next, _, log_var = self.step_transition(z_t, sample_stochastic=sample_stochastic)
            s_mu, s_log_var, stg_logits, risk, uncert = self.decode_predictions(z_next)

            rolled_states.append(s_mu.unsqueeze(1))
            rolled_state_vars.append(torch.exp(s_log_var).unsqueeze(1))
            rolled_risks.append(risk.unsqueeze(1))
            rolled_stage_logits.append(stg_logits.unsqueeze(1))
            rolled_uncertainties.append(uncert.unsqueeze(1))

            # Autoregressive slide: drop oldest window, append predicted state
            current_context = torch.cat([current_context[:, 1:, :], s_mu.unsqueeze(1)], dim=1)

        out_states = torch.cat(rolled_states, dim=1)         # [batch, K, D]
        out_state_vars = torch.cat(rolled_state_vars, dim=1) # [batch, K, D]
        out_risks = torch.cat(rolled_risks, dim=1)           # [batch, K]
        out_stage_logits = torch.cat(rolled_stage_logits, dim=1) # [batch, K, num_stages]
        out_uncert = torch.cat(rolled_uncertainties, dim=1)  # [batch, K]

        # Epistemic bounds from internal uncertainty head
        half_uncert = 0.5 * out_uncert
        risk_lower = torch.clamp(out_risks - half_uncert, 0.0, 1.0)
        risk_upper = torch.clamp(out_risks + half_uncert, 0.0, 1.0)

        stage_probs = F.softmax(out_stage_logits, dim=-1)

        return {
            "states": out_states,
            "state_variance": out_state_vars,
            "risks": out_risks,
            "risk_lower": risk_lower,
            "risk_upper": risk_upper,
            "uncertainty_spread": risk_upper - risk_lower,
            "stage_logits": out_stage_logits,
            "stage_probs": stage_probs,
        }
