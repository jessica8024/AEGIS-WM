"""Recursive multi-step forecast rollout coordinator generating typed ForecastTrajectory objects."""

import math
from typing import Dict, List, Optional
import numpy as np
import torch
import torch.nn.functional as F
from aegis_wm.common.crypto import compute_sha256
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.schemas.forecast import ForecastPoint, ForecastTrajectory
from aegis_wm.schemas.labels import AttackStageEnum
from aegis_wm.schemas.state import NetworkWindowState
from aegis_wm.state.preprocessor import StateFeatureScaler


class RecursiveForecaster:
    """Executes multi-step forward simulation using a trained TemporalWorldModel."""

    def __init__(
        self,
        model: TemporalWorldModel,
        scaler: StateFeatureScaler,
        forecast_horizon: int = 6,
        window_duration_seconds: float = 5.0,
    ):
        self.model = model
        self.scaler = scaler
        self.forecast_horizon = forecast_horizon
        self.window_duration = window_duration_seconds

    def forecast(
        self,
        context_windows: List[NetworkWindowState],
        analysis_id: str = "analysis_001",
        rollout_mode: str = "deterministic",  # "deterministic" or "monte_carlo"
        mc_trajectories: int = 20,
    ) -> ForecastTrajectory:
        """
        Takes m observed context windows, scales features, runs autoregressive rollout
        for K steps, inverse-transforms continuous predictions to physical units,
        and constructs a ForecastTrajectory.
        """
        self.model.eval()
        device = next(self.model.parameters()).device

        # Extract features from context windows
        ctx_features = [w.feature_vector for w in context_windows]
        base_win = context_windows[-1]
        base_window_idx = base_win.window_index
        base_time = base_win.end_timestamp

        # Scale features using training scaler
        x_norm = self.scaler.transform(np.array([ctx_features], dtype=np.float32))
        x_tensor = torch.tensor(x_norm, dtype=torch.float32, device=device)

        use_mc = rollout_mode == "monte_carlo"
        mc_samples = mc_trajectories if use_mc else 1

        with torch.no_grad():
            rollout_res = self.model.recursive_rollout(
                x_tensor,
                horizon=self.forecast_horizon,
                sample_stochastic=use_mc,
                monte_carlo_samples=mc_samples,
            )

        # Extract predicted tensors
        pred_states_norm = rollout_res["states"][0].cpu().numpy()     # [K, D]
        pred_risks = rollout_res["risks"][0].cpu().numpy()               # [K]
        risk_lowers = rollout_res["risk_lower"][0].cpu().numpy()         # [K]
        risk_uppers = rollout_res["risk_upper"][0].cpu().numpy()         # [K]
        stage_probs_tensor = rollout_res["stage_probs"][0].cpu().numpy() # [K, 9]
        state_vars_norm = rollout_res["state_variance"][0].cpu().numpy() # [K, D]

        # Inverse transform state vectors back to real units
        pred_states_orig = self.scaler.inverse_transform(pred_states_norm)

        points: List[ForecastPoint] = []
        prev_risk = 0.0

        for k in range(self.forecast_horizon):
            step_idx = k + 1
            target_time = base_time + step_idx * self.window_duration

            # Probability distribution across all 9 stages
            stg_prob_dict = {
                AttackStageEnum.get_display_name(s_idx): float(stage_probs_tensor[k, s_idx])
                for s_idx in range(9)
            }

            top_stage_idx = int(np.argmax(stage_probs_tensor[k]))
            top_stage = AttackStageEnum(top_stage_idx)

            # Predictive entropy
            entropy = 0.0
            for p in stage_probs_tensor[k]:
                if p > 1e-6:
                    entropy -= p * math.log2(p)
            entropy /= math.log2(9)  # normalized [0, 1]

            cur_risk = float(pred_risks[k])
            risk_vel = cur_risk - prev_risk
            prev_risk = cur_risk

            fp = ForecastPoint(
                horizon_step=step_idx,
                target_timestamp=target_time,
                predicted_state=pred_states_orig[k].tolist(),
                state_variance=state_vars_norm[k].tolist(),
                infiltration_probability=cur_risk,
                uncertainty_lower=float(risk_lowers[k]),
                uncertainty_upper=float(risk_uppers[k]),
                predictive_entropy=float(entropy),
                predicted_stage=top_stage,
                stage_probabilities=stg_prob_dict,
                risk_velocity=float(risk_vel),
            )
            points.append(fp)

        max_risk = max(p.infiltration_probability for p in points)
        peak_stage = max(points, key=lambda p: p.infiltration_probability).predicted_stage

        forecast_id = compute_sha256(f"{analysis_id}:{base_window_idx}:{base_time}")

        return ForecastTrajectory(
            forecast_id=forecast_id,
            analysis_id=analysis_id,
            base_window_index=base_window_idx,
            base_timestamp=base_time,
            horizon_count=self.forecast_horizon,
            rollout_mode=rollout_mode,
            points=points,
            max_risk_in_horizon=max_risk,
            peak_stage_predicted=peak_stage,
        )
