"""Training loop with scheduled sampling, multi-task loss, and safetensors checkpointing."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
from safetensors.torch import load_file, save_file
from torch.utils.data import DataLoader, TensorDataset
from aegis_wm.common.crypto import compute_sha256
from aegis_wm.common.logger import logger
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.training.losses import MultiTaskWorldModelLoss


class WorldModelTrainer:
    """Trains TemporalWorldModel with scheduled sampling and multi-task loss."""

    def __init__(
        self,
        model: TemporalWorldModel,
        lr: float = 0.001,
        weight_decay: float = 1e-4,
        lambda_state: float = 1.0,
        lambda_stage: float = 1.0,
        lambda_risk: float = 1.0,
        lambda_consistency: float = 0.5,
        scheduled_sampling_k: float = 10.0,
        device: Optional[str] = None,
        checkpoint_dir: Path | str = "models",
    ):
        self.device = torch.device(
            device if device and device != "auto" else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        self.model = model.to(self.device)
        self.scheduled_sampling_k = scheduled_sampling_k
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        self.optimizer = torch.optim.AdamW(
            self.model.parameters(), lr=lr, weight_decay=weight_decay
        )
        self.loss_fn = MultiTaskWorldModelLoss(
            lambda_state=lambda_state,
            lambda_stage=lambda_stage,
            lambda_risk=lambda_risk,
            lambda_consistency=lambda_consistency,
        )

        logger.info(f"Initialized WorldModelTrainer on device: {self.device}")

    def train_epoch(
        self,
        loader: DataLoader,
        epoch: int,
        use_scheduled_sampling: bool = True,
    ) -> Dict[str, float]:
        """Runs one training epoch."""
        self.model.train()
        total_loss = 0.0
        nll_total = 0.0
        focal_total = 0.0
        bce_total = 0.0
        consist_total = 0.0
        num_batches = 0

        # Scheduled sampling probability: p_tf decays as training progresses
        # p_tf = k / (k + exp(epoch / k))
        p_teacher_forcing = (
            self.scheduled_sampling_k / (self.scheduled_sampling_k + np.exp(epoch / self.scheduled_sampling_k))
            if use_scheduled_sampling
            else 1.0
        )

        for batch_x, batch_y_state, batch_y_stage, batch_y_risk in loader:
            batch_x = batch_x.to(self.device)
            batch_y_state = batch_y_state.to(self.device)
            batch_y_stage = batch_y_stage.to(self.device)
            batch_y_risk = batch_y_risk.to(self.device)

            self.optimizer.zero_grad()

            # 1-step prediction targets
            target_s1 = batch_y_state[:, 0, :]
            target_stg1 = batch_y_stage[:, 0]
            target_risk1 = batch_y_risk[:, 0]

            # Forward pass
            pred_mu, pred_log_var, pred_stage_logits, pred_risk = self.model(batch_x)

            # Scheduled sampling multi-step rollout consistency
            rollout_states = None
            if np.random.rand() > p_teacher_forcing and self.model.forecast_horizon > 1:
                # Perform 2-step rollout and compute consistency with ground truth
                rollout_res = self.model._single_rollout(batch_x, k_steps=2, sample_stochastic=False)
                rollout_states = rollout_res["states"][:, :2, :]
                target_fut2 = batch_y_state[:, :2, :]
            else:
                target_fut2 = None

            loss, loss_components = self.loss_fn(
                pred_mu=pred_mu,
                pred_log_var=pred_log_var,
                pred_stage_logits=pred_stage_logits,
                pred_risk_probs=pred_risk,
                target_state=target_s1,
                target_stage=target_stg1,
                target_risk=target_risk1,
                rollout_states=rollout_states,
                target_future_states=target_fut2,
            )

            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()

            total_loss += loss.item()
            nll_total += loss_components["loss_state_nll"]
            focal_total += loss_components["loss_stage_focal"]
            bce_total += loss_components["loss_risk_bce"]
            consist_total += loss_components["loss_rollout_consistency"]
            num_batches += 1

        return {
            "epoch": epoch,
            "teacher_forcing_ratio": float(p_teacher_forcing),
            "loss_total": total_loss / max(1, num_batches),
            "loss_state_nll": nll_total / max(1, num_batches),
            "loss_stage_focal": focal_total / max(1, num_batches),
            "loss_risk_bce": bce_total / max(1, num_batches),
            "loss_consistency": consist_total / max(1, num_batches),
        }

    def evaluate(self, loader: DataLoader) -> Dict[str, float]:
        """Evaluates model on validation data."""
        self.model.eval()
        total_loss = 0.0
        nll_total = 0.0
        num_batches = 0

        with torch.no_grad():
            for batch_x, batch_y_state, batch_y_stage, batch_y_risk in loader:
                batch_x = batch_x.to(self.device)
                batch_y_state = batch_y_state.to(self.device)
                batch_y_stage = batch_y_stage.to(self.device)
                batch_y_risk = batch_y_risk.to(self.device)

                pred_mu, pred_log_var, pred_stage_logits, pred_risk = self.model(batch_x)

                loss, loss_comp = self.loss_fn(
                    pred_mu=pred_mu,
                    pred_log_var=pred_log_var,
                    pred_stage_logits=pred_stage_logits,
                    pred_risk_probs=pred_risk,
                    target_state=batch_y_state[:, 0, :],
                    target_stage=batch_y_stage[:, 0],
                    target_risk=batch_y_risk[:, 0],
                )

                total_loss += loss.item()
                nll_total += loss_comp["loss_state_nll"]
                num_batches += 1

        return {
            "val_loss_total": total_loss / max(1, num_batches),
            "val_loss_nll": nll_total / max(1, num_batches),
        }

    def save_checkpoint(
        self,
        checkpoint_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Path, str]:
        """
        Saves model weights safely using SafeTensors format (no unsafe pickle).
        Returns: (file_path, sha256_hash).
        """
        out_path = self.checkpoint_dir / f"{checkpoint_name}.safetensors"
        meta_path = self.checkpoint_dir / f"{checkpoint_name}_meta.json"

        state_dict = {k: v.cpu() for k, v in self.model.state_dict().items()}
        save_file(state_dict, str(out_path))

        file_hash = compute_sha256(out_path)

        meta_info = metadata or {}
        meta_info["checkpoint_sha256"] = file_hash
        meta_info["architecture"] = "TemporalWorldModel"
        meta_info["feature_dim"] = self.model.feature_dim
        meta_info["latent_dim"] = self.model.latent_dim
        meta_info["context_length"] = self.model.context_length
        meta_info["forecast_horizon"] = self.model.forecast_horizon

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_info, f, indent=2)

        logger.info(f"Model saved to {out_path} (SHA-256: {file_hash[:16]}...)")
        return out_path, file_hash

    def load_checkpoint(self, checkpoint_path: Path | str) -> str:
        """Loads model weights from a SafeTensors checkpoint."""
        p = Path(checkpoint_path)
        if not p.exists():
            raise FileNotFoundError(f"Checkpoint not found: {p}")

        state_dict = load_file(str(p))
        self.model.load_state_dict(state_dict)
        self.model.to(self.device)
        file_hash = compute_sha256(p)
        logger.info(f"Loaded checkpoint {p.name} on {self.device} (SHA-256: {file_hash[:16]}...)")
        return file_hash
