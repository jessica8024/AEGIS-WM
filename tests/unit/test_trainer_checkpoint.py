"""Unit tests for training loop and safetensors checkpointing."""

import tempfile
from pathlib import Path
import pytest
import torch
from torch.utils.data import DataLoader, TensorDataset
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.training.trainer import WorldModelTrainer


def test_trainer_epoch_and_safetensors_checkpoint():
    with tempfile.TemporaryDirectory() as tmpdir:
        model = TemporalWorldModel(
            feature_dim=36,
            d_model=32,
            latent_dim=16,
            num_layers=1,
            num_heads=2,
            context_length=8,
            forecast_horizon=4,
        )

        trainer = WorldModelTrainer(
            model=model,
            lr=0.01,
            checkpoint_dir=tmpdir,
            device="cpu",
        )

        # Create dummy batch
        batch_x = torch.randn(16, 8, 36)
        batch_y_state = torch.randn(16, 4, 36)
        batch_y_stage = torch.randint(0, 9, (16, 4))
        batch_y_risk = torch.randint(0, 2, (16, 4)).float()

        dataset = TensorDataset(batch_x, batch_y_state, batch_y_stage, batch_y_risk)
        loader = DataLoader(dataset, batch_size=8)

        # Train 1 epoch
        metrics = trainer.train_epoch(loader, epoch=1, use_scheduled_sampling=True)
        assert "loss_total" in metrics
        assert metrics["loss_total"] > 0.0

        # Save checkpoint
        ckpt_path, ckpt_hash = trainer.save_checkpoint("test_model", metadata={"test": True})
        assert ckpt_path.exists()
        assert len(ckpt_hash) == 64

        # Load checkpoint into fresh model
        fresh_model = TemporalWorldModel(
            feature_dim=36,
            d_model=32,
            latent_dim=16,
            num_layers=1,
            num_heads=2,
            context_length=8,
            forecast_horizon=4,
        )
        fresh_trainer = WorldModelTrainer(model=fresh_model, checkpoint_dir=tmpdir, device="cpu")
        loaded_hash = fresh_trainer.load_checkpoint(ckpt_path)
        assert loaded_hash == ckpt_hash
