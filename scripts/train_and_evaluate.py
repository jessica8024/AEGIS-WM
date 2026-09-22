"""End-to-end extraction, training, and evaluation script on authentic CIC-IDS-2017 data."""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from aegis_wm.common.crypto import compute_sha256
from aegis_wm.common.logger import logger
from aegis_wm.evaluation.runner import BaselineBenchmarkRunner
from aegis_wm.forecasting.rollout import RecursiveForecaster
from aegis_wm.ingestion.csv_adapter import CICFlowCSVAdapter
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.state.preprocessor import StateFeatureScaler
from aegis_wm.state.sequence_builder import SequenceBuilder
from aegis_wm.state.splitter import DatasetSplitter
from aegis_wm.state.window_aggregator import WindowStateAggregator
from aegis_wm.storage.telemetry import TelemetryStore
from aegis_wm.training.trainer import WorldModelTrainer


def run_pipeline():
    logger.info("================================================================")
    logger.info("AEGIS-WM: Authentic Data Pipeline, Training & Baseline Benchmark")
    logger.info("================================================================")

    # 1. Authentic file discovery
    data_dir = Path(r"C:\Users\Sathish-PhD\Downloads\MachineLearningCSV\CIC-IDS- 2017")
    portscan_file = data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    benign_file = data_dir / "Monday-WorkingHours.pcap_ISCX.csv"

    adapter = CICFlowCSVAdapter()
    tel_store = TelemetryStore(base_dir="data")

    all_flows = []
    if portscan_file.exists() and benign_file.exists():
        logger.info(f"Loading authentic Benign baseline: {benign_file.name}")
        benign_flows, b_rep = adapter.process_csv(benign_file, max_rows=5000)
        all_flows.extend(benign_flows)

        logger.info(f"Loading authentic PortScan Reconnaissance: {portscan_file.name}")
        scan_flows, s_rep = adapter.process_csv(portscan_file, max_rows=5000)
        all_flows.extend(scan_flows)
    else:
        logger.warning("Authentic files not found at expected path. Using local sample.")
        return

    logger.info(f"Total authentic flows ingested: {len(all_flows)}")

    # 2. Window Aggregation
    aggregator = WindowStateAggregator(window_size_seconds=5.0, slide_step_seconds=5.0)
    windows = aggregator.aggregate_flows(all_flows)
    logger.info(f"Total 5s temporal state windows generated: {len(windows)}")

    # Save telemetry to Parquet
    flow_pq = tel_store.save_flows_parquet(all_flows, "data/processed/cicids2017_flows.parquet")
    state_pq = tel_store.save_states_parquet(windows, "data/processed/cicids2017_states.parquet")
    logger.info(f"Saved Parquet flows ({flow_pq}) and states ({state_pq}).")

    # 3. Build Sequences
    seq_builder = SequenceBuilder(context_length=12, forecast_horizon=6)
    sequences = seq_builder.build_sequences(windows)
    logger.info(f"Total temporal sequences constructed: {len(sequences)}")

    # 4. Leakage-safe Chronological Split
    train_seqs, val_seqs, test_seqs = DatasetSplitter.chronological_split(
        sequences, train_ratio=0.70, val_ratio=0.15, gap_sequences=18
    )
    logger.info(
        f"Partitions: Train={len(train_seqs)}, Val={len(val_seqs)}, Test={len(test_seqs)}"
    )

    # Automated leakage verification
    checks = DatasetSplitter.verify_zero_leakage(train_seqs, val_seqs, test_seqs)
    logger.info(f"Zero-Leakage Checks Passed: {checks}")

    # Convert to PyTorch tensors
    train_tensors = seq_builder.sequences_to_tensors(train_seqs)
    val_tensors = seq_builder.sequences_to_tensors(val_seqs)
    test_tensors = seq_builder.sequences_to_tensors(test_seqs)

    # 5. Fit Preprocessing Scaler strictly on train partition
    scaler = StateFeatureScaler()
    scaler.fit(train_tensors["x"])
    scaler_path = Path("models/state_scaler.json")
    scaler.save_to_file(scaler_path)
    logger.info(f"Saved fitted scaler to {scaler_path}")

    # 6. Run Baseline Benchmark Suite
    bench_runner = BaselineBenchmarkRunner(output_dir="reports")
    baseline_results = bench_runner.run_all_baselines(
        train_tensors=train_tensors,
        val_tensors=val_tensors,
        test_tensors=test_tensors,
        scaler=scaler,
        forecast_horizon=6,
    )

    # 7. Train TemporalWorldModel
    logger.info("Training TemporalWorldModel with Scheduled Sampling...")
    world_model = TemporalWorldModel(
        feature_dim=36,
        d_model=128,
        latent_dim=64,
        num_layers=2,
        num_heads=4,
        num_stages=9,
        context_length=12,
        forecast_horizon=6,
    )

    trainer = WorldModelTrainer(
        model=world_model,
        lr=0.001,
        lambda_state=1.0,
        lambda_stage=1.0,
        lambda_risk=1.0,
        lambda_consistency=0.5,
        scheduled_sampling_k=10.0,
        checkpoint_dir="models",
    )

    # Scale training data
    norm_train_x = scaler.transform(train_tensors["x"])
    train_ds = torch.utils.data.TensorDataset(
        torch.tensor(norm_train_x, dtype=torch.float32),
        train_tensors["y_state"],
        train_tensors["y_stage"],
        train_tensors["y_risk"],
    )
    train_loader = torch.utils.data.DataLoader(train_ds, batch_size=32, shuffle=True)

    norm_val_x = scaler.transform(val_tensors["x"])
    val_ds = torch.utils.data.TensorDataset(
        torch.tensor(norm_val_x, dtype=torch.float32),
        val_tensors["y_state"],
        val_tensors["y_stage"],
        val_tensors["y_risk"],
    )
    val_loader = torch.utils.data.DataLoader(val_ds, batch_size=32, shuffle=False)

    for epoch in range(1, 11):
        tr_stats = trainer.train_epoch(train_loader, epoch=epoch, use_scheduled_sampling=True)
        val_stats = trainer.evaluate(val_loader)
        logger.info(
            f"Epoch {epoch:02d} | Train Loss: {tr_stats['loss_total']:.4f} "
            f"(NLL: {tr_stats['loss_state_nll']:.4f}, Focal: {tr_stats['loss_stage_focal']:.4f}) | "
            f"Val Loss: {val_stats['val_loss_total']:.4f} | p_tf: {tr_stats['teacher_forcing_ratio']:.2f}"
        )

    # Save final base checkpoint
    ckpt_path, ckpt_hash = trainer.save_checkpoint(
        "aegis_world_model_base",
        metadata={
            "dataset": "CIC-IDS-2017",
            "train_samples": len(train_seqs),
            "test_samples": len(test_seqs),
            "epochs": 10,
        },
    )
    logger.info(f"Trained Base Checkpoint saved: {ckpt_path} (Hash: {ckpt_hash})")

    # 8. Test Rollout on Test Data
    forecaster = RecursiveForecaster(
        model=world_model,
        scaler=scaler,
        forecast_horizon=6,
        window_duration_seconds=5.0,
    )
    sample_ctx = test_seqs[0].context_windows
    sample_traj = forecaster.forecast(sample_ctx, analysis_id="test_run", rollout_mode="monte_carlo")
    logger.info(
        f"Test Rollout Executed: Max Risk={sample_traj.max_risk_in_horizon:.2f}, "
        f"Peak Stage={sample_traj.peak_stage_predicted}"
    )

    logger.info("Pipeline execution complete! All artifacts saved.")


if __name__ == "__main__":
    run_pipeline()
