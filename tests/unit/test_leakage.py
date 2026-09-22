"""Unit tests for data leakage prevention and split verification."""

import pytest
import torch
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.state.preprocessor import StateFeatureScaler
from aegis_wm.state.sequence_builder import SequenceBuilder
from aegis_wm.state.splitter import DatasetSplitter, LeakageVerificationError
from aegis_wm.state.window_aggregator import WindowStateAggregator


def make_test_flow(start_t: float) -> BidirectionalFlow:
    prov = ProvenanceMetadata(
        source_file_hash="0" * 64,
        extraction_config_hash="0" * 64,
        start_timestamp=start_t,
        end_timestamp=start_t + 2.0,
        provenance_reference="leakage_fixture",
    )
    return BidirectionalFlow(
        flow_id=f"f_{start_t}",
        provenance=prov,
        src_ip_pseudo="host_1",
        dst_ip_pseudo="host_2",
        src_port=50000,
        dst_port=80,
        protocol=6,
        start_timestamp=start_t,
        end_timestamp=start_t + 2.0,
        duration=2.0,
        fwd_packets=5,
        bwd_packets=5,
        fwd_bytes=500,
        bwd_bytes=500,
        packets_per_sec=5.0,
        bytes_per_sec=500.0,
    )


def test_leakage_safe_chronological_splits():
    # 120 windows of 5 seconds each
    flows = [make_test_flow(100.0 + i * 5.0) for i in range(120)]
    aggregator = WindowStateAggregator(window_size_seconds=5.0, slide_step_seconds=5.0)
    windows = aggregator.aggregate_flows(flows)

    seq_builder = SequenceBuilder(context_length=8, forecast_horizon=4)
    sequences = seq_builder.build_sequences(windows)

    train_seqs, val_seqs, test_seqs = DatasetSplitter.chronological_split(
        sequences, train_ratio=0.6, val_ratio=0.2, gap_sequences=12
    )

    assert len(train_seqs) > 0
    assert len(val_seqs) > 0
    assert len(test_seqs) > 0

    # Verify zero leakage checks pass
    checks = DatasetSplitter.verify_zero_leakage(train_seqs, val_seqs, test_seqs)
    assert checks["no_train_val_overlap"] is True
    assert checks["no_val_test_overlap"] is True
    assert checks["no_sequence_id_leakage"] is True
    assert checks["temporal_causality_valid"] is True


def test_scaler_fitted_strictly_on_train():
    train_x = torch.randn(20, 12, 36) * 10.0 + 5.0
    val_x = torch.randn(5, 12, 36) * 50.0 - 20.0

    scaler = StateFeatureScaler()
    scaler.fit(train_x)

    norm_train = scaler.transform(train_x)
    norm_val = scaler.transform(val_x)

    # Train mean should be close to 0
    assert torch.abs(torch.mean(norm_train)).item() < 0.1
    # Scaler mean must match train mean, not affected by val
    assert scaler.fitted is True
    assert scaler.mean is not None
    assert len(scaler.mean) == 36
