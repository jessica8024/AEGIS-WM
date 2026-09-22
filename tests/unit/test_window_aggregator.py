"""Unit tests for window state aggregation and sequence building."""

import pytest
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.schemas.labels import AttackStageEnum
from aegis_wm.state.sequence_builder import SequenceBuilder
from aegis_wm.state.window_aggregator import FEATURE_NAMES, WindowStateAggregator


def make_flow(start_t: float, dur: float, dport: int = 80, label: str = "BENIGN") -> BidirectionalFlow:
    prov = ProvenanceMetadata(
        source_file_hash="0" * 64,
        extraction_config_hash="0" * 64,
        start_timestamp=start_t,
        end_timestamp=start_t + dur,
        provenance_reference="test",
    )
    return BidirectionalFlow(
        flow_id=f"f_{start_t}_{dport}",
        provenance=prov,
        src_ip_pseudo="host_1",
        dst_ip_pseudo="host_2",
        src_port=50000,
        dst_port=dport,
        protocol=6,
        start_timestamp=start_t,
        end_timestamp=start_t + dur,
        duration=dur,
        fwd_packets=5,
        bwd_packets=5,
        fwd_bytes=500,
        bwd_bytes=1000,
        packets_per_sec=10.0,
        bytes_per_sec=1500.0,
        source_label=label,
    )


def test_window_aggregator_features():
    flows = [
        make_flow(100.0, 2.0, dport=80),
        make_flow(102.0, 1.0, dport=443),
        make_flow(106.0, 3.0, dport=22, label="PortScan"),
        make_flow(111.0, 2.0, dport=8080),
    ]

    aggregator = WindowStateAggregator(window_size_seconds=5.0, slide_step_seconds=5.0)
    windows = aggregator.aggregate_flows(flows)

    assert len(windows) >= 3
    # Check feature vector dimension is exactly 36
    for w in windows:
        assert len(w.feature_vector) == 36
        assert len(w.feature_names) == 36

    # Window 2 (105s to 110s) contains the PortScan flow
    assert windows[1].ground_truth_stage == AttackStageEnum.RECONNAISSANCE
    assert windows[1].is_compromised is True


def test_sequence_builder_shapes():
    aggregator = WindowStateAggregator(window_size_seconds=5.0, slide_step_seconds=5.0)
    flows = [make_flow(100.0 + i * 5.0, 2.0) for i in range(60)]
    windows = aggregator.aggregate_flows(flows)

    seq_builder = SequenceBuilder(context_length=12, forecast_horizon=6)
    sequences = seq_builder.build_sequences(windows)

    assert len(sequences) > 0
    tensors = seq_builder.sequences_to_tensors(sequences)

    assert tensors["x"].shape == (len(sequences), 12, 36)
    assert tensors["y_state"].shape == (len(sequences), 6, 36)
    assert tensors["y_stage"].shape == (len(sequences), 6)
    assert tensors["y_risk"].shape == (len(sequences), 6)
