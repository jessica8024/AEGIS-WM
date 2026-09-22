"""Unit tests for canonical Pydantic schemas."""

import pytest
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.schemas.labels import AttackStageEnum, StageLabel, EvidenceConfidenceEnum
from aegis_wm.schemas.state import NetworkWindowState
from aegis_wm.schemas.forecast import ForecastPoint, ForecastTrajectory
from aegis_wm.schemas.explanation import ExplanationResult, FeatureAttribution


def test_provenance_metadata_instantiation():
    meta = ProvenanceMetadata(
        source_file_hash="a" * 64,
        extraction_config_hash="b" * 64,
        start_timestamp=1700000000.0,
        end_timestamp=1700000005.0,
        provenance_reference="capture.pcap",
    )
    assert meta.schema_version == "1.0.0"
    assert meta.source_file_hash == "a" * 64


def test_bidirectional_flow_validation():
    meta = ProvenanceMetadata(
        source_file_hash="a" * 64,
        extraction_config_hash="b" * 64,
        start_timestamp=1700000000.0,
        end_timestamp=1700000005.0,
        provenance_reference="test.pcap",
    )
    flow = BidirectionalFlow(
        flow_id="f123",
        provenance=meta,
        src_ip_pseudo="host_1234567890ab",
        dst_ip_pseudo="host_cdef12345678",
        src_port=49152,
        dst_port=443,
        protocol=6,
        start_timestamp=1700000000.0,
        end_timestamp=1700000005.0,
        duration=5.0,
        fwd_packets=10,
        bwd_packets=8,
        fwd_bytes=1500,
        bwd_bytes=4200,
        packets_per_sec=3.6,
        bytes_per_sec=1140.0,
    )
    assert flow.protocol == 6
    assert flow.fwd_packets == 10
    assert flow.fwd_bwd_pkt_ratio == 1.0  # default value check


def test_attack_stage_enum():
    assert AttackStageEnum.BENIGN == 0
    assert AttackStageEnum.RECONNAISSANCE == 1
    assert AttackStageEnum.INITIAL_ACCESS == 2
    assert AttackStageEnum.COMMAND_AND_CONTROL == 5
    assert AttackStageEnum.get_display_name(5) == "Command & Control"


def test_forecast_trajectory():
    fp = ForecastPoint(
        horizon_step=1,
        target_timestamp=1700000010.0,
        predicted_state=[0.1] * 36,
        infiltration_probability=0.72,
        uncertainty_lower=0.65,
        uncertainty_upper=0.79,
        predicted_stage=AttackStageEnum.RECONNAISSANCE,
        stage_probabilities={"RECONNAISSANCE": 0.8, "BENIGN": 0.2},
    )
    traj = ForecastTrajectory(
        forecast_id="fc_1",
        analysis_id="an_1",
        base_window_index=12,
        base_timestamp=1700000005.0,
        horizon_count=1,
        points=[fp],
        max_risk_in_horizon=0.72,
        peak_stage_predicted=AttackStageEnum.RECONNAISSANCE,
    )
    assert traj.points[0].infiltration_probability == 0.72
