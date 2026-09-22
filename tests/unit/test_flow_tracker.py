"""Unit tests for bidirectional flow tracker."""

from typing import Tuple
from aegis_wm.flow.tracker import BidirectionalSession, FlowSessionTracker, compute_shannon_entropy
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.packet import PacketObservation


def make_test_packet(
    pkt_id: int,
    ts: float,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    proto: int = 6,
    length: int = 64,
    tcp_flags: int = 0x02,  # SYN
) -> Tuple[PacketObservation, str, str]:
    from aegis_wm.common.crypto import pseudonymize_ip
    prov = ProvenanceMetadata(
        source_file_hash="0" * 64,
        extraction_config_hash="0" * 64,
        start_timestamp=ts,
        end_timestamp=ts,
        provenance_reference="test_fixture",
    )
    obs = PacketObservation(
        provenance=prov,
        packet_id=pkt_id,
        timestamp=ts,
        src_ip_pseudo=pseudonymize_ip(src_ip),
        dst_ip_pseudo=pseudonymize_ip(dst_ip),
        src_port=sport,
        dst_port=dport,
        protocol=proto,
        length=length,
        ttl=64,
        tcp_flags=tcp_flags,
        payload_length=max(0, length - 54),
    )
    return obs, src_ip, dst_ip


def test_shannon_entropy_calculation():
    # Uniform values -> zero entropy
    assert compute_shannon_entropy([10, 10, 10, 10]) == 0.0
    # Diverse values -> positive entropy <= 1.0
    ent = compute_shannon_entropy([10, 20, 30, 40, 50, 60, 70, 80])
    assert 0.0 < ent <= 1.0


def test_bidirectional_session_merging():
    obs1, src1, dst1 = make_test_packet(1, 100.0, "192.168.1.10", "10.0.0.5", 50000, 80, tcp_flags=0x02)  # SYN
    obs2, src2, dst2 = make_test_packet(2, 100.05, "10.0.0.5", "192.168.1.10", 80, 50000, tcp_flags=0x12) # SYN+ACK
    obs3, src3, dst3 = make_test_packet(3, 100.10, "192.168.1.10", "10.0.0.5", 50000, 80, tcp_flags=0x10) # ACK

    tracker = FlowSessionTracker(active_timeout_seconds=10.0, inactive_timeout_seconds=5.0)
    tracker.process_packet(obs1, src1, dst1, obs1.provenance)
    tracker.process_packet(obs2, src2, dst2, obs2.provenance)
    tracker.process_packet(obs3, src3, dst3, obs3.provenance)

    # All 3 packets should merge into 1 bidirectional session
    assert len(tracker.active_sessions) == 1

    flows = tracker.flush_all(obs1.provenance)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.fwd_packets == 2  # pkt 1 and 3
    assert flow.bwd_packets == 1  # pkt 2
    assert flow.tcp_handshake_completed is True
    assert flow.fwd_syn_count == 1
    assert flow.bwd_syn_count == 1
    assert flow.bwd_ack_count == 1


def test_session_timeout_flushing():
    obs1, src1, dst1 = make_test_packet(1, 100.0, "10.1.1.1", "10.2.2.2", 1000, 80)
    obs2, src2, dst2 = make_test_packet(2, 120.0, "10.1.1.1", "10.2.2.2", 1000, 80)  # 20s later (> inactive 15s)

    tracker = FlowSessionTracker(active_timeout_seconds=60.0, inactive_timeout_seconds=15.0)
    tracker.process_packet(obs1, src1, dst1, obs1.provenance)
    tracker.process_packet(obs2, src2, dst2, obs2.provenance)

    # First session should have completed and flushed, second session active
    assert len(tracker.completed_flows) == 1
    assert len(tracker.active_sessions) == 1
