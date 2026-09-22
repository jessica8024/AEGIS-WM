"""Unit tests for Scapy PCAP parser with programmatic protocol fixture."""

import tempfile
from pathlib import Path
import pytest
from scapy.all import IP, TCP, UDP, wrpcap
from aegis_wm.packet.parser import PcapStreamingParser


@pytest.fixture
def protocol_pcap_fixture(tmp_path: Path) -> Path:
    """Generates a tiny valid PCAP file with known TCP and UDP packets for parser regression."""
    pcap_path = tmp_path / "protocol_test.pcap"

    pkts = []
    # 3-way handshake on port 80
    pkts.append(IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=45000, dport=80, flags="S", seq=1000))
    pkts.append(IP(src="10.0.0.1", dst="192.168.1.100")/TCP(sport=80, dport=45000, flags="SA", seq=2000, ack=1001))
    pkts.append(IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=45000, dport=80, flags="A", seq=1001, ack=2001))
    # HTTP data payload
    pkts.append(IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=45000, dport=80, flags="PA", seq=1001, ack=2001)/b"GET / HTTP/1.1\r\n\r\n")

    # UDP DNS query
    pkts.append(IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=53535, dport=53)/b"\x00\x01\x01\x00")

    wrpcap(str(pcap_path), pkts)
    return pcap_path


def test_pcap_parser_flow_extraction(protocol_pcap_fixture: Path):
    parser = PcapStreamingParser(active_timeout=60.0, inactive_timeout=15.0)
    flows = parser.parse_pcap(protocol_pcap_fixture)

    # Should extract 2 bidirectional flows: 1 TCP on port 80, 1 UDP on port 53
    assert len(flows) == 2

    tcp_flows = [f for f in flows if f.protocol == 6]
    udp_flows = [f for f in flows if f.protocol == 17]

    assert len(tcp_flows) == 1
    assert len(udp_flows) == 1

    tcp_flow = tcp_flows[0]
    assert tcp_flow.dst_port == 80
    assert tcp_flow.fwd_packets == 3  # SYN, ACK, PSH+ACK
    assert tcp_flow.bwd_packets == 1  # SYN+ACK
    assert tcp_flow.tcp_handshake_completed is True
    assert tcp_flow.provenance.source_file_hash != ""

    udp_flow = udp_flows[0]
    assert udp_flow.dst_port == 53
    assert udp_flow.fwd_packets == 1
