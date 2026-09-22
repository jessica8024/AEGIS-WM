"""Streaming PCAP/PCAPNG packet parser using Scapy."""

import os
from pathlib import Path
from typing import Callable, Generator, List, Optional, Tuple
from scapy.all import PcapReader, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from aegis_wm.common.crypto import compute_sha256, pseudonymize_ip
from aegis_wm.common.logger import logger
from aegis_wm.flow.tracker import FlowSessionTracker
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.schemas.packet import PacketObservation


class PcapStreamingParser:
    """Parses PCAP/PCAPNG packets into normalized observations and bidirectional flows."""

    def __init__(
        self,
        active_timeout: float = 120.0,
        inactive_timeout: float = 15.0,
        max_packets: Optional[int] = None,
    ):
        self.active_timeout = active_timeout
        self.inactive_timeout = inactive_timeout
        self.max_packets = max_packets

    def extract_packet_observation(
        self, pkt: Packet, packet_idx: int, provenance: ProvenanceMetadata
    ) -> Optional[Tuple[PacketObservation, str, str]]:
        """
        Extracts strongly-typed PacketObservation and raw source/dest IPs
        from a Scapy packet. Returns None if non-IP or malformed.
        """
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return None

        timestamp = float(pkt.time)
        length = len(pkt)

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            protocol = int(ip_layer.proto)
            ip_version = 4
            ttl = int(ip_layer.ttl)
            ip_flags = int(ip_layer.flags)
            frag = int(ip_layer.frag)
        else:
            ip_layer = pkt[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            protocol = int(ip_layer.nh)
            ip_version = 6
            ttl = int(ip_layer.hlim)
            ip_flags = 0
            frag = 0

        src_port = 0
        dst_port = 0
        tcp_flags = None
        tcp_window = None
        payload_len = 0

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = int(tcp_layer.flags)
            tcp_window = int(tcp_layer.window)
            payload_len = len(tcp_layer.payload)
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            payload_len = len(udp_layer.payload)
        elif pkt.haslayer(ICMP) or pkt.haslayer(ICMPv6EchoRequest):
            src_port = 0
            dst_port = 0
            payload_len = len(pkt.payload.payload) if hasattr(pkt.payload, "payload") else 0

        obs = PacketObservation(
            provenance=provenance,
            packet_id=packet_idx,
            timestamp=timestamp,
            src_ip_pseudo=pseudonymize_ip(src_ip),
            dst_ip_pseudo=pseudonymize_ip(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            ip_version=ip_version,
            length=length,
            ttl=ttl,
            ip_flags=ip_flags,
            fragment_offset=frag,
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
            payload_length=payload_len,
        )

        return obs, src_ip, dst_ip

    def parse_pcap(
        self,
        pcap_path: Path | str,
        progress_callback: Optional[Callable[[float, int], None]] = None,
    ) -> List[BidirectionalFlow]:
        """
        Parses a PCAP/PCAPNG file and reconstructs bidirectional flows.
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        file_hash = compute_sha256(pcap_path)
        config_hash = compute_sha256(f"pcap_active_{self.active_timeout}_inactive_{self.inactive_timeout}")
        file_size = pcap_path.stat().st_size

        tracker = FlowSessionTracker(
            active_timeout_seconds=self.active_timeout,
            inactive_timeout_seconds=self.inactive_timeout,
        )

        packet_idx = 0
        first_timestamp: Optional[float] = None
        last_timestamp: Optional[float] = None

        logger.info(f"Opening PCAP: {pcap_path.name} ({file_size} bytes)")

        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                packet_idx += 1
                if self.max_packets and packet_idx > self.max_packets:
                    break

                ts = float(pkt.time)
                if first_timestamp is None:
                    first_timestamp = ts
                last_timestamp = ts

                prov = ProvenanceMetadata(
                    source_file_hash=file_hash,
                    extraction_config_hash=config_hash,
                    start_timestamp=ts,
                    end_timestamp=ts,
                    provenance_reference=pcap_path.name,
                )

                parsed = self.extract_packet_observation(pkt, packet_idx, prov)
                if parsed:
                    obs, raw_src, raw_dst = parsed
                    tracker.process_packet(obs, raw_src, raw_dst, prov)

                if progress_callback and packet_idx % 1000 == 0:
                    progress_callback(50.0, packet_idx)

        # Final flush
        final_prov = ProvenanceMetadata(
            source_file_hash=file_hash,
            extraction_config_hash=config_hash,
            start_timestamp=first_timestamp or 0.0,
            end_timestamp=last_timestamp or 0.0,
            provenance_reference=pcap_path.name,
        )
        flows = tracker.flush_all(final_prov)
        logger.info(f"Completed PCAP parsing: {packet_idx} packets parsed, {len(flows)} bidirectional flows extracted.")
        return flows
