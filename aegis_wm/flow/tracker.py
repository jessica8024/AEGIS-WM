"""Bidirectional flow session tracker and feature computation."""

import math
from typing import Dict, List, Optional, Tuple
from aegis_wm.common.crypto import compute_sha256, pseudonymize_ip
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.schemas.packet import PacketObservation


def compute_shannon_entropy(values: List[float | int], num_bins: int = 10) -> float:
    """Computes normalized Shannon entropy of a distribution."""
    if not values or len(values) <= 1:
        return 0.0
    val_min, val_max = min(values), max(values)
    if val_min == val_max:
        return 0.0

    bin_width = (val_max - val_min) / num_bins
    counts = [0] * num_bins
    for v in values:
        idx = min(int((v - val_min) / bin_width), num_bins - 1)
        counts[idx] += 1

    total = len(values)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)

    max_entropy = math.log2(num_bins)
    return float(entropy / max_entropy) if max_entropy > 0 else 0.0


class BidirectionalSession:
    """Maintains active state of a bidirectional flow and computes derived features."""

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        initial_packet: PacketObservation,
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.created_at = initial_packet.timestamp
        self.last_seen = initial_packet.timestamp

        # Packet and byte logs
        self.fwd_packets: int = 0
        self.bwd_packets: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0

        self.fwd_lengths: List[int] = []
        self.bwd_lengths: List[int] = []
        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []
        self.all_timestamps: List[float] = []

        # Flags: [SYN, ACK, FIN, RST, PSH, URG]
        self.fwd_flags = {"syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0}
        self.bwd_flags = {"syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0}

        # Session metrics
        self.ttls: List[int] = []
        self.tcp_windows: List[int] = []
        self.fragmented_count: int = 0
        self.zero_payload_count: int = 0
        self.payload_lengths: List[int] = []

        self.add_packet(initial_packet)

    def add_packet(self, pkt: PacketObservation) -> None:
        """Incorporates an observed packet into this session."""
        self.last_seen = pkt.timestamp
        self.all_timestamps.append(pkt.timestamp)

        is_forward = (
            pkt.src_ip_pseudo == pseudonymize_ip(self.src_ip)
            and pkt.src_port == self.src_port
            and pkt.dst_port == self.dst_port
        )

        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.length
            self.fwd_lengths.append(pkt.length)
            self.fwd_timestamps.append(pkt.timestamp)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.length
            self.bwd_lengths.append(pkt.length)
            self.bwd_timestamps.append(pkt.timestamp)

        # TTL & Fragment tracking
        if pkt.ttl is not None:
            self.ttls.append(pkt.ttl)
        if pkt.fragment_offset > 0 or (pkt.ip_flags & 1):
            self.fragmented_count += 1

        # Payload
        self.payload_lengths.append(pkt.payload_length)
        if pkt.payload_length == 0:
            self.zero_payload_count += 1

        # TCP specific fields
        if pkt.tcp_flags is not None:
            flags = pkt.tcp_flags
            target_dict = self.fwd_flags if is_forward else self.bwd_flags
            if flags & 0x02:  # SYN
                target_dict["syn"] += 1
            if flags & 0x10:  # ACK
                target_dict["ack"] += 1
            if flags & 0x01:  # FIN
                target_dict["fin"] += 1
            if flags & 0x04:  # RST
                target_dict["rst"] += 1
            if flags & 0x08:  # PSH
                target_dict["psh"] += 1
            if flags & 0x20:  # URG
                target_dict["urg"] += 1

        if pkt.tcp_window is not None:
            self.tcp_windows.append(pkt.tcp_window)

    def to_bidirectional_flow(self, provenance: ProvenanceMetadata) -> BidirectionalFlow:
        """Finalizes session and returns strongly typed BidirectionalFlow."""
        duration = max(0.0, self.last_seen - self.created_at)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        packets_per_sec = float(total_packets / duration) if duration > 0 else float(total_packets)
        bytes_per_sec = float(total_bytes / duration) if duration > 0 else float(total_bytes)

        # Packet length statistics helper
        def calc_stats(arr: List[int]) -> Tuple[float, float, float, float]:
            if not arr:
                return 0.0, 0.0, 0.0, 0.0
            mean_val = sum(arr) / len(arr)
            variance = sum((x - mean_val) ** 2 for x in arr) / len(arr)
            std_val = math.sqrt(variance)
            return float(mean_val), float(std_val), float(min(arr)), float(max(arr))

        fwd_mean, fwd_std, fwd_min, fwd_max = calc_stats(self.fwd_lengths)
        bwd_mean, bwd_std, bwd_min, bwd_max = calc_stats(self.bwd_lengths)

        # IAT calculations
        def calc_iats(ts: List[float]) -> List[float]:
            if len(ts) < 2:
                return []
            return [ts[i] - ts[i - 1] for i in range(1, len(ts))]

        flow_iats = calc_iats(sorted(self.all_timestamps))
        fwd_iats = calc_iats(self.fwd_timestamps)
        bwd_iats = calc_iats(self.bwd_timestamps)

        flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max = (
            calc_stats([int(x * 1000000) for x in flow_iats]) if flow_iats else (0.0, 0.0, 0.0, 0.0)
        )
        # normalize microseconds back to seconds
        flow_iat_mean /= 1000000.0
        flow_iat_std /= 1000000.0
        flow_iat_min /= 1000000.0
        flow_iat_max /= 1000000.0

        fwd_iat_mean = (sum(fwd_iats) / len(fwd_iats)) if fwd_iats else 0.0
        bwd_iat_mean = (sum(bwd_iats) / len(bwd_iats)) if bwd_iats else 0.0

        # Flag ratios and Handshake
        total_syn = self.fwd_flags["syn"] + self.bwd_flags["syn"]
        total_ack = self.fwd_flags["ack"] + self.bwd_flags["ack"]
        total_rst = self.fwd_flags["rst"] + self.bwd_flags["rst"]

        syn_ack_ratio = float(total_syn / total_ack) if total_ack > 0 else float(total_syn)
        rst_syn_ratio = float(total_rst / total_syn) if total_syn > 0 else float(total_rst)

        # Handshake heuristic
        handshake_completed = (
            self.fwd_flags["syn"] > 0
            and self.bwd_flags["syn"] > 0
            and self.bwd_flags["ack"] > 0
            and self.fwd_flags["ack"] > 0
        )
        handshake_failed = (self.fwd_flags["syn"] > 0 and self.bwd_flags["syn"] == 0 and duration > 3.0)
        connection_reset = total_rst > 0

        # TTL statistics
        ttl_mean = float(sum(self.ttls) / len(self.ttls)) if self.ttls else 0.0
        ttl_variance = (
            float(sum((t - ttl_mean) ** 2 for t in self.ttls) / len(self.ttls)) if self.ttls else 0.0
        )

        # Window statistics
        tcp_win_min = min(self.tcp_windows) if self.tcp_windows else 0
        tcp_win_max = max(self.tcp_windows) if self.tcp_windows else 0

        # Entropies & burstiness
        zero_payload_ratio = (
            float(self.zero_payload_count / total_packets) if total_packets > 0 else 0.0
        )
        payload_entropy = compute_shannon_entropy(self.payload_lengths)
        timing_entropy = compute_shannon_entropy(flow_iats) if flow_iats else 0.0

        # Burstiness score: (std - mean) / (std + mean) bounded [-1, 1]
        burstiness = 0.0
        if flow_iat_std + flow_iat_mean > 0:
            burstiness = (flow_iat_std - flow_iat_mean) / (flow_iat_std + flow_iat_mean)

        flow_id = compute_sha256(
            f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.protocol}:{self.created_at}"
        )

        return BidirectionalFlow(
            flow_id=flow_id,
            provenance=provenance,
            src_ip_pseudo=pseudonymize_ip(self.src_ip),
            dst_ip_pseudo=pseudonymize_ip(self.dst_ip),
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            start_timestamp=self.created_at,
            end_timestamp=self.last_seen,
            duration=duration,
            fwd_packets=self.fwd_packets,
            bwd_packets=self.bwd_packets,
            fwd_bytes=self.fwd_bytes,
            bwd_bytes=self.bwd_bytes,
            packets_per_sec=packets_per_sec,
            bytes_per_sec=bytes_per_sec,
            fwd_pkt_len_mean=fwd_mean,
            fwd_pkt_len_std=fwd_std,
            fwd_pkt_len_min=fwd_min,
            fwd_pkt_len_max=fwd_max,
            bwd_pkt_len_mean=bwd_mean,
            bwd_pkt_len_std=bwd_std,
            bwd_pkt_len_min=bwd_min,
            bwd_pkt_len_max=bwd_max,
            fwd_bwd_pkt_ratio=float(self.fwd_packets / max(1, self.bwd_packets)),
            fwd_bwd_byte_ratio=float(self.fwd_bytes / max(1, self.bwd_bytes)),
            flow_iat_mean=flow_iat_mean,
            flow_iat_std=flow_iat_std,
            flow_iat_min=flow_iat_min,
            flow_iat_max=flow_iat_max,
            fwd_iat_mean=fwd_iat_mean,
            bwd_iat_mean=bwd_iat_mean,
            fwd_syn_count=self.fwd_flags["syn"],
            fwd_ack_count=self.fwd_flags["ack"],
            fwd_fin_count=self.fwd_flags["fin"],
            fwd_rst_count=self.fwd_flags["rst"],
            fwd_psh_count=self.fwd_flags["psh"],
            fwd_urg_count=self.fwd_flags["urg"],
            bwd_syn_count=self.bwd_flags["syn"],
            bwd_ack_count=self.bwd_flags["ack"],
            bwd_fin_count=self.bwd_flags["fin"],
            bwd_rst_count=self.bwd_flags["rst"],
            bwd_psh_count=self.bwd_flags["psh"],
            bwd_urg_count=self.bwd_flags["urg"],
            syn_ack_ratio=syn_ack_ratio,
            rst_syn_ratio=rst_syn_ratio,
            tcp_handshake_completed=handshake_completed,
            tcp_handshake_failed=handshake_failed,
            connection_reset=connection_reset,
            retransmission_count=0,
            ttl_mean=ttl_mean,
            ttl_variance=ttl_variance,
            tcp_win_min=tcp_win_min,
            tcp_win_max=tcp_win_max,
            fragmented_packet_count=self.fragmented_count,
            zero_payload_ratio=zero_payload_ratio,
            payload_size_entropy=payload_entropy,
            timing_entropy=timing_entropy,
            burstiness_score=burstiness,
        )


class FlowSessionTracker:
    """Manages active sessions with configurable timeouts and bidirectional merging."""

    def __init__(
        self,
        active_timeout_seconds: float = 120.0,
        inactive_timeout_seconds: float = 15.0,
    ):
        self.active_timeout = active_timeout_seconds
        self.inactive_timeout = inactive_timeout_seconds
        self.active_sessions: Dict[Tuple[str, str, int, int, int], BidirectionalSession] = {}
        self.completed_flows: List[BidirectionalFlow] = []

    def _get_session_key(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int
    ) -> Tuple[Tuple[str, str, int, int, int], bool]:
        """
        Returns canonical forward session key and boolean indicating whether
        the packet aligns with existing forward session direction.
        """
        fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        if fwd_key in self.active_sessions:
            return fwd_key, True
        if bwd_key in self.active_sessions:
            return bwd_key, False

        # If not present, forward key is established
        return fwd_key, True

    def process_packet(
        self,
        pkt: PacketObservation,
        raw_src_ip: str,
        raw_dst_ip: str,
        provenance: ProvenanceMetadata,
    ) -> Optional[BidirectionalFlow]:
        """
        Processes a packet into existing or new session.
        Checks for expired sessions and returns them if expired.
        """
        # Periodic expiration check
        self.flush_expired(pkt.timestamp, provenance)

        key, is_fwd = self._get_session_key(
            raw_src_ip, raw_dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol
        )

        if key not in self.active_sessions:
            # Create new session
            session = BidirectionalSession(
                src_ip=raw_src_ip,
                dst_ip=raw_dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                initial_packet=pkt,
            )
            self.active_sessions[key] = session
        else:
            session = self.active_sessions[key]
            # Check timeout before adding
            if (
                pkt.timestamp - session.last_seen > self.inactive_timeout
                or pkt.timestamp - session.created_at > self.active_timeout
            ):
                # Session expired, finalize previous and start new
                completed = session.to_bidirectional_flow(provenance)
                self.completed_flows.append(completed)
                # start new session
                new_session = BidirectionalSession(
                    src_ip=raw_src_ip,
                    dst_ip=raw_dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    initial_packet=pkt,
                )
                self.active_sessions[key] = new_session
            else:
                session.add_packet(pkt)

        return None

    def flush_expired(
        self, current_timestamp: float, provenance: ProvenanceMetadata
    ) -> List[BidirectionalFlow]:
        """Flushes sessions that exceeded active or inactive timeouts."""
        expired_keys = []
        for key, session in self.active_sessions.items():
            if (
                current_timestamp - session.last_seen > self.inactive_timeout
                or current_timestamp - session.created_at > self.active_timeout
            ):
                expired_keys.append(key)

        for k in expired_keys:
            session = self.active_sessions.pop(k)
            flow = session.to_bidirectional_flow(provenance)
            self.completed_flows.append(flow)

        return self.completed_flows

    def flush_all(self, provenance: ProvenanceMetadata) -> List[BidirectionalFlow]:
        """Flushes all remaining active sessions at EOF."""
        for session in self.active_sessions.values():
            self.completed_flows.append(session.to_bidirectional_flow(provenance))
        self.active_sessions.clear()
        return self.completed_flows
