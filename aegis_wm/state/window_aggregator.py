"""Sliding window state aggregation: builds 36-D global state vectors, host profiles, and graph edges."""

import collections
import math
from typing import Dict, List, Optional, Set, Tuple
from aegis_wm.common.crypto import compute_sha256
from aegis_wm.common.logger import logger
from aegis_wm.flow.tracker import compute_shannon_entropy
from aegis_wm.labels.mapper import AttackStageMapper
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.schemas.labels import AttackStageEnum
from aegis_wm.schemas.state import GraphEdge, HostWindowState, NetworkWindowState

HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3389, 4444, 8080, 8443}

FEATURE_NAMES = [
    "active_flow_count",
    "new_connection_count",
    "unique_src_hosts",
    "unique_dst_hosts",
    "unique_dst_ports",
    "byte_rate",
    "packet_rate",
    "syn_rate",
    "rst_rate",
    "ack_rate",
    "fin_rate",
    "syn_ack_ratio",
    "rst_syn_ratio",
    "failed_handshake_rate",
    "fwd_bwd_byte_ratio",
    "fwd_bwd_pkt_ratio",
    "flow_duration_mean",
    "flow_duration_std",
    "flow_iat_mean",
    "flow_iat_std",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "dst_port_entropy",
    "dst_host_entropy",
    "scan_activity_indicator",
    "fan_in_mean",
    "fan_out_mean",
    "burstiness",
    "ttl_variance_mean",
    "tcp_window_mean",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "high_risk_service_contacts",
]


class WindowStateAggregator:
    """Aggregates flow telemetry into continuous temporal window states S_t."""

    def __init__(
        self,
        window_size_seconds: float = 5.0,
        slide_step_seconds: float = 5.0,
        stage_mapper: Optional[AttackStageMapper] = None,
    ):
        self.window_size = window_size_seconds
        self.slide_step = slide_step_seconds
        self.stage_mapper = stage_mapper or AttackStageMapper()

    def aggregate_flows(
        self, flows: List[BidirectionalFlow]
    ) -> List[NetworkWindowState]:
        """
        Groups flows into temporal windows and computes global state vectors S_t.
        """
        if not flows:
            return []

        sorted_flows = sorted(flows, key=lambda f: f.start_timestamp)
        min_time = sorted_flows[0].start_timestamp
        max_time = max(f.end_timestamp for f in sorted_flows)

        total_span = max_time - min_time
        if total_span <= 0:
            total_span = self.window_size

        window_states: List[NetworkWindowState] = []
        current_start = min_time
        window_idx = 0

        while current_start <= max_time or window_idx == 0:
            current_end = current_start + self.window_size

            # Active flows in window [current_start, current_end]
            active_flows = [
                f for f in sorted_flows
                if f.start_timestamp <= current_end and f.end_timestamp >= current_start
            ]

            state = self._build_window_state(
                window_idx=window_idx,
                start_time=current_start,
                end_time=current_end,
                flows=active_flows,
            )
            window_states.append(state)

            window_idx += 1
            current_start += self.slide_step
            if current_start > max_time:
                break

        logger.info(f"Aggregated {len(flows)} flows into {len(window_states)} temporal state windows.")
        return window_states

    def _build_window_state(
        self,
        window_idx: int,
        start_time: float,
        end_time: float,
        flows: List[BidirectionalFlow],
    ) -> NetworkWindowState:
        """Constructs a single NetworkWindowState with 36-D feature vector and edges."""
        count = len(flows)
        prov = (
            flows[0].provenance
            if flows
            else ProvenanceMetadata(
                source_file_hash="0" * 64,
                extraction_config_hash="0" * 64,
                start_timestamp=start_time,
                end_timestamp=end_time,
                provenance_reference="window_synthetic",
            )
        )

        if count == 0:
            # Empty quiet window
            features = [0.0] * len(FEATURE_NAMES)
            return NetworkWindowState(
                window_index=window_idx,
                start_timestamp=start_time,
                end_timestamp=end_time,
                duration_seconds=self.window_size,
                provenance=prov,
                feature_vector=features,
                feature_names=FEATURE_NAMES,
                ground_truth_stage=AttackStageEnum.BENIGN,
                is_compromised=False,
            )

        # Entities and ports
        src_hosts = set(f.src_ip_pseudo for f in flows)
        dst_hosts = set(f.dst_ip_pseudo for f in flows)
        dst_ports = [f.dst_port for f in flows]
        unique_dst_ports = set(dst_ports)

        # Flows initiated within this window
        new_connections = sum(1 for f in flows if start_time <= f.start_timestamp <= end_time)

        # Volume and Rates
        total_bytes = sum(f.fwd_bytes + f.bwd_bytes for f in flows)
        total_pkts = sum(f.fwd_packets + f.bwd_packets for f in flows)
        byte_rate = total_bytes / self.window_size
        packet_rate = total_pkts / self.window_size

        # TCP Flag aggregates
        syn_count = sum(f.fwd_syn_count + f.bwd_syn_count for f in flows)
        rst_count = sum(f.fwd_rst_count + f.bwd_rst_count for f in flows)
        ack_count = sum(f.fwd_ack_count + f.bwd_ack_count for f in flows)
        fin_count = sum(f.fwd_fin_count + f.bwd_fin_count for f in flows)

        syn_rate = syn_count / self.window_size
        rst_rate = rst_count / self.window_size
        ack_rate = ack_count / self.window_size
        fin_rate = fin_count / self.window_size

        syn_ack_ratio = float(syn_count / max(1, ack_count))
        rst_syn_ratio = float(rst_count / max(1, syn_count))

        failed_handshakes = sum(1 for f in flows if f.tcp_handshake_failed)
        failed_handshake_rate = failed_handshakes / self.window_size

        total_fwd_bytes = sum(f.fwd_bytes for f in flows)
        total_bwd_bytes = sum(f.bwd_bytes for f in flows)
        total_fwd_pkts = sum(f.fwd_packets for f in flows)
        total_bwd_pkts = sum(f.bwd_packets for f in flows)

        fwd_bwd_byte_ratio = float(total_fwd_bytes / max(1, total_bwd_bytes))
        fwd_bwd_pkt_ratio = float(total_fwd_pkts / max(1, total_bwd_pkts))

        # Flow duration stats
        durations = [f.duration for f in flows]
        dur_mean = float(sum(durations) / count)
        dur_std = float(math.sqrt(sum((x - dur_mean) ** 2 for x in durations) / count))

        # IAT stats
        iats = [f.flow_iat_mean for f in flows]
        iat_mean = float(sum(iats) / count)
        iat_std = float(math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / count))

        # Packet lengths
        fwd_lens = [f.fwd_pkt_len_mean for f in flows]
        bwd_lens = [f.bwd_pkt_len_mean for f in flows]
        fwd_len_mean = float(sum(fwd_lens) / count)
        fwd_len_std = float(math.sqrt(sum((x - fwd_len_mean) ** 2 for x in fwd_lens) / count))
        bwd_len_mean = float(sum(bwd_lens) / count)
        bwd_len_std = float(math.sqrt(sum((x - bwd_len_mean) ** 2 for x in bwd_lens) / count))

        # Entropies
        dst_port_entropy = compute_shannon_entropy(dst_ports)
        host_hashes = [int(h.split("_")[1], 16) % 10000 for h in dst_hosts if "_" in h]
        dst_host_entropy = compute_shannon_entropy(host_hashes)

        # Scan and Fan-in / Fan-out statistics
        src_out_degree: Dict[str, Set[str]] = collections.defaultdict(set)
        dst_in_degree: Dict[str, Set[str]] = collections.defaultdict(set)
        src_port_scan: Dict[str, Set[int]] = collections.defaultdict(set)

        for f in flows:
            src_out_degree[f.src_ip_pseudo].add(f.dst_ip_pseudo)
            dst_in_degree[f.dst_ip_pseudo].add(f.src_ip_pseudo)
            src_port_scan[f.src_ip_pseudo].add(f.dst_port)

        fan_out_mean = (
            float(sum(len(targets) for targets in src_out_degree.values()) / len(src_out_degree))
            if src_out_degree
            else 0.0
        )
        fan_in_mean = (
            float(sum(len(sources) for sources in dst_in_degree.values()) / len(dst_in_degree))
            if dst_in_degree
            else 0.0
        )

        # Scan activity: max ports contacted by a single source host
        max_ports_scanned = max(len(ports) for ports in src_port_scan.values()) if src_port_scan else 0
        scan_activity_indicator = float(max_ports_scanned / max(1, len(unique_dst_ports)))

        # Packet derived features
        ttl_vars = [f.ttl_variance for f in flows]
        ttl_variance_mean = float(sum(ttl_vars) / count)

        tcp_wins = [f.tcp_win_max for f in flows if f.protocol == 6]
        tcp_window_mean = float(sum(tcp_wins) / len(tcp_wins)) if tcp_wins else 0.0

        # Protocols
        tcp_count = sum(1 for f in flows if f.protocol == 6)
        udp_count = sum(1 for f in flows if f.protocol == 17)
        icmp_count = sum(1 for f in flows if f.protocol in {1, 58})
        tcp_ratio = float(tcp_count / count)
        udp_ratio = float(udp_count / count)
        icmp_ratio = float(icmp_count / count)

        # High risk service access
        high_risk_contacts = sum(1 for f in flows if f.dst_port in HIGH_RISK_PORTS)

        # Burstiness score average
        burstiness = float(sum(f.burstiness_score for f in flows) / count)

        # Compile feature vector S_t
        feature_vector = [
            float(count),
            float(new_connections),
            float(len(src_hosts)),
            float(len(dst_hosts)),
            float(len(unique_dst_ports)),
            byte_rate,
            packet_rate,
            syn_rate,
            rst_rate,
            ack_rate,
            fin_rate,
            syn_ack_ratio,
            rst_syn_ratio,
            failed_handshake_rate,
            fwd_bwd_byte_ratio,
            fwd_bwd_pkt_ratio,
            dur_mean,
            dur_std,
            iat_mean,
            iat_std,
            fwd_len_mean,
            fwd_len_std,
            bwd_len_mean,
            bwd_len_std,
            dst_port_entropy,
            dst_host_entropy,
            scan_activity_indicator,
            fan_in_mean,
            fan_out_mean,
            burstiness,
            ttl_variance_mean,
            tcp_window_mean,
            tcp_ratio,
            udp_ratio,
            icmp_ratio,
            float(high_risk_contacts),
        ]

        # Determine ground-truth stage from labels if present
        labels = [f.source_label for f in flows if f.source_label and f.source_label != "BENIGN"]
        if labels:
            # Pick most prevalent attack stage in window
            top_label = collections.Counter(labels).most_common(1)[0][0]
            stage_info = self.stage_mapper.map_label(top_label)
            ground_truth_stage = stage_info.stage_id
            is_compromised = ground_truth_stage != AttackStageEnum.BENIGN
        else:
            ground_truth_stage = AttackStageEnum.BENIGN
            is_compromised = False

        # Build communication graph edges
        edge_map: Dict[Tuple[str, str, int, int], Dict[str, int]] = collections.defaultdict(
            lambda: {"flows": 0, "bytes": 0, "syn": 0, "rst": 0}
        )
        for f in flows:
            ekey = (f.src_ip_pseudo, f.dst_ip_pseudo, f.protocol, f.dst_port)
            edge_map[ekey]["flows"] += 1
            edge_map[ekey]["bytes"] += f.fwd_bytes + f.bwd_bytes
            edge_map[ekey]["syn"] += f.fwd_syn_count
            edge_map[ekey]["rst"] += f.fwd_rst_count

        edges = [
            GraphEdge(
                src_host=k[0],
                dst_host=k[1],
                protocol=k[2],
                dst_port=k[3],
                flow_count=v["flows"],
                byte_count=v["bytes"],
                syn_count=v["syn"],
                rst_count=v["rst"],
            )
            for k, v in edge_map.items()
        ]

        return NetworkWindowState(
            window_index=window_idx,
            start_timestamp=start_time,
            end_timestamp=end_time,
            duration_seconds=self.window_size,
            provenance=prov,
            active_flow_count=count,
            new_connection_count=new_connections,
            unique_src_hosts=len(src_hosts),
            unique_dst_hosts=len(dst_hosts),
            unique_dst_ports=len(unique_dst_ports),
            byte_rate=byte_rate,
            packet_rate=packet_rate,
            syn_rate=syn_rate,
            rst_rate=rst_rate,
            ack_rate=ack_rate,
            fin_rate=fin_rate,
            syn_ack_ratio=syn_ack_ratio,
            rst_syn_ratio=rst_syn_ratio,
            failed_handshake_rate=failed_handshake_rate,
            fwd_bwd_byte_ratio=fwd_bwd_byte_ratio,
            fwd_bwd_pkt_ratio=fwd_bwd_pkt_ratio,
            dst_port_entropy=dst_port_entropy,
            dst_host_entropy=dst_host_entropy,
            scan_activity_indicator=scan_activity_indicator,
            fan_in_mean=fan_in_mean,
            fan_out_mean=fan_out_mean,
            burstiness=burstiness,
            ttl_variance_mean=ttl_variance_mean,
            tcp_window_mean=tcp_window_mean,
            tcp_ratio=tcp_ratio,
            udp_ratio=udp_ratio,
            icmp_ratio=icmp_ratio,
            high_risk_service_contacts=high_risk_contacts,
            feature_vector=feature_vector,
            feature_names=FEATURE_NAMES,
            ground_truth_stage=ground_truth_stage,
            is_compromised=is_compromised,
            edges=edges,
        )
