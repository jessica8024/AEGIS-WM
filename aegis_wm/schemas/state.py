"""Schemas for time-windowed network and host states."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.labels import AttackStageEnum


class HostWindowState(BaseModel):
    """Behavioral profile of a pseudonymized host in a single time window."""

    host_pseudo: str = Field(..., description="Pseudonymized host ID")
    window_index: int = Field(..., ge=0)
    inbound_flows: int = Field(0)
    outbound_flows: int = Field(0)
    inbound_bytes: int = Field(0)
    outbound_bytes: int = Field(0)
    unique_peers: int = Field(0)
    unique_ports: int = Field(0)
    failed_connection_ratio: float = Field(0.0)
    scan_fanout_score: float = Field(0.0)
    beaconing_score: float = Field(0.0)
    data_transfer_deviation: float = Field(0.0)
    estimated_role: str = Field("client", description="e.g. client, server, scanner, beacon")


class GraphEdge(BaseModel):
    """Directed communication edge between hosts during a window."""

    src_host: str
    dst_host: str
    protocol: int
    dst_port: int
    flow_count: int
    byte_count: int
    syn_count: int = 0
    rst_count: int = 0


class NetworkWindowState(BaseModel):
    """
    Global network state S_t for a single time window t.
    Contains the 36-dimensional continuous feature vector and optional structural graph.
    """

    window_index: int = Field(..., ge=0, description="Sequential window index")
    start_timestamp: float = Field(..., description="Window start time epoch seconds")
    end_timestamp: float = Field(..., description="Window end time epoch seconds")
    duration_seconds: float = Field(5.0, description="Window duration")
    provenance: ProvenanceMetadata

    # Aggregate Flow Metrics
    active_flow_count: int = Field(0)
    new_connection_count: int = Field(0)
    unique_src_hosts: int = Field(0)
    unique_dst_hosts: int = Field(0)
    unique_dst_ports: int = Field(0)

    # Rates
    byte_rate: float = Field(0.0, description="Bytes per second")
    packet_rate: float = Field(0.0, description="Packets per second")
    syn_rate: float = Field(0.0, description="SYN packets per second")
    rst_rate: float = Field(0.0, description="RST packets per second")
    ack_rate: float = Field(0.0, description="ACK packets per second")
    fin_rate: float = Field(0.0, description="FIN packets per second")

    # Ratio Metrics
    syn_ack_ratio: float = Field(0.0)
    rst_syn_ratio: float = Field(0.0)
    failed_handshake_rate: float = Field(0.0)
    fwd_bwd_byte_ratio: float = Field(1.0)
    fwd_bwd_pkt_ratio: float = Field(1.0)

    # Entropies & Behavioral Indicators
    dst_port_entropy: float = Field(0.0)
    dst_host_entropy: float = Field(0.0)
    scan_activity_indicator: float = Field(0.0)
    fan_in_mean: float = Field(0.0)
    fan_out_mean: float = Field(0.0)
    burstiness: float = Field(0.0)

    # Packet-Derived Features
    ttl_variance_mean: float = Field(0.0)
    tcp_window_mean: float = Field(0.0)
    fragmentation_rate: float = Field(0.0)
    zero_payload_ratio: float = Field(0.0)
    timing_entropy_mean: float = Field(0.0)

    # Protocol Distribution Ratios
    tcp_ratio: float = Field(0.0)
    udp_ratio: float = Field(0.0)
    icmp_ratio: float = Field(0.0)
    high_risk_service_contacts: int = Field(0)

    # Feature Vector Representation S_t
    feature_vector: List[float] = Field(default_factory=list, description="Ordered feature vector S_t")
    feature_names: List[str] = Field(default_factory=list, description="Feature names in order")

    # Ground-truth Stage & Risk (for training/evaluation)
    ground_truth_stage: AttackStageEnum = Field(AttackStageEnum.BENIGN)
    is_compromised: bool = Field(False)

    # Graph Topology (optional)
    edges: List[GraphEdge] = Field(default_factory=list)


class TemporalSequence(BaseModel):
    """A temporal context sequence of m windows paired with K future horizons."""

    sequence_id: str
    context_windows: List[NetworkWindowState] = Field(..., description="Observed windows [t-m+1, ..., t]")
    future_windows: List[NetworkWindowState] = Field(
        default_factory=list, description="Ground truth future windows [t+1, ..., t+K]"
    )
