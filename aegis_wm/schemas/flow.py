"""Schema for canonical bidirectional network flows."""

from typing import List, Optional
from pydantic import BaseModel, Field
from aegis_wm.schemas.base import ProvenanceMetadata


class BidirectionalFlow(BaseModel):
    """Canonical representation of a bidirectional network session."""

    flow_id: str = Field(..., description="Unique flow identifier hash")
    provenance: ProvenanceMetadata

    # Canonical 5-Tuple (pseudonymized IPs)
    src_ip_pseudo: str = Field(..., description="Forward initiator pseudonymized host")
    dst_ip_pseudo: str = Field(..., description="Forward responder pseudonymized host")
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: int = Field(..., description="IP protocol (6=TCP, 17=UDP, 1=ICMP)")

    # Temporal Bounds
    start_timestamp: float = Field(..., description="Epoch seconds of first packet")
    end_timestamp: float = Field(..., description="Epoch seconds of last packet")
    duration: float = Field(..., ge=0.0, description="Flow duration in seconds")

    # Volume & Rate Statistics
    fwd_packets: int = Field(..., ge=0)
    bwd_packets: int = Field(..., ge=0)
    fwd_bytes: int = Field(..., ge=0)
    bwd_bytes: int = Field(..., ge=0)
    packets_per_sec: float = Field(..., ge=0.0)
    bytes_per_sec: float = Field(..., ge=0.0)

    # Packet Length Metrics
    fwd_pkt_len_mean: float = Field(0.0)
    fwd_pkt_len_std: float = Field(0.0)
    fwd_pkt_len_min: float = Field(0.0)
    fwd_pkt_len_max: float = Field(0.0)
    bwd_pkt_len_mean: float = Field(0.0)
    bwd_pkt_len_std: float = Field(0.0)
    bwd_pkt_len_min: float = Field(0.0)
    bwd_pkt_len_max: float = Field(0.0)
    fwd_bwd_pkt_ratio: float = Field(1.0)
    fwd_bwd_byte_ratio: float = Field(1.0)

    # Inter-Arrival Time (IAT) Metrics
    flow_iat_mean: float = Field(0.0)
    flow_iat_std: float = Field(0.0)
    flow_iat_min: float = Field(0.0)
    flow_iat_max: float = Field(0.0)
    fwd_iat_mean: float = Field(0.0)
    bwd_iat_mean: float = Field(0.0)

    # TCP Flag Metrics
    fwd_syn_count: int = Field(0)
    fwd_ack_count: int = Field(0)
    fwd_fin_count: int = Field(0)
    fwd_rst_count: int = Field(0)
    fwd_psh_count: int = Field(0)
    fwd_urg_count: int = Field(0)
    bwd_syn_count: int = Field(0)
    bwd_ack_count: int = Field(0)
    bwd_fin_count: int = Field(0)
    bwd_rst_count: int = Field(0)
    bwd_psh_count: int = Field(0)
    bwd_urg_count: int = Field(0)
    syn_ack_ratio: float = Field(0.0)
    rst_syn_ratio: float = Field(0.0)

    # Handshake & Protocol Integrity
    tcp_handshake_completed: bool = Field(False)
    tcp_handshake_failed: bool = Field(False)
    connection_reset: bool = Field(False)
    retransmission_count: int = Field(0)

    # Advanced Packet/Session Metrics
    ttl_mean: float = Field(0.0)
    ttl_variance: float = Field(0.0)
    tcp_win_min: int = Field(0)
    tcp_win_max: int = Field(0)
    fragmented_packet_count: int = Field(0)
    zero_payload_ratio: float = Field(0.0)
    payload_size_entropy: float = Field(0.0)
    timing_entropy: float = Field(0.0)
    burstiness_score: float = Field(0.0)

    # Optional Dataset Ground-Truth Label (for training/evaluation, never as model input)
    source_label: Optional[str] = Field(None, description="Raw label from source dataset if labeled")
