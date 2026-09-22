"""Schema for raw packet observations."""

from typing import Optional
from pydantic import BaseModel, Field
from aegis_wm.schemas.base import ProvenanceMetadata


class PacketObservation(BaseModel):
    """Normalized observation extracted from an individual network packet."""

    provenance: ProvenanceMetadata
    packet_id: int = Field(..., description="Monotonically increasing packet index in capture")
    timestamp: float = Field(..., description="Packet arrival timestamp (epoch seconds)")
    src_ip_pseudo: str = Field(..., description="Pseudonymized source IP (host_<hmac>)")
    dst_ip_pseudo: str = Field(..., description="Pseudonymized destination IP (host_<hmac>)")
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: int = Field(..., description="IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)")
    ip_version: int = Field(4, description="IP version (4 or 6)")
    length: int = Field(..., ge=0, description="Total packet length in bytes")
    ttl: Optional[int] = Field(None, ge=0, le=255, description="IP Time-To-Live / Hop Limit")
    ip_flags: int = Field(0, description="IP flags (e.g. DF=2, MF=1)")
    fragment_offset: int = Field(0, description="IP fragment offset")
    tcp_flags: Optional[int] = Field(None, description="TCP flags bitmask")
    tcp_window: Optional[int] = Field(None, description="TCP window size")
    payload_length: int = Field(0, ge=0, description="Transport layer payload length")
