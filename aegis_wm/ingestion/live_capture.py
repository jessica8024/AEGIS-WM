"""Authorized live network packet capture with bounded ring queues and privilege checks."""

import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from scapy.all import AsyncSniffer, get_if_list
from aegis_wm.common.crypto import compute_sha256
from aegis_wm.common.logger import logger
from aegis_wm.flow.tracker import FlowSessionTracker
from aegis_wm.packet.parser import PcapStreamingParser
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow


class UnauthorizedMonitoringError(PermissionError):
    """Raised when live capture is attempted without explicit operator authorization."""
    pass


class LiveCaptureEngine:
    """
    Safely captures packets from an authorized network interface using bounded queues.
    Enforces ethical authorization checks and reports queue backpressure.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        max_queue_size: int = 50000,
        active_timeout: float = 120.0,
        inactive_timeout: float = 15.0,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.max_queue_size = max_queue_size
        self.packet_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.dropped_packets: int = 0
        self.total_captured: int = 0
        self.is_running: bool = False
        self._sniffer: Optional[AsyncSniffer] = None
        self._worker_thread: Optional[threading.Thread] = None

        self.tracker = FlowSessionTracker(
            active_timeout_seconds=active_timeout,
            inactive_timeout_seconds=inactive_timeout,
        )
        self.parser = PcapStreamingParser(
            active_timeout=active_timeout,
            inactive_timeout=inactive_timeout,
        )

    @staticmethod
    def list_interfaces() -> List[str]:
        """Enumerates available system network interfaces."""
        try:
            return get_if_list()
        except Exception as e:
            logger.error(f"Failed to list network interfaces: {e}")
            return []

    def start(
        self,
        authorization_confirmed: bool,
        flow_callback: Optional[Callable[[BidirectionalFlow], None]] = None,
    ) -> None:
        """
        Starts live packet capture.
        MANDATORY: authorization_confirmed must be True, acknowledging that
        the operator has explicit legal authority to capture on this network.
        """
        if not authorization_confirmed:
            raise UnauthorizedMonitoringError(
                "Live network capture requires explicit authorization acknowledgement. "
                "Monitoring is legally permitted only on networks you own or are explicitly authorized to audit."
            )

        if self.is_running:
            logger.warning("Capture engine is already active.")
            return

        self.is_running = True
        self.dropped_packets = 0
        self.total_captured = 0

        # Start worker thread to process packet queue into flows
        self._worker_thread = threading.Thread(
            target=self._process_queue_worker,
            args=(flow_callback,),
            daemon=True,
        )
        self._worker_thread.start()

        # Packet enqueue handler
        def _on_packet(pkt):
            if not self.is_running:
                return
            self.total_captured += 1
            try:
                self.packet_queue.put_nowait(pkt)
            except queue.Full:
                self.dropped_packets += 1

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=_on_packet,
                store=False,
            )
            self._sniffer.start()
            logger.info(
                f"Live capture initiated on interface '{self.interface or 'default'}' "
                f"with filter: '{self.bpf_filter or 'none'}'."
            )
        except Exception as e:
            self.is_running = False
            logger.error(f"Failed to bind live sniffer: {e}")
            raise PermissionError(
                f"Failed to start packet capture on interface {self.interface}: {e}. "
                "Ensure sufficient administrative privileges (e.g. Npcap on Windows or sudo on Linux)."
            )

    def stop(self) -> Dict[str, Any]:
        """Stops capture and flushes remaining active flow sessions."""
        if not self.is_running:
            return self.get_stats()

        self.is_running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.warning(f"Error stopping sniffer: {e}")

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

        stats = self.get_stats()
        logger.info(f"Live capture terminated. Final stats: {stats}")
        return stats

    def get_stats(self) -> Dict[str, Any]:
        """Returns capture operational metrics including queue pressure."""
        return {
            "is_running": self.is_running,
            "total_captured": self.total_captured,
            "dropped_packets": self.dropped_packets,
            "queue_size": self.packet_queue.qsize(),
            "max_queue_size": self.max_queue_size,
            "queue_pressure_pct": (self.packet_queue.qsize() / self.max_queue_size) * 100.0,
            "active_sessions_count": len(self.tracker.active_sessions),
        }

    def _process_queue_worker(
        self, flow_callback: Optional[Callable[[BidirectionalFlow], None]]
    ) -> None:
        """Background thread consuming packets and building bidirectional sessions."""
        packet_idx = 0
        prov = ProvenanceMetadata(
            source_file_hash=compute_sha256(f"live_capture_{time.time()}"),
            extraction_config_hash=compute_sha256(f"bpf_{self.bpf_filter}"),
            start_timestamp=time.time(),
            end_timestamp=time.time(),
            provenance_reference=f"interface:{self.interface or 'default'}",
        )

        while self.is_running or not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            packet_idx += 1
            parsed = self.parser.extract_packet_observation(pkt, packet_idx, prov)
            if parsed:
                obs, raw_src, raw_dst = parsed
                completed = self.tracker.process_packet(obs, raw_src, raw_dst, prov)
                if completed and flow_callback:
                    flow_callback(completed)

        # Final flush on stop
        final_flows = self.tracker.flush_all(prov)
        if flow_callback:
            for f in final_flows:
                flow_callback(f)
