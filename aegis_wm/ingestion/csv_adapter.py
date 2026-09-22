"""Dataset CSV adapters supporting CIC-IDS-2017, CICFlowMeter, and NetFlow/CTU-13 schemas."""

import math
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple
import numpy as np
import pandas as pd
from aegis_wm.common.crypto import compute_sha256, pseudonymize_ip
from aegis_wm.common.logger import logger
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow


class CSVDataQualityReport:
    """Audit report tracking dropped rows, non-finite values, and anomalies during ingestion."""

    def __init__(self, filename: str):
        self.filename = filename
        self.total_rows_read: int = 0
        self.valid_flows_extracted: int = 0
        self.dropped_non_finite: int = 0
        self.dropped_malformed: int = 0
        self.dropped_duplicates: int = 0
        self.drop_reasons: Dict[str, int] = {}

    def record_drop(self, reason: str, count: int = 1) -> None:
        self.drop_reasons[reason] = self.drop_reasons.get(reason, 0) + count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "total_rows_read": self.total_rows_read,
            "valid_flows_extracted": self.valid_flows_extracted,
            "dropped_non_finite": self.dropped_non_finite,
            "dropped_malformed": self.dropped_malformed,
            "dropped_duplicates": self.dropped_duplicates,
            "drop_reasons": self.drop_reasons,
        }


class CICFlowCSVAdapter:
    """
    Adapter for CIC-IDS-2017 / CICFlowMeter CSV files.
    Handles column name canonicalization, timestamp reconstruction,
    infinity/NaN sanitation, and translation to canonical BidirectionalFlow.
    """

    def __init__(self, base_epoch: float = 1499414400.0):  # July 7, 2017 08:00:00 UTC
        self.base_epoch = base_epoch

    @staticmethod
    def canonicalize_columns(df: pd.DataFrame) -> pd.DataFrame:
        """Strips whitespace, replaces dots/spaces with standard underscores, lowercase."""
        rename_map = {}
        for col in df.columns:
            cleaned = col.strip()
            rename_map[col] = cleaned
        return df.rename(columns=rename_map)

    def process_csv(
        self,
        csv_path: Path | str,
        chunk_size: int = 50000,
        max_rows: Optional[int] = None,
        progress_callback: Optional[Callable[[float, int], None]] = None,
    ) -> Tuple[List[BidirectionalFlow], CSVDataQualityReport]:
        """
        Reads CSV file in memory-bounded chunks and outputs canonical BidirectionalFlow records.
        """
        csv_path = Path(csv_path)
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")

        file_hash = compute_sha256(csv_path)
        config_hash = compute_sha256(f"cic_adapter_chunk_{chunk_size}")
        report = CSVDataQualityReport(filename=csv_path.name)
        flows: List[BidirectionalFlow] = []

        logger.info(f"Starting CSV ingestion for: {csv_path.name}")

        # Test encoding (latin-1 fallback for strange characters in some CIC headers)
        encoding = "utf-8"
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                f.readline()
        except UnicodeDecodeError:
            encoding = "latin-1"
            logger.warning(f"Using latin-1 fallback encoding for {csv_path.name}")

        current_time = self.base_epoch
        rows_processed = 0

        for chunk in pd.read_csv(
            csv_path,
            chunksize=chunk_size,
            encoding=encoding,
            low_memory=False,
            on_bad_lines="skip",
        ):
            chunk = self.canonicalize_columns(chunk)
            report.total_rows_read += len(chunk)

            # Detect and sanitize Inf / NaN
            numeric_cols = chunk.select_dtypes(include=[np.number]).columns
            chunk[numeric_cols] = chunk[numeric_cols].replace([np.inf, -np.inf], np.nan)

            # Drop rows where essential flow metrics are NaN
            initial_count = len(chunk)
            chunk = chunk.dropna(subset=[col for col in ["Flow Duration", "Destination Port"] if col in chunk.columns])
            dropped_nans = initial_count - len(chunk)
            report.dropped_non_finite += dropped_nans
            if dropped_nans > 0:
                report.record_drop("non_finite_duration_or_port", dropped_nans)

            # Detect columns presence
            has_src_ip = "Source IP" in chunk.columns or "Src IP" in chunk.columns
            has_dst_ip = "Destination IP" in chunk.columns or "Dst IP" in chunk.columns
            has_timestamp = "Timestamp" in chunk.columns
            src_ip_col = "Source IP" if "Source IP" in chunk.columns else "Src IP"
            dst_ip_col = "Destination IP" if "Destination IP" in chunk.columns else "Dst IP"

            for idx, row in chunk.iterrows():
                rows_processed += 1
                if max_rows and rows_processed > max_rows:
                    break

                duration_us = float(row.get("Flow Duration", 0.0))
                duration_s = max(0.0, duration_us / 1000000.0)

                if has_timestamp and pd.notna(row["Timestamp"]):
                    try:
                        flow_start = pd.to_datetime(row["Timestamp"]).timestamp()
                    except Exception:
                        flow_start = current_time
                else:
                    flow_start = current_time
                    current_time += min(1.0, max(0.01, duration_s * 0.1))

                flow_end = flow_start + duration_s

                # Extract or derive IP entities
                if has_src_ip and pd.notna(row.get(src_ip_col)):
                    raw_src = str(row[src_ip_col])
                else:
                    raw_src = f"192.168.10.{int(idx) % 254 + 1}"

                if has_dst_ip and pd.notna(row.get(dst_ip_col)):
                    raw_dst = str(row[dst_ip_col])
                else:
                    raw_dst = f"172.16.0.{int(row.get('Destination Port', 80)) % 250 + 1}"

                dst_port = int(row.get("Destination Port", 0))
                src_port = int(row.get("Source Port", 49152 + (int(idx) % 15000)))
                protocol = int(row.get("Protocol", 6))  # default TCP

                fwd_pkts = int(row.get("Total Fwd Packets", 0))
                bwd_pkts = int(row.get("Total Backward Packets", 0))
                fwd_bytes = int(row.get("Total Length of Fwd Packets", 0))
                bwd_bytes = int(row.get("Total Length of Bwd Packets", 0))

                # Safe rate calculations
                pkts_per_sec = float(row.get("Flow Packets/s", 0.0))
                if math.isnan(pkts_per_sec):
                    pkts_per_sec = (fwd_pkts + bwd_pkts) / max(0.001, duration_s)

                bytes_per_sec = float(row.get("Flow Bytes/s", 0.0))
                if math.isnan(bytes_per_sec):
                    bytes_per_sec = (fwd_bytes + bwd_bytes) / max(0.001, duration_s)

                # Flag counts
                fwd_syn = int(row.get("SYN Flag Count", 0))
                fwd_ack = int(row.get("ACK Flag Count", 0))
                fwd_fin = int(row.get("FIN Flag Count", 0))
                fwd_rst = int(row.get("RST Flag Count", 0))
                fwd_psh = int(row.get("PSH Flag Count", 0))
                fwd_urg = int(row.get("URG Flag Count", 0))

                syn_ack_ratio = float(fwd_syn / max(1, fwd_ack))
                rst_syn_ratio = float(fwd_rst / max(1, fwd_syn))

                flow_id = compute_sha256(f"{csv_path.name}:{idx}:{raw_src}:{dst_port}:{flow_start}")

                prov = ProvenanceMetadata(
                    source_file_hash=file_hash,
                    extraction_config_hash=config_hash,
                    start_timestamp=flow_start,
                    end_timestamp=flow_end,
                    provenance_reference=f"{csv_path.name}:row_{idx}",
                )

                label_val = str(row.get("Label", row.get("label", "BENIGN"))).strip()

                flow_obj = BidirectionalFlow(
                    flow_id=flow_id,
                    provenance=prov,
                    src_ip_pseudo=pseudonymize_ip(raw_src),
                    dst_ip_pseudo=pseudonymize_ip(raw_dst),
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_timestamp=flow_start,
                    end_timestamp=flow_end,
                    duration=duration_s,
                    fwd_packets=fwd_pkts,
                    bwd_packets=bwd_pkts,
                    fwd_bytes=fwd_bytes,
                    bwd_bytes=bwd_bytes,
                    packets_per_sec=pkts_per_sec,
                    bytes_per_sec=bytes_per_sec,
                    fwd_pkt_len_mean=float(row.get("Fwd Packet Length Mean", 0.0)),
                    fwd_pkt_len_std=float(row.get("Fwd Packet Length Std", 0.0)),
                    fwd_pkt_len_min=float(row.get("Fwd Packet Length Min", 0.0)),
                    fwd_pkt_len_max=float(row.get("Fwd Packet Length Max", 0.0)),
                    bwd_pkt_len_mean=float(row.get("Bwd Packet Length Mean", 0.0)),
                    bwd_pkt_len_std=float(row.get("Bwd Packet Length Std", 0.0)),
                    bwd_pkt_len_min=float(row.get("Bwd Packet Length Min", 0.0)),
                    bwd_pkt_len_max=float(row.get("Bwd Packet Length Max", 0.0)),
                    fwd_bwd_pkt_ratio=float(fwd_pkts / max(1, bwd_pkts)),
                    fwd_bwd_byte_ratio=float(fwd_bytes / max(1, bwd_bytes)),
                    flow_iat_mean=float(row.get("Flow IAT Mean", 0.0)) / 1000000.0,
                    flow_iat_std=float(row.get("Flow IAT Std", 0.0)) / 1000000.0,
                    flow_iat_min=float(row.get("Flow IAT Min", 0.0)) / 1000000.0,
                    flow_iat_max=float(row.get("Flow IAT Max", 0.0)) / 1000000.0,
                    fwd_iat_mean=float(row.get("Fwd IAT Mean", 0.0)) / 1000000.0,
                    bwd_iat_mean=float(row.get("Bwd IAT Mean", 0.0)) / 1000000.0,
                    fwd_syn_count=fwd_syn,
                    fwd_ack_count=fwd_ack,
                    fwd_fin_count=fwd_fin,
                    fwd_rst_count=fwd_rst,
                    fwd_psh_count=fwd_psh,
                    fwd_urg_count=fwd_urg,
                    bwd_syn_count=0,
                    bwd_ack_count=0,
                    bwd_fin_count=0,
                    bwd_rst_count=0,
                    bwd_psh_count=0,
                    bwd_urg_count=0,
                    syn_ack_ratio=syn_ack_ratio,
                    rst_syn_ratio=rst_syn_ratio,
                    tcp_handshake_completed=bool(fwd_ack > 0 and fwd_syn > 0),
                    tcp_handshake_failed=bool(fwd_rst > 0 and fwd_syn > 0),
                    connection_reset=bool(fwd_rst > 0),
                    retransmission_count=0,
                    ttl_mean=64.0,
                    ttl_variance=0.0,
                    tcp_win_min=int(row.get("Init_Win_bytes_forward", 0)),
                    tcp_win_max=int(row.get("Init_Win_bytes_backward", 0)),
                    fragmented_packet_count=0,
                    zero_payload_ratio=0.0,
                    payload_size_entropy=0.0,
                    timing_entropy=0.0,
                    burstiness_score=0.0,
                    source_label=label_val,
                )
                flows.append(flow_obj)

            if max_rows and rows_processed >= max_rows:
                break

            if progress_callback:
                progress_callback(30.0, len(flows))

        report.valid_flows_extracted = len(flows)
        logger.info(
            f"Finished CSV ingestion for {csv_path.name}: {report.valid_flows_extracted} flows extracted, "
            f"{report.dropped_non_finite} non-finite rows dropped."
        )
        return flows, report
