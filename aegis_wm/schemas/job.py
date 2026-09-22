"""Schema for analysis job tracking."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class JobStatusEnum(str, Enum):
    PENDING = "pending"
    INGESTING = "ingesting"
    WINDOWING = "windowing"
    FORECASTING = "forecasting"
    EXPLAINING = "explaining"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisJob(BaseModel):
    """Job record representing an analysis lifecycle."""

    job_id: str
    filename: str
    file_type: str = Field(..., description="'pcap', 'pcapng', 'csv'")
    file_size_bytes: int
    source_file_sha256: str
    status: JobStatusEnum = JobStatusEnum.PENDING
    progress_percent: float = 0.0
    status_message: str = "Initialized"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Telemetry Extraction Stats
    total_packets_parsed: int = 0
    total_flows_extracted: int = 0
    total_windows_generated: int = 0
    total_alerts_generated: int = 0

    # Paths to Versioned Artifacts
    parquet_flow_path: Optional[str] = None
    parquet_state_path: Optional[str] = None
    report_pdf_path: Optional[str] = None
    error_details: Optional[str] = None
