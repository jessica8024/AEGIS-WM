"""SQLite metadata and audit store for AEGIS-WM."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from aegis_wm.schemas.alert import AlertRecord, AlertSeverityEnum, AlertStateEnum
from aegis_wm.schemas.job import AnalysisJob, JobStatusEnum


class SQLiteMetadataStore:
    """Manages transactional metadata, alerts, and audit records in SQLite."""

    def __init__(self, db_path: Path | str = "data/aegis_metadata.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes tables if they do not exist."""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Jobs table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                job_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                source_file_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                progress_percent REAL NOT NULL DEFAULT 0.0,
                status_message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                total_packets_parsed INTEGER NOT NULL DEFAULT 0,
                total_flows_extracted INTEGER NOT NULL DEFAULT 0,
                total_windows_generated INTEGER NOT NULL DEFAULT 0,
                total_alerts_generated INTEGER NOT NULL DEFAULT 0,
                parquet_flow_path TEXT,
                parquet_state_path TEXT,
                report_pdf_path TEXT,
                error_details TEXT
            )
            """)

            # Alerts table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL,
                forecast_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                state TEXT NOT NULL,
                forecast_horizon_seconds REAL NOT NULL,
                forecast_horizon_steps INTEGER NOT NULL,
                infiltration_probability REAL NOT NULL,
                uncertainty_range REAL NOT NULL,
                predicted_stage INTEGER NOT NULL,
                primary_host_pseudo TEXT,
                top_indicator_features TEXT NOT NULL,
                supporting_flow_count INTEGER NOT NULL,
                policy_rule_triggered TEXT NOT NULL,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                analyst_notes TEXT,
                FOREIGN KEY (analysis_id) REFERENCES analysis_jobs(job_id)
            )
            """)

            # Audit log table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                details TEXT NOT NULL
            )
            """)

            conn.commit()

    def record_audit(self, action: str, target_resource: str, actor: str = "system", details: Optional[Dict[str, Any]] = None) -> None:
        """Appends an immutable entry to the audit log."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs (timestamp, actor, action, target_resource, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    actor,
                    action,
                    target_resource,
                    json.dumps(details or {}),
                ),
            )
            conn.commit()

    def save_job(self, job: AnalysisJob) -> None:
        """Inserts or updates an analysis job record."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO analysis_jobs (
                    job_id, filename, file_type, file_size_bytes, source_file_sha256,
                    status, progress_percent, status_message, created_at, started_at,
                    completed_at, total_packets_parsed, total_flows_extracted,
                    total_windows_generated, total_alerts_generated, parquet_flow_path,
                    parquet_state_path, report_pdf_path, error_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status=excluded.status,
                    progress_percent=excluded.progress_percent,
                    status_message=excluded.status_message,
                    started_at=excluded.started_at,
                    completed_at=excluded.completed_at,
                    total_packets_parsed=excluded.total_packets_parsed,
                    total_flows_extracted=excluded.total_flows_extracted,
                    total_windows_generated=excluded.total_windows_generated,
                    total_alerts_generated=excluded.total_alerts_generated,
                    parquet_flow_path=excluded.parquet_flow_path,
                    parquet_state_path=excluded.parquet_state_path,
                    report_pdf_path=excluded.report_pdf_path,
                    error_details=excluded.error_details
                """,
                (
                    job.job_id,
                    job.filename,
                    job.file_type,
                    job.file_size_bytes,
                    job.source_file_sha256,
                    job.status.value,
                    job.progress_percent,
                    job.status_message,
                    job.created_at.isoformat(),
                    job.started_at.isoformat() if job.started_at else None,
                    job.completed_at.isoformat() if job.completed_at else None,
                    job.total_packets_parsed,
                    job.total_flows_extracted,
                    job.total_windows_generated,
                    job.total_alerts_generated,
                    job.parquet_flow_path,
                    job.parquet_state_path,
                    job.report_pdf_path,
                    job.error_details,
                ),
            )
            conn.commit()

    def get_job(self, job_id: str) -> Optional[AnalysisJob]:
        """Retrieves a job by ID."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM analysis_jobs WHERE job_id = ?", (job_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return AnalysisJob(
                job_id=row["job_id"],
                filename=row["filename"],
                file_type=row["file_type"],
                file_size_bytes=row["file_size_bytes"],
                source_file_sha256=row["source_file_sha256"],
                status=JobStatusEnum(row["status"]),
                progress_percent=row["progress_percent"],
                status_message=row["status_message"],
                created_at=datetime.fromisoformat(row["created_at"]),
                started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
                completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                total_packets_parsed=row["total_packets_parsed"],
                total_flows_extracted=row["total_flows_extracted"],
                total_windows_generated=row["total_windows_generated"],
                total_alerts_generated=row["total_alerts_generated"],
                parquet_flow_path=row["parquet_flow_path"],
                parquet_state_path=row["parquet_state_path"],
                report_pdf_path=row["report_pdf_path"],
                error_details=row["error_details"],
            )

    def list_jobs(self, limit: int = 50) -> List[AnalysisJob]:
        """Lists recent jobs."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM analysis_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            jobs = []
            for row in rows:
                jobs.append(
                    AnalysisJob(
                        job_id=row["job_id"],
                        filename=row["filename"],
                        file_type=row["file_type"],
                        file_size_bytes=row["file_size_bytes"],
                        source_file_sha256=row["source_file_sha256"],
                        status=JobStatusEnum(row["status"]),
                        progress_percent=row["progress_percent"],
                        status_message=row["status_message"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
                        completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                        total_packets_parsed=row["total_packets_parsed"],
                        total_flows_extracted=row["total_flows_extracted"],
                        total_windows_generated=row["total_windows_generated"],
                        total_alerts_generated=row["total_alerts_generated"],
                        parquet_flow_path=row["parquet_flow_path"],
                        parquet_state_path=row["parquet_state_path"],
                        report_pdf_path=row["report_pdf_path"],
                        error_details=row["error_details"],
                    )
                )
            return jobs

    def save_alert(self, alert: AlertRecord) -> None:
        """Saves an alert."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (
                    alert_id, analysis_id, forecast_id, created_at, severity, state,
                    forecast_horizon_seconds, forecast_horizon_steps, infiltration_probability,
                    uncertainty_range, predicted_stage, primary_host_pseudo,
                    top_indicator_features, supporting_flow_count, policy_rule_triggered,
                    acknowledged_by, acknowledged_at, analyst_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    state=excluded.state,
                    acknowledged_by=excluded.acknowledged_by,
                    acknowledged_at=excluded.acknowledged_at,
                    analyst_notes=excluded.analyst_notes
                """,
                (
                    alert.alert_id,
                    alert.analysis_id,
                    alert.forecast_id,
                    alert.created_at.isoformat(),
                    alert.severity.value,
                    alert.state.value,
                    alert.forecast_horizon_seconds,
                    alert.forecast_horizon_steps,
                    alert.infiltration_probability,
                    alert.uncertainty_range,
                    int(alert.predicted_stage),
                    alert.primary_host_pseudo,
                    json.dumps(alert.top_indicator_features),
                    alert.supporting_flow_count,
                    alert.policy_rule_triggered,
                    alert.acknowledged_by,
                    alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                    alert.analyst_notes,
                ),
            )
            conn.commit()

    def list_alerts(self, analysis_id: Optional[str] = None, limit: int = 100) -> List[AlertRecord]:
        """Lists alerts optionally filtered by analysis_id."""
        with self._connection() as conn:
            cursor = conn.cursor()
            if analysis_id:
                cursor.execute(
                    "SELECT * FROM alerts WHERE analysis_id = ? ORDER BY created_at DESC LIMIT ?",
                    (analysis_id, limit),
                )
            else:
                cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            alerts = []
            for row in rows:
                alerts.append(
                    AlertRecord(
                        alert_id=row["alert_id"],
                        analysis_id=row["analysis_id"],
                        forecast_id=row["forecast_id"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        severity=AlertSeverityEnum(row["severity"]),
                        state=AlertStateEnum(row["state"]),
                        forecast_horizon_seconds=row["forecast_horizon_seconds"],
                        forecast_horizon_steps=row["forecast_horizon_steps"],
                        infiltration_probability=row["infiltration_probability"],
                        uncertainty_range=row["uncertainty_range"],
                        predicted_stage=row["predicted_stage"],
                        primary_host_pseudo=row["primary_host_pseudo"],
                        top_indicator_features=json.loads(row["top_indicator_features"]),
                        supporting_flow_count=row["supporting_flow_count"],
                        policy_rule_triggered=row["policy_rule_triggered"],
                        acknowledged_by=row["acknowledged_by"],
                        acknowledged_at=datetime.fromisoformat(row["acknowledged_at"])
                        if row["acknowledged_at"]
                        else None,
                        analyst_notes=row["analyst_notes"],
                    )
                )
            return alerts
