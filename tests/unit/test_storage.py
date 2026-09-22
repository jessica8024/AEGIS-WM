"""Unit tests for SQLite and Parquet storage components."""

import tempfile
from pathlib import Path
import pytest
from aegis_wm.schemas.alert import AlertRecord, AlertSeverityEnum, AlertStateEnum
from aegis_wm.schemas.base import ProvenanceMetadata
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.schemas.job import AnalysisJob, JobStatusEnum
from aegis_wm.schemas.labels import AttackStageEnum
from aegis_wm.storage.sqlite import SQLiteMetadataStore
from aegis_wm.storage.telemetry import TelemetryStore


def test_sqlite_job_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_aegis.db"
        store = SQLiteMetadataStore(db_path=db_path)

        job = AnalysisJob(
            job_id="job_001",
            filename="capture.pcap",
            file_type="pcap",
            file_size_bytes=10240,
            source_file_sha256="c" * 64,
            status=JobStatusEnum.PENDING,
        )
        store.save_job(job)

        fetched = store.get_job("job_001")
        assert fetched is not None
        assert fetched.filename == "capture.pcap"
        assert fetched.status == JobStatusEnum.PENDING

        job.status = JobStatusEnum.COMPLETED
        job.progress_percent = 100.0
        job.total_flows_extracted = 42
        store.save_job(job)

        updated = store.get_job("job_001")
        assert updated.status == JobStatusEnum.COMPLETED
        assert updated.total_flows_extracted == 42


def test_sqlite_alerts_and_audit():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_aegis.db"
        store = SQLiteMetadataStore(db_path=db_path)

        store.record_audit(action="TEST_ACTION", target_resource="SYS_CONFIG", actor="admin")

        alert = AlertRecord(
            alert_id="alt_1",
            analysis_id="job_001",
            forecast_id="fc_1",
            severity=AlertSeverityEnum.CRITICAL,
            state=AlertStateEnum.ACTIVE,
            forecast_horizon_seconds=30.0,
            forecast_horizon_steps=6,
            infiltration_probability=0.88,
            uncertainty_range=0.12,
            predicted_stage=AttackStageEnum.LATERAL_MOVEMENT,
            primary_host_pseudo="host_abcd1234ef56",
            top_indicator_features=["dst_port_entropy", "scan_activity_indicator"],
            supporting_flow_count=5,
            policy_rule_triggered="POLICY_CRITICAL_MULTI_STEP",
        )
        store.save_alert(alert)

        alerts = store.list_alerts("job_001")
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverityEnum.CRITICAL
        assert alerts[0].top_indicator_features == ["dst_port_entropy", "scan_activity_indicator"]


def test_telemetry_parquet_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        tel_store = TelemetryStore(base_dir=tmpdir)
        meta = ProvenanceMetadata(
            source_file_hash="x" * 64,
            extraction_config_hash="y" * 64,
            start_timestamp=100.0,
            end_timestamp=105.0,
            provenance_reference="sample.pcap",
        )
        flow = BidirectionalFlow(
            flow_id="f_roundtrip",
            provenance=meta,
            src_ip_pseudo="host_aaa111",
            dst_ip_pseudo="host_bbb222",
            src_port=1000,
            dst_port=80,
            protocol=6,
            start_timestamp=100.0,
            end_timestamp=105.0,
            duration=5.0,
            fwd_packets=2,
            bwd_packets=2,
            fwd_bytes=100,
            bwd_bytes=200,
            packets_per_sec=0.8,
            bytes_per_sec=60.0,
        )

        pq_path = Path(tmpdir) / "test_flows.parquet"
        tel_store.save_flows_parquet([flow], pq_path)
        assert pq_path.exists()

        df = tel_store.load_flows_dataframe(pq_path)
        assert len(df) == 1
        assert df.iloc[0]["flow_id"] == "f_roundtrip"
        assert df.iloc[0]["protocol"] == 6
