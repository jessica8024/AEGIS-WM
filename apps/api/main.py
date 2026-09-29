"""FastAPI Backend Application for AEGIS-WM."""

import asyncio
import json
import os
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import torch
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from aegis_wm.common.config import load_config
from aegis_wm.common.crypto import compute_sha256
from aegis_wm.common.logger import logger
from aegis_wm.detection.policy import DetectionPolicyEngine
from aegis_wm.explainability.evidence import EvidenceLinker
from aegis_wm.forecasting.rollout import RecursiveForecaster
from aegis_wm.ingestion.csv_adapter import CICFlowCSVAdapter
from aegis_wm.ingestion.live_capture import LiveCaptureEngine, UnauthorizedMonitoringError
from aegis_wm.ingestion.replay import TelemetryReplayEngine
from aegis_wm.models.world_model import TemporalWorldModel
from aegis_wm.packet.parser import PcapStreamingParser
from aegis_wm.reporting.pdf_report import ForensicReportGenerator
from aegis_wm.schemas.alert import AlertRecord, AlertStateEnum
from aegis_wm.schemas.job import AnalysisJob, JobStatusEnum
from aegis_wm.schemas.labels import AttackStageEnum
from aegis_wm.state.preprocessor import StateFeatureScaler
from aegis_wm.state.sequence_builder import SequenceBuilder
from aegis_wm.state.window_aggregator import WindowStateAggregator
from aegis_wm.storage.sqlite import SQLiteMetadataStore
from aegis_wm.storage.telemetry import TelemetryStore

app = FastAPI(
    title="AEGIS-WM API",
    description="Anticipatory Enterprise Graph Intelligence System using Network World Models",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global services & stores
config = load_config("configs/system.yaml")
meta_store = SQLiteMetadataStore(db_path="data/aegis_metadata.db")
tel_store = TelemetryStore(base_dir="data")
report_gen = ForensicReportGenerator(output_dir="reports")
policy_engine = DetectionPolicyEngine(metadata_store=meta_store, min_persistence_windows=1)
live_engine = LiveCaptureEngine()

# In-memory runtime cache for fast interactive frontend querying
runtime_trajectories: Dict[str, Any] = {}
runtime_explanations: Dict[str, Any] = {}
runtime_windows: Dict[str, List[Any]] = {}

# Live capture flow buffer
live_captured_flows: List[Any] = []

def _on_live_flow(flow: Any):
    live_captured_flows.append(flow)

# Deterministic Replay Global State
replay_state: Dict[str, Any] = {
    "is_running": False,
    "job_id": None,
    "speed": 1.0,
    "total_flows": 0,
    "replayed_flows": 0,
    "current_timestamp": 0.0,
}
active_replay_engine: Optional[TelemetryReplayEngine] = None
replay_thread: Optional[threading.Thread] = None


# --- Model Management Helper ---
def get_or_load_model() -> Tuple[TemporalWorldModel, StateFeatureScaler]:
    """Loads baseline world model and fitted scaler, or initializes defaults."""
    scaler_path = Path("models/state_scaler.json")
    if scaler_path.exists():
        scaler = StateFeatureScaler.load_from_file(scaler_path)
    else:
        scaler = StateFeatureScaler()
        scaler.fit(torch.randn(10, 12, 36))

    model = TemporalWorldModel(
        feature_dim=36,
        d_model=128,
        latent_dim=64,
        num_layers=2,
        num_heads=4,
        num_stages=9,
        context_length=12,
        forecast_horizon=6,
    )
    ckpt_path = Path("models/aegis_world_model_base.safetensors")
    if ckpt_path.exists():
        try:
            from safetensors.torch import load_file
            model.load_state_dict(load_file(str(ckpt_path)))
        except Exception as e:
            logger.warning(f"Could not load checkpoint weights: {e}")

    model.eval()
    return model, scaler


# --- Request/Response Models ---
class CaptureStartRequest(BaseModel):
    interface: Optional[str] = None
    bpf_filter: str = ""
    monitoring_authorized: bool = Field(
        ...,
        description="Mandatory legal acknowledgement that the operator has explicit permission to monitor.",
    )


class ReplayRequest(BaseModel):
    analysis_id: str
    speed_multiplier: float = 1.0


class AlertAcknowledgeRequest(BaseModel):
    analyst_name: str
    notes: Optional[str] = None
    new_state: AlertStateEnum = AlertStateEnum.ACKNOWLEDGED


# =====================================================================
# API Endpoints
# =====================================================================

@app.get("/api/v1/health")
def health_check():
    """System health check and hardware capability discovery."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cuda_available": torch.cuda.is_available(),
        "device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU",
        "version": "0.1.0",
    }


@app.get("/api/v1/system/capabilities")
def system_capabilities():
    """Returns supported ingestion modes, models, and policy thresholds."""
    return {
        "supported_input_modes": ["csv", "pcap", "pcapng", "offline_replay", "authorized_live_capture"],
        "max_upload_size_mb": 500,
        "default_window_size_seconds": config.windowing.window_size_seconds,
        "context_length_windows": config.windowing.context_length,
        "forecast_horizon_windows": config.windowing.forecast_horizon,
        "attack_stages": [
            {"id": int(s), "name": AttackStageEnum.get_display_name(int(s))}
            for s in AttackStageEnum
        ],
        "policy_thresholds": {
            "warning": config.policy.risk_threshold_warning,
            "critical": config.policy.risk_threshold_critical,
            "max_uncertainty": config.policy.max_uncertainty_threshold,
        },
    }


@app.post("/api/v1/analyses")
async def upload_analysis_file(file: UploadFile = File(...)):
    """Uploads a network telemetry file (PCAP, PCAPNG, or CSV) for analysis."""
    safe_name = Path(file.filename or "upload").name
    ext = safe_name.split(".")[-1].lower()
    if ext not in {"pcap", "pcapng", "csv"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '.{ext}'. Supported formats: .pcap, .pcapng, .csv",
        )

    job_id = f"job_{uuid.uuid4().hex[:10]}"
    upload_path = Path("data/raw") / f"{job_id}_{safe_name}"
    upload_path.parent.mkdir(parents=True, exist_ok=True)

    bytes_written = 0
    with open(upload_path, "wb") as buffer:
        while chunk := await file.read(65536):
            buffer.write(chunk)
            bytes_written += len(chunk)

    file_hash = compute_sha256(upload_path)
    job = AnalysisJob(
        job_id=job_id,
        filename=safe_name,
        file_type=ext,
        file_size_bytes=bytes_written,
        source_file_sha256=file_hash,
        status=JobStatusEnum.PENDING,
        status_message="Uploaded successfully. Ready to start.",
    )
    meta_store.save_job(job)
    meta_store.record_audit("FILE_UPLOADED", job_id, details={"filename": safe_name, "size": bytes_written})

    return job


def _execute_analysis_pipeline(job_id: str):
    """Background task executing complete end-to-end analysis pipeline."""
    job = meta_store.get_job(job_id)
    if not job:
        return

    try:
        job.status = JobStatusEnum.INGESTING
        job.started_at = datetime.now(timezone.utc)
        job.progress_percent = 10.0
        job.status_message = "Ingesting telemetry flows..."
        meta_store.save_job(job)

        raw_file = Path("data/raw") / f"{job.job_id}_{job.filename}"

        # 1. Ingestion
        flows = []
        if job.file_type == "csv":
            adapter = CICFlowCSVAdapter()
            flows, _ = adapter.process_csv(raw_file, max_rows=50000)
            job.total_packets_parsed = sum(f.fwd_packets + f.bwd_packets for f in flows)
        else:
            parser = PcapStreamingParser(active_timeout=120.0, inactive_timeout=15.0)
            flows = parser.parse_pcap(raw_file)
            job.total_packets_parsed = sum(f.fwd_packets + f.bwd_packets for f in flows)

        job.total_flows_extracted = len(flows)
        job.progress_percent = 40.0
        job.status = JobStatusEnum.WINDOWING
        job.status_message = f"Extracted {len(flows)} flows. Building 5s temporal states..."
        meta_store.save_job(job)

        # 2. State Windowing
        aggregator = WindowStateAggregator(window_size_seconds=5.0, slide_step_seconds=5.0)
        windows = aggregator.aggregate_flows(flows)
        job.total_windows_generated = len(windows)
        runtime_windows[job_id] = windows

        # Save Parquet artifacts
        flow_pq = tel_store.save_flows_parquet(flows, f"data/processed/{job_id}_flows.parquet")
        state_pq = tel_store.save_states_parquet(windows, f"data/processed/{job_id}_states.parquet")
        job.parquet_flow_path = flow_pq
        job.parquet_state_path = state_pq

        job.progress_percent = 65.0
        job.status = JobStatusEnum.FORECASTING
        job.status_message = "Executing World Model recursive rollout..."
        meta_store.save_job(job)

        # 3. World Model Forecasting
        world_model, scaler = get_or_load_model()
        forecaster = RecursiveForecaster(
            model=world_model, scaler=scaler, forecast_horizon=6, window_duration_seconds=5.0
        )

        seq_builder = SequenceBuilder(context_length=12, forecast_horizon=6)
        sequences = seq_builder.build_sequences(windows)

        # Focus context on peak threat/compromise progression if any attack occurred, else latest windows
        compromised_indices = [i for i, w in enumerate(windows) if w.is_compromised]
        if compromised_indices:
            peak_idx = max(compromised_indices, key=lambda i: (windows[i].packet_rate + windows[i].byte_rate, windows[i].active_flow_count))
            end_idx = min(len(windows), max(12, peak_idx + 6))
            start_idx = max(0, end_idx - 12)
            active_ctx = windows[start_idx:end_idx]
            if len(active_ctx) < 12:
                active_ctx = [active_ctx[0]] * (12 - len(active_ctx)) + active_ctx
        else:
            active_ctx = windows[-12:] if len(windows) >= 12 else (windows + [windows[-1]] * (12 - len(windows)))

        trajectory = forecaster.forecast(active_ctx, analysis_id=job_id, rollout_mode="monte_carlo")
        runtime_trajectories[job_id] = trajectory

        # 4. Explainability & Evidence Linking
        job.progress_percent = 85.0
        job.status = JobStatusEnum.EXPLAINING
        job.status_message = "Linking feature and entity evidence..."
        meta_store.save_job(job)

        evidence_linker = EvidenceLinker(model=world_model, telemetry_store=tel_store, scaler=scaler)
        explanation = evidence_linker.build_explanation(
            trajectory=trajectory,
            context_windows=active_ctx,
            flow_parquet_path=flow_pq,
        )
        runtime_explanations[job_id] = explanation

        # Persist JSON artifacts for persistence across restarts
        try:
            with open(f"data/processed/{job_id}_trajectory.json", "w") as f:
                f.write(trajectory.model_dump_json())
            with open(f"data/processed/{job_id}_explanation.json", "w") as f:
                f.write(explanation.model_dump_json())
        except Exception as pe:
            logger.warning(f"Could not persist JSON artifacts: {pe}")

        # 5. Detection Alerting Policy
        alert = policy_engine.evaluate_forecast(trajectory, explanation, analysis_id=job_id)
        if alert:
            job.total_alerts_generated = 1

        # 6. Generate Forensic PDF Report
        alerts = meta_store.list_alerts(job_id)
        pdf_path = report_gen.generate_report(
            job=job, trajectory=trajectory, explanation=explanation, alerts=alerts
        )
        job.report_pdf_path = str(pdf_path)

        job.status = JobStatusEnum.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.progress_percent = 100.0
        job.status_message = "Analysis complete. Forecasts and evidence ready."
        meta_store.save_job(job)
        meta_store.record_audit("ANALYSIS_COMPLETED", job_id)

    except Exception as e:
        logger.error(f"Pipeline failed for job {job_id}: {e}", exc_info=True)
        job.status = JobStatusEnum.FAILED
        job.status_message = f"Failed: {str(e)}"
        job.error_details = str(e)
        meta_store.save_job(job)


def _execute_pipeline_on_flows(job_id: str, flows: List[Any]):
    """Executes the analysis pipeline on pre-parsed in-memory flows (e.g. from live capture)."""
    job = meta_store.get_job(job_id)
    if not job:
        return

    try:
        job.status = JobStatusEnum.INGESTING
        job.started_at = datetime.now(timezone.utc)
        job.total_packets_parsed = sum(f.fwd_packets + f.bwd_packets for f in flows)
        job.total_flows_extracted = len(flows)
        job.progress_percent = 40.0
        job.status = JobStatusEnum.WINDOWING
        job.status_message = f"Extracted {len(flows)} flows. Building 5s temporal states..."
        meta_store.save_job(job)

        aggregator = WindowStateAggregator(window_size_seconds=5.0, slide_step_seconds=5.0)
        windows = aggregator.aggregate_flows(flows)
        job.total_windows_generated = len(windows)
        runtime_windows[job_id] = windows

        flow_pq = tel_store.save_flows_parquet(flows, f"data/processed/{job_id}_flows.parquet")
        state_pq = tel_store.save_states_parquet(windows, f"data/processed/{job_id}_states.parquet")
        job.parquet_flow_path = flow_pq
        job.parquet_state_path = state_pq

        job.progress_percent = 65.0
        job.status = JobStatusEnum.FORECASTING
        job.status_message = "Executing World Model recursive rollout..."
        meta_store.save_job(job)

        world_model, scaler = get_or_load_model()
        forecaster = RecursiveForecaster(
            model=world_model, scaler=scaler, forecast_horizon=6, window_duration_seconds=5.0
        )
        active_ctx = windows[-12:] if len(windows) >= 12 else (windows + [windows[-1]] * (12 - len(windows)))
        trajectory = forecaster.forecast(active_ctx, analysis_id=job_id, rollout_mode="monte_carlo")
        runtime_trajectories[job_id] = trajectory

        job.progress_percent = 85.0
        job.status = JobStatusEnum.EXPLAINING
        job.status_message = "Linking feature and entity evidence..."
        meta_store.save_job(job)

        evidence_linker = EvidenceLinker(model=world_model, telemetry_store=tel_store, scaler=scaler)
        explanation = evidence_linker.build_explanation(
            trajectory=trajectory,
            context_windows=active_ctx,
            flow_parquet_path=flow_pq,
        )
        runtime_explanations[job_id] = explanation

        try:
            with open(f"data/processed/{job_id}_trajectory.json", "w") as f:
                f.write(trajectory.model_dump_json())
            with open(f"data/processed/{job_id}_explanation.json", "w") as f:
                f.write(explanation.model_dump_json())
        except Exception:
            pass

        alert = policy_engine.evaluate_forecast(trajectory, explanation, analysis_id=job_id)
        if alert:
            job.total_alerts_generated = 1

        alerts = meta_store.list_alerts(job_id)
        pdf_path = report_gen.generate_report(
            job=job, trajectory=trajectory, explanation=explanation, alerts=alerts
        )
        job.report_pdf_path = str(pdf_path)

        job.status = JobStatusEnum.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.progress_percent = 100.0
        job.status_message = "Analysis complete. Forecasts and evidence ready."
        meta_store.save_job(job)
        meta_store.record_audit("ANALYSIS_COMPLETED", job_id)

    except Exception as e:
        logger.error(f"Live pipeline failed for job {job_id}: {e}", exc_info=True)
        job.status = JobStatusEnum.FAILED
        job.status_message = f"Failed: {str(e)}"
        job.error_details = str(e)
        meta_store.save_job(job)


@app.post("/api/v1/analyses/{analysis_id}/start")
def start_analysis(analysis_id: str, background_tasks: BackgroundTasks):
    """Initiates asynchronous analysis pipeline for an uploaded file."""
    job = meta_store.get_job(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    background_tasks.add_task(_execute_analysis_pipeline, analysis_id)
    return {"status": "started", "job_id": analysis_id}


@app.get("/api/v1/analyses/{analysis_id}")
def get_analysis_status(analysis_id: str):
    """Retrieves current job status, progress, and telemetry metrics."""
    job = meta_store.get_job(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return job


@app.get("/api/v1/analyses")
def list_analyses(limit: int = 50):
    """Lists recent analysis jobs."""
    return meta_store.list_jobs(limit=limit)


@app.get("/api/v1/analyses/{analysis_id}/timeline")
def get_analysis_timeline(analysis_id: str):
    """
    Returns dual-timeline payload:
    1. Historical observed windows (timestamps, actual flows, packet rates)
    2. Projected K-step forecast trajectory with 95% uncertainty intervals
    """
    job = meta_store.get_job(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    windows = runtime_windows.get(analysis_id, [])
    trajectory = runtime_trajectories.get(analysis_id)

    # If trajectory not in memory, try loading from disk
    if not trajectory:
        traj_file = Path(f"data/processed/{analysis_id}_trajectory.json")
        if traj_file.exists():
            try:
                with open(traj_file, "r") as f:
                    from aegis_wm.schemas.forecast import ForecastTrajectory
                    trajectory = ForecastTrajectory.model_validate_json(f.read())
                    runtime_trajectories[analysis_id] = trajectory
            except Exception:
                pass

    # Historical observed points
    history = []
    if windows:
        # If there are compromised windows, include history around the compromised windows
        comp_wins = [w for w in windows if w.is_compromised]
        if comp_wins:
            peak_w = max(comp_wins, key=lambda w: (w.packet_rate + w.byte_rate, w.active_flow_count))
            p_idx = windows.index(peak_w)
            h_start = max(0, p_idx - 16)
            h_end = min(len(windows), p_idx + 8)
            hist_windows = windows[h_start:h_end]
        else:
            hist_windows = windows[-24:]

        for w in hist_windows:
            history.append({
                "window_index": w.window_index,
                "timestamp": w.start_timestamp,
                "active_flows": w.active_flow_count,
                "packet_rate": w.packet_rate,
                "byte_rate": w.byte_rate,
                "observed_stage": AttackStageEnum.get_display_name(int(w.ground_truth_stage)),
                "is_compromised": w.is_compromised,
            })

    # Projected future points
    forecast = []
    if trajectory:
        for pt in trajectory.points:
            forecast.append({
                "horizon_step": pt.horizon_step,
                "timestamp": pt.target_timestamp,
                "infiltration_probability": pt.infiltration_probability,
                "uncertainty_lower": pt.uncertainty_lower,
                "uncertainty_upper": pt.uncertainty_upper,
                "predictive_entropy": pt.predictive_entropy,
                "predicted_stage": AttackStageEnum.get_display_name(int(pt.predicted_stage)),
                "stage_probabilities": pt.stage_probabilities,
                "risk_velocity": pt.risk_velocity,
            })

    return {
        "analysis_id": analysis_id,
        "history": history,
        "forecast": forecast,
        "max_risk_in_horizon": trajectory.max_risk_in_horizon if trajectory else 0.0,
        "peak_stage": AttackStageEnum.get_display_name(int(trajectory.peak_stage_predicted)) if trajectory else "Benign",
    }


@app.get("/api/v1/analyses/{analysis_id}/flows")
def get_analysis_flows(
    analysis_id: str,
    limit: int = 50,
    offset: int = 0,
    min_port: Optional[int] = None,
    protocol: Optional[int] = None,
):
    """Returns paginated, filterable raw flow telemetry from versioned Parquet."""
    job = meta_store.get_job(analysis_id)
    if not job or not job.parquet_flow_path:
        return {"flows": [], "total": 0}

    filters = ["1=1"]
    if min_port:
        filters.append(f"dst_port >= {min_port}")
    if protocol:
        filters.append(f"protocol = {protocol}")

    sql_cond = " AND ".join(filters)
    flow_records = tel_store.query_flows(job.parquet_flow_path, sql_filter=sql_cond, limit=limit, offset=offset)
    return {"flows": flow_records, "total": job.total_flows_extracted, "limit": limit, "offset": offset}


@app.get("/api/v1/analyses/{analysis_id}/hosts")
def get_analysis_hosts(analysis_id: str, port: Optional[int] = None):
    """Returns network communication topology and high-risk host profiles."""
    windows = runtime_windows.get(analysis_id, [])
    job = meta_store.get_job(analysis_id)

    nodes = {}
    link_map = {}

    if windows:
        comp_wins = [w for w in windows if w.is_compromised]
        target_windows = comp_wins[:60] + windows[-30:] if comp_wins else (windows if len(windows) <= 100 else windows[-60:])
        for w in target_windows:
            for edge in w.edges:
                if port is not None and edge.dst_port != port:
                    continue
                src = edge.src_host
                dst = edge.dst_host
                if src not in nodes:
                    nodes[src] = {"id": src, "label": src, "flows": 0, "bytes": 0}
                if dst not in nodes:
                    nodes[dst] = {"id": dst, "label": dst, "flows": 0, "bytes": 0}

                nodes[src]["flows"] += edge.flow_count
                nodes[src]["bytes"] += edge.byte_count
                nodes[dst]["flows"] += edge.flow_count
                nodes[dst]["bytes"] += edge.byte_count

                lkey = (src, dst, edge.dst_port, edge.protocol)
                if lkey not in link_map:
                    link_map[lkey] = {
                        "source": src,
                        "target": dst,
                        "protocol": "TCP" if edge.protocol == 6 else ("UDP" if edge.protocol == 17 else str(edge.protocol)),
                        "port": edge.dst_port,
                        "flows": 0,
                        "bytes": 0,
                    }
                link_map[lkey]["flows"] += edge.flow_count
                link_map[lkey]["bytes"] += edge.byte_count
    elif job and job.parquet_flow_path and Path(job.parquet_flow_path).exists():
        sql = f"dst_port = {port}" if port is not None else "1=1"
        try:
            flow_records = tel_store.query_flows(job.parquet_flow_path, sql_filter=sql, limit=1000)
            for r in flow_records:
                src = str(r.get("src_ip_pseudo", ""))
                dst = str(r.get("dst_ip_pseudo", ""))
                p = int(r.get("dst_port", 0))
                proto = int(r.get("protocol", 6))
                bytes_tot = int(r.get("fwd_bytes", 0) + r.get("bwd_bytes", 0))

                if src not in nodes:
                    nodes[src] = {"id": src, "label": src, "flows": 0, "bytes": 0}
                if dst not in nodes:
                    nodes[dst] = {"id": dst, "label": dst, "flows": 0, "bytes": 0}

                nodes[src]["flows"] += 1
                nodes[src]["bytes"] += bytes_tot
                nodes[dst]["flows"] += 1
                nodes[dst]["bytes"] += bytes_tot

                lkey = (src, dst, p, proto)
                if lkey not in link_map:
                    link_map[lkey] = {
                        "source": src,
                        "target": dst,
                        "protocol": "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto)),
                        "port": p,
                        "flows": 0,
                        "bytes": 0,
                    }
                link_map[lkey]["flows"] += 1
                link_map[lkey]["bytes"] += bytes_tot
        except Exception as e:
            logger.warning(f"Could not read flows for topology: {e}")

    if not nodes:
        return {"nodes": [], "links": []}

    top_nodes = sorted(nodes.values(), key=lambda n: n["flows"], reverse=True)[:35]
    top_node_ids = set(n["id"] for n in top_nodes)
    filtered_links = [l for l in link_map.values() if l["source"] in top_node_ids and l["target"] in top_node_ids]

    return {"nodes": top_nodes, "links": filtered_links}


@app.get("/api/v1/analyses/{analysis_id}/forecasts")
def get_forecasts(analysis_id: str):
    """Retrieves full ForecastTrajectory object."""
    trajectory = runtime_trajectories.get(analysis_id)
    if not trajectory:
        traj_file = Path(f"data/processed/{analysis_id}_trajectory.json")
        if traj_file.exists():
            try:
                with open(traj_file, "r") as f:
                    from aegis_wm.schemas.forecast import ForecastTrajectory
                    return ForecastTrajectory.model_validate_json(f.read())
            except Exception:
                pass
        raise HTTPException(status_code=404, detail="No forecast generated yet")
    return trajectory


@app.get("/api/v1/analyses/{analysis_id}/explanations/{forecast_id}")
def get_explanation(analysis_id: str, forecast_id: str):
    """Retrieves full ExplanationResult with feature attributions and supporting flows."""
    exp = runtime_explanations.get(analysis_id)
    if not exp:
        exp_file = Path(f"data/processed/{analysis_id}_explanation.json")
        if exp_file.exists():
            try:
                with open(exp_file, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        raise HTTPException(status_code=404, detail="No explanation generated yet")
    return exp


@app.get("/api/v1/alerts")
def list_alerts(analysis_id: Optional[str] = None):
    """Lists alerts with full audit context."""
    return meta_store.list_alerts(analysis_id=analysis_id)


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str, req: AlertAcknowledgeRequest):
    """Allows analyst to acknowledge alert and attach investigation notes."""
    alerts = meta_store.list_alerts()
    matched = next((a for a in alerts if a.alert_id == alert_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Alert not found")

    matched.state = req.new_state
    matched.acknowledged_by = req.analyst_name
    matched.acknowledged_at = datetime.now(timezone.utc)
    matched.analyst_notes = req.notes
    meta_store.save_alert(matched)
    meta_store.record_audit("ALERT_ACKNOWLEDGED", alert_id, actor=req.analyst_name, details={"notes": req.notes})
    return matched


@app.get("/api/v1/reports/{analysis_id}")
def download_report(analysis_id: str):
    """Downloads forensic analysis PDF report."""
    job = meta_store.get_job(analysis_id)
    if not job or not job.report_pdf_path or not Path(job.report_pdf_path).exists():
        raise HTTPException(status_code=404, detail="Report PDF not generated yet")
    return FileResponse(
        job.report_pdf_path,
        media_type="application/pdf",
        filename=Path(job.report_pdf_path).name,
    )


@app.post("/api/v1/capture/start")
def start_live_capture(req: CaptureStartRequest):
    """Starts authorized live packet capture with explicit operator confirmation."""
    try:
        live_captured_flows.clear()
        live_engine.start(authorization_confirmed=req.monitoring_authorized, flow_callback=_on_live_flow)
        return {"status": "started", "stats": live_engine.get_stats()}
    except UnauthorizedMonitoringError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/capture/stop")
def stop_live_capture(background_tasks: BackgroundTasks, create_analysis: bool = True):
    """Stops live capture, flushes flows, and optionally launches an analysis job."""
    stats = live_engine.stop()
    new_job_id = None
    if create_analysis and live_captured_flows:
        new_job_id = f"live_{int(time.time())}"
        job = AnalysisJob(
            job_id=new_job_id,
            filename=f"Live_Capture_{datetime.now().strftime('%H%M%S')}.pcap",
            file_type="pcap",
            file_size_bytes=sum(f.fwd_bytes + f.bwd_bytes for f in live_captured_flows),
            source_file_sha256=compute_sha256(f"live_{new_job_id}_{len(live_captured_flows)}"),
            status=JobStatusEnum.PENDING,
            status_message="Live capture completed. Launching pipeline...",
        )
        meta_store.save_job(job)
        flows_copy = list(live_captured_flows)
        background_tasks.add_task(_execute_pipeline_on_flows, new_job_id, flows_copy)

    return {"status": "stopped", "stats": stats, "analysis_id": new_job_id}


@app.get("/api/v1/capture/stats")
def capture_stats():
    """Returns queue pressure and packet statistics for live capture."""
    return live_engine.get_stats()


class ReplayStartPayload(BaseModel):
    job_id: str
    speed_multiplier: float = 1.0


@app.post("/api/v1/replay/start")
def start_replay(payload: ReplayStartPayload):
    """Starts deterministic replay simulation for an analyzed telemetry dataset."""
    global active_replay_engine, replay_thread, replay_state
    job = meta_store.get_job(payload.job_id)
    if not job or not job.parquet_flow_path or not Path(job.parquet_flow_path).exists():
        raise HTTPException(status_code=404, detail="Analyzed telemetry dataset not found for replay")

    if replay_state["is_running"] and active_replay_engine:
        active_replay_engine.stop()

    active_replay_engine = TelemetryReplayEngine(speed_multiplier=payload.speed_multiplier)
    replay_state.update({
        "is_running": True,
        "job_id": payload.job_id,
        "speed": payload.speed_multiplier,
        "total_flows": job.total_flows_extracted,
        "replayed_flows": 0,
        "current_timestamp": 0.0,
    })

    def _run_replay():
        try:
            flow_records = tel_store.query_flows(job.parquet_flow_path, limit=2000)
            for r in flow_records:
                if not replay_state["is_running"]:
                    break
                replay_state["replayed_flows"] += 1
                replay_state["current_timestamp"] = float(r.get("start_timestamp", time.time()))
                time.sleep(max(0.005, 0.05 / max(0.1, payload.speed_multiplier)))
        finally:
            replay_state["is_running"] = False

    replay_thread = threading.Thread(target=_run_replay, daemon=True)
    replay_thread.start()
    return {"status": "started", "replay": replay_state}


@app.post("/api/v1/replay/stop")
def stop_replay():
    """Stops active deterministic replay simulation."""
    global active_replay_engine, replay_state
    if active_replay_engine:
        active_replay_engine.stop()
    replay_state["is_running"] = False
    return {"status": "stopped", "replay": replay_state}


@app.get("/api/v1/replay/status")
def get_replay_status():
    """Returns current replay simulation state."""
    return replay_state


@app.get("/api/v1/models")
def list_models():
    """Lists available model checkpoints."""
    models_dir = Path("models")
    ckpts = []
    if models_dir.exists():
        for f in models_dir.glob("*.safetensors"):
            ckpts.append({
                "model_name": f.stem,
                "file_path": str(f),
                "sha256": compute_sha256(f),
                "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
            })
    return ckpts


@app.get("/api/v1/evaluations/benchmarks")
def get_benchmarks():
    """Returns baseline and world model benchmark metrics from reports."""
    bench_file = Path("reports/baselines_benchmark.json")
    if bench_file.exists():
        with open(bench_file, "r") as f:
            data = json.load(f)
        return data
    raise HTTPException(status_code=404, detail="Benchmark reports not found")


# Mount built React/TypeScript analyst console SPA if dist exists
dist_dir = Path("apps/analyst-console/dist")
if dist_dir.exists():
    app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="static_frontend")
