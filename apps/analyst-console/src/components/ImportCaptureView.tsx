import React, { useState, useRef, useEffect } from "react";
import {
  Upload,
  Play,
  Square,
  FileText,
  Activity,
  AlertTriangle,
  CheckCircle,
  Radio,
  Clock,
  Cpu,
  Layers,
  Shield,
  RefreshCw,
  Zap,
  Gauge,
  CheckCircle2,
} from "lucide-react";
import { AnalysisJob, CaptureStats, ReplayStatus } from "../types";
import {
  uploadTelemetryFile,
  startAnalysis,
  startLiveCapture,
  stopLiveCapture,
  fetchCaptureStats,
  startReplay,
  stopReplay,
  fetchReplayStatus,
} from "../api";

interface ImportCaptureViewProps {
  onAnalysisCreated: (job: AnalysisJob) => void;
  analyses: AnalysisJob[];
  onRefreshAnalyses: () => void;
}

export const ImportCaptureView: React.FC<ImportCaptureViewProps> = ({
  onAnalysisCreated,
  analyses,
  onRefreshAnalyses,
}) => {
  // File upload state
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Live capture state
  const [ifaceName, setIfaceName] = useState("");
  const [bpfFilter, setBpfFilter] = useState("tcp or udp");
  const [legalAuthorized, setLegalAuthorized] = useState(false);
  const [captureActive, setCaptureActive] = useState(false);
  const [captureStats, setCaptureStats] = useState<CaptureStats | null>(null);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [stoppingCapture, setStoppingCapture] = useState(false);

  // Replay state
  const [replaySpeed, setReplaySpeed] = useState<number>(1.0);
  const [replayJobId, setReplayJobId] = useState<string>("");
  const [replayStatus, setReplayStatus] = useState<ReplayStatus | null>(null);
  const [replayError, setReplayError] = useState<string | null>(null);
  const [replayLoading, setReplayLoading] = useState(false);

  // Initial replay status and analyses default
  useEffect(() => {
    fetchReplayStatus()
      .then((st) => setReplayStatus(st))
      .catch(() => {});
  }, []);

  // Poll live capture stats while active
  useEffect(() => {
    let timer: any = null;
    if (captureActive) {
      timer = setInterval(() => {
        fetchCaptureStats()
          .then((st) => {
            setCaptureStats(st);
            if (!st.is_running) {
              setCaptureActive(false);
            }
          })
          .catch(() => {});
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [captureActive]);

  // Poll replay status while running
  useEffect(() => {
    let timer: any = null;
    if (replayStatus?.is_running) {
      timer = setInterval(() => {
        fetchReplayStatus()
          .then((st) => setReplayStatus(st))
          .catch(() => {});
      }, 750);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [replayStatus?.is_running]);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleUploadAndAnalyze = async () => {
    if (!selectedFile) return;
    setUploading(true);
    setUploadError(null);

    try {
      const job = await uploadTelemetryFile(selectedFile);
      onAnalysisCreated(job);
      await startAnalysis(job.job_id);
      setSelectedFile(null);
      onRefreshAnalyses();
    } catch (err: any) {
      setUploadError(err.message || "Failed to upload and start analysis");
    } finally {
      setUploading(false);
    }
  };

  const handleStartCapture = async () => {
    if (!legalAuthorized) {
      setCaptureError("Mandatory authorization confirmation required.");
      return;
    }
    setCaptureError(null);
    try {
      const res = await startLiveCapture(ifaceName, bpfFilter);
      setCaptureActive(true);
      setCaptureStats(res.stats);
    } catch (err: any) {
      setCaptureError(err.message || "Failed to start capture");
    }
  };

  const handleStopCapture = async (createAnalysis: boolean) => {
    setStoppingCapture(true);
    try {
      const res = await stopLiveCapture(createAnalysis);
      setCaptureActive(false);
      setCaptureStats(res.stats);
      if (res.analysis_id) {
        onRefreshAnalyses();
      }
    } catch (err: any) {
      setCaptureError(err.message || "Failed to stop capture");
    } finally {
      setStoppingCapture(false);
    }
  };

  const handleStartReplay = async () => {
    if (!replayJobId) {
      setReplayError("Please select a completed dataset for simulation.");
      return;
    }
    setReplayError(null);
    setReplayLoading(true);
    try {
      const res = await startReplay(replayJobId, replaySpeed);
      setReplayStatus(res.replay);
    } catch (err: any) {
      setReplayError(err.message || "Failed to start replay");
    } finally {
      setReplayLoading(false);
    }
  };

  const handleStopReplay = async () => {
    setReplayLoading(true);
    try {
      const res = await stopReplay();
      setReplayStatus(res.replay);
    } catch (err: any) {
      setReplayError(err.message || "Failed to stop replay");
    } finally {
      setReplayLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Telemetry File Upload Section */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc", display: "flex", alignItems: "center", gap: 8 }}>
              <Upload size={18} color="#06b6d4" />
              Network Telemetry Ingestion (PCAP, PCAPNG, CSV)
            </div>
            <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>
              Upload authentic packet capture or NetFlow CSV to run through the AEGIS-WM temporal feature pipeline
            </div>
          </div>
        </div>

        {uploadError && (
          <div style={{ padding: "8px 12px", background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: 4, color: "#fca5a5", fontSize: 12, marginBottom: 12 }}>
            {uploadError}
          </div>
        )}

        {/* Dropzone */}
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          style={{
            border: `2px dashed ${dragActive ? "#06b6d4" : "#334155"}`,
            background: dragActive ? "rgba(6, 182, 212, 0.05)" : "#0f172a",
            borderRadius: 6,
            padding: "32px 20px",
            textAlign: "center",
            cursor: "pointer",
            transition: "all 0.2s ease",
          }}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pcap,.pcapng,.csv"
            style={{ display: "none" }}
          />

          <FileText size={36} color={selectedFile ? "#06b6d4" : "#64748b"} style={{ margin: "0 auto 12px" }} />

          {selectedFile ? (
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc" }}>{selectedFile.name}</div>
              <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 4 }}>
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB &bull; Ready for upload
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: 13, fontWeight: 500, color: "#e2e8f0" }}>
                Drag and drop raw network capture or click to browse
              </div>
              <div style={{ fontSize: 11, color: "#64748b", marginTop: 4 }}>
                Supported: .pcap, .pcapng, .csv (CIC-IDS format) &bull; Up to 500 MB
              </div>
            </div>
          )}
        </div>

        {selectedFile && (
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
            <button
              className="soc-btn"
              onClick={(e) => {
                e.stopPropagation();
                setSelectedFile(null);
              }}
              disabled={uploading}
            >
              Cancel
            </button>
            <button
              className="soc-btn soc-btn-primary"
              onClick={handleUploadAndAnalyze}
              disabled={uploading}
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              {uploading ? (
                <>
                  <Activity size={14} className="spin" />
                  <span>Processing Telemetry...</span>
                </>
              ) : (
                <>
                  <Play size={14} />
                  <span>Upload & Launch Analysis</span>
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Grid: Live Capture & Offline Replay */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Authorized Live Capture */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc", marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>
            <Radio size={16} color={captureActive ? "#ef4444" : "#06b6d4"} />
            Authorized Live Network Capture
          </div>
          <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 12 }}>
            Capture real-time packet stream directly into the sliding temporal window pipeline
          </div>

          {captureError && (
            <div style={{ padding: "6px 10px", background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: 4, color: "#fca5a5", fontSize: 11, marginBottom: 12 }}>
              {captureError}
            </div>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: 10, flex: 1 }}>
            <div>
              <label style={{ fontSize: 11, color: "#94a3b8", display: "block", marginBottom: 4 }}>
                Interface (Optional, leave blank for default):
              </label>
              <input
                className="soc-input font-mono"
                style={{ width: "100%" }}
                placeholder="e.g. eth0, Wi-Fi, Ethernet"
                value={ifaceName}
                onChange={(e) => setIfaceName(e.target.value)}
                disabled={captureActive}
              />
            </div>

            <div>
              <label style={{ fontSize: 11, color: "#94a3b8", display: "block", marginBottom: 4 }}>
                BPF Filter Expression:
              </label>
              <input
                className="soc-input font-mono"
                style={{ width: "100%" }}
                placeholder="e.g. tcp or udp"
                value={bpfFilter}
                onChange={(e) => setBpfFilter(e.target.value)}
                disabled={captureActive}
              />
            </div>

            {/* Mandatory Legal Acknowledgement */}
            <div style={{ padding: "8px 10px", background: "#0f172a", border: "1px solid #334155", borderRadius: 4, marginTop: 2 }}>
              <label style={{ display: "flex", alignItems: "flex-start", gap: 8, cursor: "pointer", fontSize: 11, color: "#cbd5e1" }}>
                <input
                  type="checkbox"
                  checked={legalAuthorized}
                  onChange={(e) => setLegalAuthorized(e.target.checked)}
                  disabled={captureActive}
                  style={{ marginTop: 2 }}
                />
                <span>
                  <strong>Legal Authorization:</strong> I confirm that I am explicitly authorized to monitor and inspect packets on this network interface in compliance with enterprise security policy.
                </span>
              </label>
            </div>

            {/* Live Operational Metrics Panel */}
            <div style={{ padding: "10px", background: "#090d16", border: "1px solid #334155", borderRadius: 6, marginTop: 4 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 10, textTransform: "uppercase", color: "#64748b", fontWeight: 700 }}>
                  Capture Engine State
                </span>
                <span style={{ fontSize: 11, fontWeight: 600, color: captureActive ? "#ef4444" : "#64748b", display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: captureActive ? "#ef4444" : "#64748b", display: "inline-block" }}></span>
                  {captureActive ? "RECORDING" : "IDLE"}
                </span>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
                <div className="kpi-box" style={{ padding: "6px 8px" }}>
                  <div className="kpi-label">Captured Packets</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 14 }}>
                    {(captureStats?.total_captured ?? 0).toLocaleString()}
                  </div>
                </div>
                <div className="kpi-box" style={{ padding: "6px 8px" }}>
                  <div className="kpi-label">Active Sessions</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 14, color: "#38bdf8" }}>
                    {captureStats?.active_sessions_count ?? 0}
                  </div>
                </div>
              </div>

              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "#94a3b8", marginBottom: 2 }}>
                  <span>Queue Pressure</span>
                  <span className="font-mono">{captureStats ? `${captureStats.queue_pressure_pct.toFixed(1)}%` : "0.0%"}</span>
                </div>
                <div style={{ height: 6, background: "#1e293b", borderRadius: 3, overflow: "hidden" }}>
                  <div
                    style={{
                      height: "100%",
                      width: `${Math.min(100, captureStats?.queue_pressure_pct ?? 0)}%`,
                      background: (captureStats?.queue_pressure_pct ?? 0) > 70 ? "#ef4444" : "#06b6d4",
                      transition: "width 0.3s ease",
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
              {captureActive ? (
                <>
                  <button
                    className="soc-btn"
                    disabled={stoppingCapture}
                    onClick={() => handleStopCapture(false)}
                    style={{ padding: "6px 12px", fontSize: 11 }}
                  >
                    <Square size={12} style={{ marginRight: 4 }} /> Stop
                  </button>
                  <button
                    className="soc-btn"
                    style={{ background: "#065f46", color: "#34d399", border: "1px solid #059669", padding: "6px 12px", fontSize: 11 }}
                    disabled={stoppingCapture}
                    onClick={() => handleStopCapture(true)}
                  >
                    <Zap size={12} style={{ marginRight: 4 }} />
                    {stoppingCapture ? "Processing..." : "Stop & Analyze Telemetry"}
                  </button>
                </>
              ) : (
                <button
                  className="soc-btn soc-btn-primary"
                  disabled={!legalAuthorized}
                  onClick={handleStartCapture}
                  style={{ display: "flex", alignItems: "center", gap: 6 }}
                >
                  <Play size={12} />
                  <span>Start Live Capture</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Offline Telemetry Replay */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc", marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>
            <Clock size={16} color="#06b6d4" />
            Deterministic Telemetry Replay Engine
          </div>
          <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 12 }}>
            Simulate realistic packet arrival timings at controllable speeds for tabletop exercises
          </div>

          {replayError && (
            <div style={{ padding: "6px 10px", background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: 4, color: "#fca5a5", fontSize: 11, marginBottom: 12 }}>
              {replayError}
            </div>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: 10, flex: 1 }}>
            <div>
              <label style={{ fontSize: 11, color: "#94a3b8", display: "block", marginBottom: 4 }}>
                Select Analyzed Telemetry Dataset:
              </label>
              <select
                className="soc-input font-mono"
                style={{ width: "100%" }}
                value={replayJobId}
                onChange={(e) => setReplayJobId(e.target.value)}
                disabled={replayStatus?.is_running}
              >
                <option value="">-- Select Completed Ingestion --</option>
                {analyses
                  .filter((a) => a.status === "completed")
                  .map((a) => (
                    <option key={a.job_id} value={a.job_id}>
                      {a.filename} ({a.total_flows_extracted.toLocaleString()} flows)
                    </option>
                  ))}
              </select>
            </div>

            <div>
              <label style={{ fontSize: 11, color: "#94a3b8", display: "block", marginBottom: 4 }}>
                Speed Multiplier: <strong style={{ color: "#38bdf8" }}>{replaySpeed}x</strong>
              </label>
              <div style={{ display: "flex", gap: 6 }}>
                {[0.5, 1.0, 2.0, 5.0, 10.0].map((s) => (
                  <button
                    key={s}
                    className={`soc-btn ${replaySpeed === s ? "soc-btn-primary" : ""}`}
                    style={{ flex: 1, padding: "4px 0", fontSize: 11 }}
                    onClick={() => setReplaySpeed(s)}
                    disabled={replayStatus?.is_running}
                  >
                    {s}x
                  </button>
                ))}
              </div>
            </div>

            {/* Replay Status Box */}
            <div style={{ padding: "10px", background: "#090d16", border: "1px solid #334155", borderRadius: 6, marginTop: 4 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 10, textTransform: "uppercase", color: "#64748b", fontWeight: 700 }}>
                  Simulation Status
                </span>
                <span style={{ fontSize: 11, fontWeight: 600, color: replayStatus?.is_running ? "#34d399" : "#64748b", display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: replayStatus?.is_running ? "#34d399" : "#64748b", display: "inline-block" }}></span>
                  {replayStatus?.is_running ? "STREAMING REPLAY" : "INACTIVE"}
                </span>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
                <div className="kpi-box" style={{ padding: "6px 8px" }}>
                  <div className="kpi-label">Replayed Flows</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 14 }}>
                    {(replayStatus?.replayed_flows ?? 0).toLocaleString()} / {(replayStatus?.total_flows ?? 0).toLocaleString()}
                  </div>
                </div>
                <div className="kpi-box" style={{ padding: "6px 8px" }}>
                  <div className="kpi-label">Simulation Clock</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 12, color: "#cbd5e1" }}>
                    {replayStatus?.current_timestamp && replayStatus.current_timestamp > 0
                      ? new Date(replayStatus.current_timestamp * 1000).toISOString().substr(11, 8)
                      : "00:00:00"}
                  </div>
                </div>
              </div>

              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "#94a3b8", marginBottom: 2 }}>
                  <span>Replay Progress</span>
                  <span className="font-mono">
                    {replayStatus && replayStatus.total_flows > 0
                      ? `${Math.min(100, Math.round((replayStatus.replayed_flows / replayStatus.total_flows) * 100))}%`
                      : "0%"}
                  </span>
                </div>
                <div style={{ height: 6, background: "#1e293b", borderRadius: 3, overflow: "hidden" }}>
                  <div
                    style={{
                      height: "100%",
                      width: `${
                        replayStatus && replayStatus.total_flows > 0
                          ? Math.min(100, (replayStatus.replayed_flows / replayStatus.total_flows) * 100)
                          : 0
                      }%`,
                      background: "linear-gradient(90deg, #06b6d4, #10b981)",
                      transition: "width 0.3s ease",
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
              {replayStatus?.is_running ? (
                <button
                  className="soc-btn"
                  style={{ background: "#7f1d1d", color: "#fca5a5", border: "1px solid #991b1b" }}
                  disabled={replayLoading}
                  onClick={handleStopReplay}
                >
                  <Square size={12} style={{ marginRight: 4 }} /> Stop Simulation
                </button>
              ) : (
                <button
                  className="soc-btn soc-btn-primary"
                  disabled={!replayJobId || replayLoading}
                  onClick={handleStartReplay}
                  style={{ display: "flex", alignItems: "center", gap: 6 }}
                >
                  <Play size={12} />
                  <span>Start Deterministic Replay</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
