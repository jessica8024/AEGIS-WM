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
} from "lucide-react";
import { AnalysisJob } from "../types";
import {
  uploadTelemetryFile,
  startAnalysis,
  startLiveCapture,
  stopLiveCapture,
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
  const [captureStats, setCaptureStats] = useState<any>(null);
  const [captureError, setCaptureError] = useState<string | null>(null);

  // Replay state
  const [replaySpeed, setReplaySpeed] = useState<number>(1.0);
  const [replayJobId, setReplayJobId] = useState<string>("");

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

  const handleStopCapture = async () => {
    try {
      const res = await stopLiveCapture();
      setCaptureActive(false);
      setCaptureStats(res.stats);
    } catch (err: any) {
      setCaptureError(err.message || "Failed to stop capture");
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
            padding: "36px 20px",
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
        <div className="card">
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

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
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
            <div style={{ padding: "8px 10px", background: "#0f172a", border: "1px solid #334155", borderRadius: 4, marginTop: 4 }}>
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

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 8 }}>
              {captureActive ? (
                <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#ef4444", fontSize: 12, fontWeight: 600 }}>
                  <Activity size={14} className="spin" />
                  <span>Capturing live traffic...</span>
                </div>
              ) : (
                <div style={{ fontSize: 11, color: "#64748b" }}>Engine idle</div>
              )}

              {captureActive ? (
                <button
                  className="soc-btn"
                  style={{ background: "#7f1d1d", color: "#fca5a5", border: "1px solid #991b1b" }}
                  onClick={handleStopCapture}
                >
                  <Square size={12} style={{ marginRight: 4 }} /> Stop Capture
                </button>
              ) : (
                <button
                  className="soc-btn soc-btn-primary"
                  disabled={!legalAuthorized}
                  onClick={handleStartCapture}
                >
                  <Play size={12} style={{ marginRight: 4 }} /> Start Live Capture
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Offline Telemetry Replay */}
        <div className="card">
          <div style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc", marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>
            <Clock size={16} color="#06b6d4" />
            Deterministic Telemetry Replay Engine
          </div>
          <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 12 }}>
            Simulate realistic packet arrival timings at controllable speeds for tabletop exercises
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: "#94a3b8", display: "block", marginBottom: 4 }}>
                Select Analyzed Telemetry Dataset:
              </label>
              <select
                className="soc-input font-mono"
                style={{ width: "100%" }}
                value={replayJobId}
                onChange={(e) => setReplayJobId(e.target.value)}
              >
                <option value="">-- Select Completed Ingestion --</option>
                {analyses.map((a) => (
                  <option key={a.job_id} value={a.job_id}>
                    {a.filename} ({a.total_flows_extracted} flows, {a.total_windows_generated} windows)
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
                  >
                    {s}x
                  </button>
                ))}
              </div>
            </div>

            <div style={{ marginTop: 16, padding: 10, background: "#0f172a", borderRadius: 4, fontSize: 11, color: "#94a3b8" }}>
              <div>Replay streams packets through the bidirectional flow tracker at inter-arrival delays scaled by 1/{replaySpeed}.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
