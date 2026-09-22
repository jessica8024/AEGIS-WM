import React from "react";
import { Shield, Cpu, Download, RefreshCw, AlertCircle } from "lucide-react";
import { AnalysisJob } from "../types";

interface HeaderProps {
  health: any;
  analyses: AnalysisJob[];
  selectedJobId: string;
  onSelectJob: (id: string) => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  analyses,
  selectedJobId,
  onSelectJob,
  onRefresh,
}) => {
  const currentJob = analyses.find((a) => a.job_id === selectedJobId);

  return (
    <header className="top-navbar">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Shield size={20} color="#06b6d4" />
          <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: "-0.02em" }}>
            AEGIS<span style={{ color: "#06b6d4" }}>-WM</span>
          </span>
        </div>
        <span style={{ color: "#475569", fontSize: 11 }}>|</span>
        <span style={{ color: "#94a3b8", fontSize: 11, fontWeight: 500 }}>
          Anticipatory Enterprise Graph Intelligence System
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {/* Hardware Mode Badge */}
        <div
          className="badge"
          style={{
            background: health?.cuda_available ? "#064e3b" : "#1e293b",
            color: health?.cuda_available ? "#34d399" : "#94a3b8",
            border: "1px solid #334155",
          }}
          title={health?.device_name || "Hardware Engine"}
        >
          <Cpu size={12} />
          <span>{health?.cuda_available ? `GPU: ${health.device_name}` : "CPU Engine"}</span>
        </div>

        {/* Active Analysis Selector */}
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Analysis:</span>
          <select
            className="soc-input font-mono"
            style={{ minWidth: 220 }}
            value={selectedJobId}
            onChange={(e) => onSelectJob(e.target.value)}
          >
            {analyses.map((a) => (
              <option key={a.job_id} value={a.job_id}>
                {a.filename} ({a.status.toUpperCase()})
              </option>
            ))}
            {analyses.length === 0 && <option value="">No analyses loaded</option>}
          </select>
        </div>

        {/* Download PDF Report */}
        {currentJob?.report_pdf_path && (
          <a
            href={`/api/v1/reports/${currentJob.job_id}`}
            target="_blank"
            rel="noreferrer"
            className="btn btn-secondary"
            style={{ textDecoration: "none" }}
            title="Download Forensic PDF Report"
          >
            <Download size={13} />
            <span>Report PDF</span>
          </a>
        )}

        <button className="btn btn-secondary" onClick={onRefresh} title="Refresh Telemetry">
          <RefreshCw size={13} />
        </button>
      </div>
    </header>
  );
};
