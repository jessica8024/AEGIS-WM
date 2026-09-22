import React, { useState } from "react";
import { AlertTriangle, Activity, CheckCircle, Clock, ShieldAlert, FileText, Check } from "lucide-react";
import { AlertRecord, AnalysisJob, TimelinePayload } from "../types";
import { acknowledgeAlert } from "../api";

interface OverviewProps {
  job?: AnalysisJob;
  timeline?: TimelinePayload;
  alerts: AlertRecord[];
  onRefreshAlerts: () => void;
}

export const OverviewView: React.FC<OverviewProps> = ({
  job,
  timeline,
  alerts,
  onRefreshAlerts,
}) => {
  const [ackModalAlert, setAckModalAlert] = useState<AlertRecord | null>(null);
  const [analystName, setAnalystName] = useState("SecOps Analyst");
  const [analystNotes, setAnalystNotes] = useState("");

  const maxRisk = timeline?.max_risk_in_horizon ?? 0;
  const peakStage = timeline?.peak_stage ?? "Benign";
  const activeAlertCount = alerts.filter((a) => a.state === "active").length;

  const handleAcknowledge = async () => {
    if (!ackModalAlert) return;
    await acknowledgeAlert(ackModalAlert.alert_id, analystName, analystNotes);
    setAckModalAlert(null);
    setAnalystNotes("");
    onRefreshAlerts();
  };

  return (
    <div>
      {/* KPI Cards Grid */}
      <div className="kpi-grid">
        <div className="kpi-box">
          <div className="kpi-label">Projected Compromise Risk</div>
          <div
            className="kpi-value"
            style={{
              color: maxRisk > 0.7 ? "#ef4444" : maxRisk > 0.4 ? "#f59e0b" : "#10b981",
            }}
          >
            {(maxRisk * 100).toFixed(1)}%
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            Next 30s Anticipatory Horizon
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-label">Predicted Attack Stage</div>
          <div className="kpi-value" style={{ fontSize: 18, color: "#38bdf8" }}>
            {peakStage}
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            Transition Model Prediction
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-label">Extracted Telemetry</div>
          <div className="kpi-value font-mono">
            {job?.total_flows_extracted.toLocaleString() ?? 0}
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            {job?.total_windows_generated ?? 0} States (5s Windows)
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-label">Active Anticipatory Alerts</div>
          <div
            className="kpi-value font-mono"
            style={{ color: activeAlertCount > 0 ? "#ef4444" : "#10b981" }}
          >
            {activeAlertCount}
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            {alerts.length} Total Audit Records
          </div>
        </div>
      </div>

      {/* Analysis Provenance Info */}
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">
            <Activity size={14} color="#06b6d4" />
            Telemetry Session Provenance
          </span>
          <span
            className="badge font-mono"
            style={{
              background: job?.status === "completed" ? "#064e3b" : "#1e293b",
              color: job?.status === "completed" ? "#34d399" : "#38bdf8",
              border: "1px solid #334155",
            }}
          >
            {job?.status.toUpperCase() ?? "IDLE"}
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }}>
          <div>
            <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Source File</div>
            <div className="font-mono" style={{ fontSize: 13, marginTop: 2 }}>{job?.filename || "No file"}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>SHA-256 Provenance Hash</div>
            <div className="font-mono" style={{ fontSize: 11, color: "#94a3b8", marginTop: 2, wordBreak: "break-all" }}>
              {job?.source_file_sha256 || "N/A"}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Packets Processed</div>
            <div className="font-mono" style={{ fontSize: 13, marginTop: 2 }}>
              {job?.total_packets_parsed.toLocaleString() || 0}
            </div>
          </div>
        </div>
      </div>

      {/* Alerts Feed Table */}
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">
            <ShieldAlert size={14} color="#f59e0b" />
            Detection Alerts & Investigation Audit
          </span>
        </div>

        {alerts.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", color: "#64748b" }}>
            <CheckCircle size={28} color="#10b981" style={{ margin: "0 auto 8px" }} />
            <div>No active alerts. Telemetry indicates normal baseline network evolution.</div>
          </div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Severity</th>
                <th>Lead Time</th>
                <th>Risk</th>
                <th>Triggered Policy</th>
                <th>Target Host</th>
                <th>State</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alt) => (
                <tr key={alt.alert_id}>
                  <td className="font-mono">{alt.alert_id}</td>
                  <td>
                    <span
                      className={`badge badge-${alt.severity}`}
                    >
                      {alt.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="font-mono" style={{ color: "#38bdf8" }}>
                    {alt.forecast_horizon_seconds.toFixed(0)}s ahead
                  </td>
                  <td className="font-mono font-bold">
                    {(alt.infiltration_probability * 100).toFixed(1)}%
                  </td>
                  <td>{alt.policy_rule_triggered}</td>
                  <td className="font-mono">{alt.primary_host_pseudo || "All Hosts"}</td>
                  <td>
                    <span
                      className="badge"
                      style={{
                        background: alt.state === "active" ? "#7f1d1d" : "#1e293b",
                        color: alt.state === "active" ? "#fca5a5" : "#94a3b8",
                      }}
                    >
                      {alt.state.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    {alt.state === "active" && (
                      <button
                        className="btn btn-secondary"
                        style={{ padding: "3px 8px", fontSize: 11 }}
                        onClick={() => setAckModalAlert(alt)}
                      >
                        <Check size={11} /> Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Acknowledge Modal */}
      {ackModalAlert && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 50,
          }}
        >
          <div className="soc-card" style={{ width: 440, background: "#0f172a" }}>
            <div className="soc-card-header">
              <span className="soc-card-title">Acknowledge Alert {ackModalAlert.alert_id}</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: "#94a3b8", display: "block", marginBottom: 4 }}>
                  Analyst Name
                </label>
                <input
                  type="text"
                  className="soc-input"
                  style={{ width: "100%" }}
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                />
              </div>
              <div>
                <label style={{ fontSize: 11, color: "#94a3b8", display: "block", marginBottom: 4 }}>
                  Investigation Notes
                </label>
                <textarea
                  className="soc-input font-mono"
                  style={{ width: "100%", height: 80, resize: "none" }}
                  placeholder="Record initial triage findings..."
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
                <button className="btn btn-secondary" onClick={() => setAckModalAlert(null)}>
                  Cancel
                </button>
                <button className="btn btn-primary" onClick={handleAcknowledge}>
                  Confirm & Audit
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
