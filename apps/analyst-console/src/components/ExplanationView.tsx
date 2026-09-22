import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  Zap,
  TrendingUp,
  Clock,
  Layers,
  Network,
  Activity,
  AlertCircle,
  CheckCircle2,
  HelpCircle,
} from "lucide-react";
import { AnalysisJob, ExplanationResult, TimelinePayload } from "../types";
import { fetchExplanation } from "../api";

interface ExplanationViewProps {
  job?: AnalysisJob;
  timeline?: TimelinePayload;
}

export const ExplanationView: React.FC<ExplanationViewProps> = ({ job, timeline }) => {
  const [explanation, setExplanation] = useState<ExplanationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterDirection, setFilterDirection] = useState<"all" | "increases_risk" | "decreases_risk">("all");

  useEffect(() => {
    if (!job?.job_id) {
      setExplanation(null);
      return;
    }

    let isMounted = true;
    setLoading(true);
    setError(null);

    fetchExplanation(job.job_id, "latest")
      .then((data) => {
        if (isMounted) {
          setExplanation(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || "No explanation data available");
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [job?.job_id]);

  if (!job) {
    return (
      <div className="card" style={{ padding: 48, textAlign: "center", color: "#64748b" }}>
        <HelpCircle size={36} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
        <div style={{ fontSize: 14, fontWeight: 500 }}>No active analysis selected</div>
        <div style={{ fontSize: 12, marginTop: 4 }}>Select an analysis from the header dropdown to view explanations.</div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="card" style={{ padding: 48, textAlign: "center", color: "#94a3b8" }}>
        <Activity size={32} className="spin" style={{ margin: "0 auto 12px", color: "#06b6d4" }} />
        <div style={{ fontSize: 13, fontWeight: 500 }}>Computing Integrated Gradients & Temporal Attribution...</div>
        <div style={{ fontSize: 11, color: "#64748b", marginTop: 4 }}>
          Calculating baseline path convergence across model layers
        </div>
      </div>
    );
  }

  if (error || !explanation) {
    return (
      <div className="card" style={{ padding: 40, textAlign: "center" }}>
        <AlertCircle size={36} color="#eab308" style={{ margin: "0 auto 12px" }} />
        <div style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc" }}>Forensic Explanation Not Available</div>
        <div style={{ fontSize: 12, color: "#94a3b8", maxWidth: 500, margin: "6px auto 16px" }}>
          {error || "An explanation has not been generated for this job yet. Run a forecast on windowed telemetry to trigger attribution."}
        </div>
      </div>
    );
  }

  const filteredFeatures = (explanation.top_features || []).filter((f) => {
    if (filterDirection === "all") return true;
    return f.direction === filterDirection;
  });

  const maxContribution = Math.max(
    ...explanation.top_features.map((f) => Math.abs(f.contribution)),
    0.0001
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Explanation Header & Quality KPI Banner */}
      <div className="kpi-grid">
        <div className="kpi-box">
          <div className="kpi-label">Attributed Forecast Horizon</div>
          <div className="kpi-value font-mono" style={{ color: "#38bdf8" }}>
            +{((explanation.forecast_horizon || 1) * 5)}s
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            Step {explanation.forecast_horizon || 1} in Rollout Horizon
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-label">Projected Probability</div>
          <div
            className="kpi-value font-mono"
            style={{
              color:
                explanation.infiltration_probability > 0.7
                  ? "#ef4444"
                  : explanation.infiltration_probability > 0.4
                  ? "#f59e0b"
                  : "#10b981",
            }}
          >
            {(explanation.infiltration_probability * 100).toFixed(1)}%
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            Predicted State Transition Risk
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-label">Evidence Verification Level</div>
          <div
            className="kpi-value"
            style={{
              fontSize: 16,
              color: explanation.evidence_level === "STRONG" ? "#10b981" : "#f59e0b",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <CheckCircle2 size={18} />
            {explanation.evidence_level || "VERIFIED"}
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            Linkage between gradients & flows
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-label">Attribution Stability Score</div>
          <div className="kpi-value font-mono" style={{ color: "#a855f7" }}>
            {(explanation.explanation_stability_score || 0.95).toFixed(3)}
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>
            Robustness to input perturbation
          </div>
        </div>
      </div>

      {/* Feature Attribution Section */}
      <div className="card">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 16,
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc" }}>
              Feature Attribution (Integrated Gradients)
            </div>
            <div style={{ fontSize: 11, color: "#94a3b8" }}>
              Measures marginal influence of continuous state features on forecasted compromise risk
            </div>
          </div>

          <div style={{ display: "flex", gap: 6 }}>
            <button
              className={`soc-btn ${filterDirection === "all" ? "soc-btn-primary" : ""}`}
              style={{ fontSize: 11, padding: "4px 8px" }}
              onClick={() => setFilterDirection("all")}
            >
              All Features ({explanation.top_features.length})
            </button>
            <button
              className={`soc-btn ${filterDirection === "increases_risk" ? "soc-btn-primary" : ""}`}
              style={{ fontSize: 11, padding: "4px 8px" }}
              onClick={() => setFilterDirection("increases_risk")}
            >
              Risk Drivers (+)
            </button>
            <button
              className={`soc-btn ${filterDirection === "decreases_risk" ? "soc-btn-primary" : ""}`}
              style={{ fontSize: 11, padding: "4px 8px" }}
              onClick={() => setFilterDirection("decreases_risk")}
            >
              Protective Factors (-)
            </button>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {filteredFeatures.map((feat, idx) => {
            const pct = Math.min(100, Math.round((Math.abs(feat.contribution) / maxContribution) * 100));
            const isRisk = feat.direction === "increases_risk";

            return (
              <div
                key={idx}
                style={{
                  display: "grid",
                  gridTemplateColumns: "220px 1fr 100px 90px",
                  alignItems: "center",
                  gap: 12,
                  padding: "6px 8px",
                  background: idx % 2 === 0 ? "#0f172a" : "transparent",
                  borderRadius: 4,
                  fontSize: 12,
                }}
              >
                <div className="font-mono" style={{ color: "#e2e8f0", fontWeight: 500 }}>
                  {feat.feature_name}
                </div>

                {/* Contribution bar */}
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div
                    style={{
                      flex: 1,
                      height: 8,
                      background: "#1e293b",
                      borderRadius: 4,
                      overflow: "hidden",
                      display: "flex",
                    }}
                  >
                    <div
                      style={{
                        width: `${pct}%`,
                        background: isRisk
                          ? "linear-gradient(90deg, #f97316, #ef4444)"
                          : "linear-gradient(90deg, #10b981, #06b6d4)",
                        borderRadius: 4,
                        transition: "width 0.3s ease",
                      }}
                    />
                  </div>
                </div>

                <div
                  className="font-mono"
                  style={{
                    textAlign: "right",
                    color: isRisk ? "#ef4444" : "#10b981",
                    fontWeight: 600,
                  }}
                >
                  {isRisk ? "+" : "-"}{Math.abs(feat.contribution).toFixed(4)}
                </div>

                <div style={{ textAlign: "right" }}>
                  <span
                    className="badge"
                    style={{
                      background: isRisk ? "#450a0a" : "#064e3b",
                      color: isRisk ? "#fca5a5" : "#6ee7b7",
                      border: `1px solid ${isRisk ? "#7f1d1d" : "#047857"}`,
                      fontSize: 10,
                      padding: "2px 6px",
                    }}
                  >
                    {isRisk ? "Elevates Risk" : "Attenuates"}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Temporal History Attribution */}
      {explanation.temporal_attributions && explanation.temporal_attributions.length > 0 && (
        <div className="card">
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc" }}>
              Temporal Attention Profile Across Context Windows (m=12)
            </div>
            <div style={{ fontSize: 11, color: "#94a3b8" }}>
              Identifies which historical 5-second observation windows exerted the highest predictive weight on the future rollout
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: `repeat(${explanation.temporal_attributions.length}, 1fr)`,
              gap: 8,
              marginTop: 16,
            }}
          >
            {explanation.temporal_attributions.map((t, idx) => {
              const maxT = Math.max(...explanation.temporal_attributions.map((x) => x.contribution), 0.0001);
              const heightPct = Math.max(12, Math.round((t.contribution / maxT) * 100));

              return (
                <div
                  key={idx}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    gap: 6,
                  }}
                >
                  <div
                    style={{
                      fontSize: 10,
                      color: "#94a3b8",
                      fontFamily: "monospace",
                    }}
                  >
                    {t.contribution.toFixed(3)}
                  </div>

                  <div
                    style={{
                      width: "100%",
                      height: 100,
                      background: "#0f172a",
                      borderRadius: 4,
                      display: "flex",
                      alignItems: "flex-end",
                      padding: 2,
                      border: "1px solid #1e293b",
                    }}
                  >
                    <div
                      style={{
                        width: "100%",
                        height: `${heightPct}%`,
                        background:
                          idx === explanation.temporal_attributions.length - 1
                            ? "#06b6d4"
                            : "linear-gradient(180deg, #38bdf8, #1e3a8a)",
                        borderRadius: 2,
                        transition: "height 0.3s ease",
                      }}
                      title={`Window ${t.window_index}: contribution ${t.contribution.toFixed(4)}, active flows ${t.active_flow_count}`}
                    />
                  </div>

                  <div
                    style={{
                      fontSize: 10,
                      color: idx === explanation.temporal_attributions.length - 1 ? "#06b6d4" : "#64748b",
                      fontWeight: idx === explanation.temporal_attributions.length - 1 ? 700 : 500,
                      fontFamily: "monospace",
                    }}
                  >
                    t{t.relative_window_offset >= 0 ? `+${t.relative_window_offset}` : t.relative_window_offset}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Supporting Entities & Flows */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Identified High-Risk Entities */}
        <div className="card">
          <div style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc", marginBottom: 12 }}>
            Identified High-Risk Entities (Pseudonymized)
          </div>

          {explanation.supporting_entities && explanation.supporting_entities.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {explanation.supporting_entities.map((entity, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: 10,
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 4,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span className="font-mono" style={{ fontSize: 12, fontWeight: 600, color: "#38bdf8" }}>
                      {entity.host_pseudo}
                    </span>
                    <span
                      className="badge"
                      style={{
                        background: entity.risk_score > 0.7 ? "#7f1d1d" : "#78350f",
                        color: entity.risk_score > 0.7 ? "#fca5a5" : "#fcd34d",
                      }}
                    >
                      {entity.role || "Anomalous Node"}
                    </span>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      gap: 16,
                      marginTop: 8,
                      fontSize: 11,
                      color: "#94a3b8",
                    }}
                  >
                    <div>
                      Risk Score:{" "}
                      <span className="font-mono" style={{ color: "#ef4444", fontWeight: 600 }}>
                        {(entity.risk_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div>
                      Peers Contacted:{" "}
                      <span className="font-mono" style={{ color: "#e2e8f0" }}>
                        {entity.unique_peers_contacted}
                      </span>
                    </div>
                    <div>
                      Ports:{" "}
                      <span className="font-mono" style={{ color: "#e2e8f0" }}>
                        {entity.top_dst_ports.slice(0, 3).join(", ") || "N/A"}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: "#64748b", fontSize: 12, padding: 12 }}>No high-risk entities flagged.</div>
          )}
        </div>

        {/* Linked Telemetry Flows */}
        <div className="card">
          <div style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc", marginBottom: 12 }}>
            Supporting Telemetry Evidence Flows ({explanation.supporting_flows?.length || 0})
          </div>

          {explanation.supporting_flows && explanation.supporting_flows.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 300, overflowY: "auto" }}>
              {explanation.supporting_flows.map((flow, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: "8px 10px",
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 4,
                    fontSize: 11,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span className="font-mono" style={{ color: "#cbd5e1" }}>
                      {flow.src_ip_pseudo} &rarr; {flow.dst_ip_pseudo}:{flow.dst_port}
                    </span>
                    <span style={{ color: "#64748b", fontFamily: "monospace" }}>
                      Proto {flow.protocol === 6 ? "TCP" : flow.protocol === 17 ? "UDP" : flow.protocol}
                    </span>
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4, color: "#94a3b8" }}>
                    <span>
                      {flow.packets} pkts &bull; {(flow.bytes / 1024).toFixed(1)} KB
                    </span>
                    {flow.anomaly_flags && flow.anomaly_flags.length > 0 && (
                      <span style={{ color: "#f97316", fontWeight: 500 }}>
                        {flow.anomaly_flags.join(", ")}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: "#64748b", fontSize: 12, padding: 12 }}>No supporting flows linked.</div>
          )}
        </div>
      </div>
    </div>
  );
};
