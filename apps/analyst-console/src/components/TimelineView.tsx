import React, { useState } from "react";
import { Clock, TrendingUp, AlertTriangle, Info } from "lucide-react";
import { TimelinePayload, AnalysisJob } from "../types";

interface TimelineViewProps {
  timeline?: TimelinePayload;
  job?: AnalysisJob;
}

export const TimelineView: React.FC<TimelineViewProps> = ({ timeline, job }) => {
  const [hoveredPoint, setHoveredPoint] = useState<any | null>(null);

  if (!timeline || (!timeline.history.length && !timeline.forecast.length)) {
    return (
      <div className="soc-card" style={{ padding: 48, textAlign: "center", color: "#64748b" }}>
        <Clock size={32} style={{ margin: "0 auto 12px" }} />
        <div>No timeline telemetry available. Ingest a file to view anticipatory forecasts.</div>
      </div>
    );
  }

  const history = timeline.history;
  const forecast = timeline.forecast;

  // Chart dimensions
  const svgWidth = 860;
  const svgHeight = 280;
  const padding = { top: 30, right: 30, bottom: 40, left: 60 };
  const chartW = svgWidth - padding.left - padding.right;
  const chartH = svgHeight - padding.top - padding.bottom;

  const totalPoints = history.length + forecast.length;
  const stepX = chartW / Math.max(1, totalPoints - 1);

  // Helper coordinate mappers
  const getY = (riskVal: number) => padding.top + chartH - riskVal * chartH;
  const getX = (idx: number) => padding.left + idx * stepX;

  // Build SVG paths
  // History line
  const historyCoords = history.map((h, i) => ({ x: getX(i), y: getY(h.is_compromised ? 0.9 : 0.05), ...h }));
  const historyPath = historyCoords.reduce((acc, pt, i) => `${acc} ${i === 0 ? "M" : "L"} ${pt.x} ${pt.y}`, "");

  // Forecast line & Uncertainty area
  const forecastStartIdx = Math.max(0, history.length - 1);
  const startPt = historyCoords[forecastStartIdx] || { x: getX(0), y: getY(0) };

  const forecastCoords = forecast.map((f, i) => {
    const idx = history.length + i;
    return {
      x: getX(idx),
      y: getY(f.infiltration_probability),
      yLower: getY(f.uncertainty_lower),
      yUpper: getY(f.uncertainty_upper),
      ...f,
    };
  });

  const fullForecastLine = `${startPt.x},${startPt.y} ` + forecastCoords.map((pt) => `${pt.x},${pt.y}`).join(" ");

  // Uncertainty polygon (upper curve forward, lower curve backwards)
  let uncertaintyPolygon = `M ${startPt.x} ${startPt.y} `;
  forecastCoords.forEach((pt) => { uncertaintyPolygon += `L ${pt.x} ${pt.yUpper} `; });
  for (let i = forecastCoords.length - 1; i >= 0; i--) {
    uncertaintyPolygon += `L ${forecastCoords[i].x} ${forecastCoords[i].yLower} `;
  }
  uncertaintyPolygon += `Z`;

  const warningY = getY(0.45);
  const criticalY = getY(0.70);
  const dividerX = getX(history.length - 0.5);

  return (
    <div>
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">
            <TrendingUp size={14} color="#06b6d4" />
            Anticipatory Attack Horizon & Uncertainty Trajectory
          </span>
          <div style={{ display: "flex", gap: 16, fontSize: 11 }}>
            <span style={{ display: "flex", alignItems: "center", gap: 6, color: "#94a3b8" }}>
              <span style={{ width: 10, height: 2, background: "#38bdf8", display: "inline-block" }} /> Observed History
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 6, color: "#f59e0b" }}>
              <span style={{ width: 10, height: 2, background: "#f59e0b", display: "inline-block" }} /> Forecast Progression
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 6, color: "#64748b" }}>
              <span style={{ width: 10, height: 8, background: "rgba(245, 158, 11, 0.15)", display: "inline-block" }} /> 95% Uncertainty CI
            </span>
          </div>
        </div>

        {/* Dual-Timeline SVG Graph */}
        <div style={{ overflowX: "auto", position: "relative" }}>
          <svg width={svgWidth} height={svgHeight} style={{ display: "block" }}>
            {/* Grid & Axis */}
            {[0.0, 0.25, 0.5, 0.75, 1.0].map((val) => {
              const y = getY(val);
              return (
                <g key={val}>
                  <line x1={padding.left} y1={y} x2={svgWidth - padding.right} y2={y} stroke="#1e293b" strokeWidth="1" />
                  <text x={padding.left - 8} y={y + 4} fill="#64748b" fontSize="10" textAnchor="end" className="font-mono">
                    {(val * 100).toFixed(0)}%
                  </text>
                </g>
              );
            })}

            {/* Threshold Lines */}
            <line x1={padding.left} y1={warningY} x2={svgWidth - padding.right} y2={warningY} stroke="#d97706" strokeWidth="1" strokeDasharray="4 4" opacity="0.6" />
            <text x={svgWidth - padding.right} y={warningY - 4} fill="#d97706" fontSize="9" textAnchor="end" className="font-mono">
              Warning (45%)
            </text>

            <line x1={padding.left} y1={criticalY} x2={svgWidth - padding.right} y2={criticalY} stroke="#dc2626" strokeWidth="1" strokeDasharray="4 4" opacity="0.7" />
            <text x={svgWidth - padding.right} y={criticalY - 4} fill="#dc2626" fontSize="9" textAnchor="end" className="font-mono">
              Critical (70%)
            </text>

            {/* Time Divider: Observed vs Future */}
            <line x1={dividerX} y1={padding.top} x2={dividerX} y2={padding.top + chartH} stroke="#0284c7" strokeWidth="1.5" strokeDasharray="3 3" />
            <text x={dividerX - 6} y={padding.top + 14} fill="#38bdf8" fontSize="10" textAnchor="end" fontWeight="600">
              OBSERVED (T)
            </text>
            <text x={dividerX + 6} y={padding.top + 14} fill="#f59e0b" fontSize="10" textAnchor="start" fontWeight="600">
              RECURSIVE ROLLOUT (T+1..K)
            </text>

            {/* Uncertainty Shaded Area */}
            {forecastCoords.length > 0 && (
              <path d={uncertaintyPolygon} fill="rgba(245, 158, 11, 0.15)" stroke="none" />
            )}

            {/* History Path */}
            {historyCoords.length > 0 && (
              <path d={historyPath} fill="none" stroke="#38bdf8" strokeWidth="2.5" />
            )}

            {/* Forecast Path */}
            {forecastCoords.length > 0 && (
              <polyline points={fullForecastLine} fill="none" stroke="#f59e0b" strokeWidth="2.5" strokeDasharray="5 3" />
            )}

            {/* Forecast Horizon Nodes */}
            {forecastCoords.map((pt, i) => (
              <g key={i} onMouseEnter={() => setHoveredPoint(pt)} onMouseLeave={() => setHoveredPoint(null)} style={{ cursor: "pointer" }}>
                <circle cx={pt.x} cy={pt.y} r="5" fill="#f59e0b" stroke="#0f172a" strokeWidth="2" />
                <text x={pt.x} y={padding.top + chartH + 18} fill="#94a3b8" fontSize="10" textAnchor="middle" className="font-mono">
                  +{pt.horizon_step * 5}s
                </text>
              </g>
            ))}
          </svg>
        </div>

        {/* Selected Horizon Card */}
        {hoveredPoint && (
          <div style={{ marginTop: 12, padding: "10px 14px", background: "#090d16", border: "1px solid #334155", borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <span style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Horizon Step</span>
              <div className="font-mono font-bold" style={{ color: "#f59e0b" }}>
                T + {hoveredPoint.horizon_step} ({hoveredPoint.horizon_step * 5}s ahead)
              </div>
            </div>
            <div>
              <span style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Infiltration Risk</span>
              <div className="font-mono font-bold">{(hoveredPoint.infiltration_probability * 100).toFixed(1)}%</div>
            </div>
            <div>
              <span style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>95% Confidence Band</span>
              <div className="font-mono" style={{ color: "#94a3b8" }}>
                [{(hoveredPoint.uncertainty_lower * 100).toFixed(0)}% - {(hoveredPoint.uncertainty_upper * 100).toFixed(0)}%]
              </div>
            </div>
            <div>
              <span style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Predicted Stage</span>
              <div className="badge badge-warning" style={{ marginTop: 2 }}>
                {hoveredPoint.predicted_stage}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Trajectory Breakdown Table */}
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">Rollout Trajectory Breakdown (K=6 Horizons)</span>
        </div>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Horizon</th>
              <th>Target Epoch Time</th>
              <th>Infiltration Risk</th>
              <th>95% Uncertainty CI</th>
              <th>Entropy</th>
              <th>Predicted Attack Stage</th>
              <th>Risk Velocity</th>
            </tr>
          </thead>
          <tbody>
            {forecast.map((pt) => (
              <tr key={pt.horizon_step}>
                <td className="font-mono" style={{ color: "#f59e0b" }}>
                  Horizon {pt.horizon_step} (+{pt.horizon_step * 5}s)
                </td>
                <td className="font-mono">{new Date(pt.timestamp * 1000).toLocaleTimeString()}</td>
                <td className="font-mono font-bold" style={{ color: pt.infiltration_probability > 0.7 ? "#ef4444" : pt.infiltration_probability > 0.4 ? "#f59e0b" : "#10b981" }}>
                  {(pt.infiltration_probability * 100).toFixed(1)}%
                </td>
                <td className="font-mono" style={{ color: "#94a3b8" }}>
                  [{(pt.uncertainty_lower * 100).toFixed(0)}% - {(pt.uncertainty_upper * 100).toFixed(0)}%]
                </td>
                <td className="font-mono">{pt.predictive_entropy.toFixed(3)}</td>
                <td>
                  <span className={`badge ${pt.predicted_stage === "Benign" ? "badge-benign" : "badge-warning"}`}>
                    {pt.predicted_stage}
                  </span>
                </td>
                <td className="font-mono" style={{ color: pt.risk_velocity >= 0 ? "#ef4444" : "#10b981" }}>
                  {pt.risk_velocity > 0 ? "+" : ""}{pt.risk_velocity.toFixed(3)}/s
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
