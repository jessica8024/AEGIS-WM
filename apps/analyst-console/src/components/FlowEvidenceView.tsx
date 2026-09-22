import React, { useEffect, useState } from "react";
import { Database, Filter, ChevronLeft, ChevronRight } from "lucide-react";
import { FlowRecord, AnalysisJob } from "../types";
import { fetchFlows } from "../api";

interface FlowEvidenceProps {
  jobId?: string;
  job?: AnalysisJob;
}

export const FlowEvidenceView: React.FC<FlowEvidenceProps> = ({ jobId, job }) => {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(0);
  const [protocolFilter, setProtocolFilter] = useState<string>("");
  const [portFilter, setPortFilter] = useState<string>("");
  const pageSize = 25;
  const activeId = jobId || job?.job_id || "";

  const loadData = async () => {
    if (!activeId) return;
    const protoNum = protocolFilter ? parseInt(protocolFilter) : undefined;
    const portNum = portFilter ? parseInt(portFilter) : undefined;
    const res = await fetchFlows(activeId, pageSize, page * pageSize, portNum, protoNum);
    setFlows(res.flows);
    setTotal(res.total);
  };

  useEffect(() => {
    loadData();
  }, [activeId, page, protocolFilter, portFilter]);

  return (
    <div>
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">
            <Database size={14} color="#06b6d4" />
            Authentic Flow Telemetry Records (Extracted Parquet)
          </span>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <select
              className="soc-input"
              value={protocolFilter}
              onChange={(e) => { setProtocolFilter(e.target.value); setPage(0); }}
            >
              <option value="">All Protocols</option>
              <option value="6">TCP (6)</option>
              <option value="17">UDP (17)</option>
              <option value="1">ICMP (1)</option>
            </select>

            <input
              type="text"
              placeholder="Filter Min Port..."
              className="soc-input font-mono"
              style={{ width: 130 }}
              value={portFilter}
              onChange={(e) => { setPortFilter(e.target.value); setPage(0); }}
            />
          </div>
        </div>

        {flows.length === 0 ? (
          <div style={{ padding: 32, textAlign: "center", color: "#64748b" }}>
            No telemetry flows matching the current filter criteria.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source Entity</th>
                  <th>Destination Entity</th>
                  <th>Port</th>
                  <th>Proto</th>
                  <th>Packets (F/B)</th>
                  <th>Bytes (F/B)</th>
                  <th>Duration</th>
                  <th>Flags / Ratios</th>
                  <th>Label</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((f, i) => (
                  <tr key={f.flow_id || i}>
                    <td className="font-mono" style={{ whiteSpace: "nowrap" }}>
                      {new Date(f.start_timestamp * 1000).toLocaleTimeString()}
                    </td>
                    <td className="font-mono">{f.src_ip_pseudo}:{f.src_port}</td>
                    <td className="font-mono">{f.dst_ip_pseudo}</td>
                    <td className="font-mono" style={{ color: "#38bdf8" }}>{f.dst_port}</td>
                    <td>
                      <span className="badge badge-info">
                        {f.protocol === 6 ? "TCP" : f.protocol === 17 ? "UDP" : `IP_${f.protocol}`}
                      </span>
                    </td>
                    <td className="font-mono">{f.fwd_packets} / {f.bwd_packets}</td>
                    <td className="font-mono">{f.fwd_bytes} / {f.bwd_bytes}</td>
                    <td className="font-mono">{f.duration.toFixed(3)}s</td>
                    <td className="font-mono" style={{ fontSize: 11 }}>
                      SYN/ACK: {f.syn_ack_ratio.toFixed(2)} | RST: {f.rst_syn_ratio.toFixed(2)}
                    </td>
                    <td>
                      <span className={`badge ${f.source_label && f.source_label !== "BENIGN" ? "badge-warning" : "badge-benign"}`}>
                        {f.source_label || "BENIGN"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 12 }}>
          <div style={{ fontSize: 11, color: "#64748b" }}>
            Showing {page * pageSize + 1} - {Math.min(total, (page + 1) * pageSize)} of {total.toLocaleString()} flows
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <button
              className="btn btn-secondary"
              disabled={page === 0}
              onClick={() => setPage(page - 1)}
            >
              <ChevronLeft size={13} /> Prev
            </button>
            <button
              className="btn btn-secondary"
              disabled={(page + 1) * pageSize >= total}
              onClick={() => setPage(page + 1)}
            >
              Next <ChevronRight size={13} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
