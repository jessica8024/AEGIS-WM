import React, { useEffect, useRef, useState, useMemo } from "react";
import { Share2, Server, Globe, Filter, X, ArrowRight, Shield } from "lucide-react";
import { TopologyLink, TopologyNode, AnalysisJob } from "../types";
import { fetchHosts } from "../api";

interface TopologyProps {
  job?: AnalysisJob;
  nodes?: TopologyNode[];
  links?: TopologyLink[];
}

export const TopologyView: React.FC<TopologyProps> = ({ job, nodes: initialNodes, links: initialLinks }) => {
  const [nodes, setNodes] = useState<TopologyNode[]>(initialNodes || []);
  const [links, setLinks] = useState<TopologyLink[]>(initialLinks || []);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const coordsRef = useRef<Map<string, { x: number; y: number }>>(new Map());
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [filterPort, setFilterPort] = useState<string>("");

  useEffect(() => {
    if (job?.job_id && (!initialNodes || initialNodes.length === 0)) {
      const portNum = filterPort.trim() && !isNaN(Number(filterPort.trim())) ? Number(filterPort.trim()) : undefined;
      fetchHosts(job.job_id, portNum).then((res) => {
        setNodes(res.nodes);
        setLinks(res.links);
      }).catch(() => {});
    } else if (initialNodes && initialLinks) {
      setNodes(initialNodes);
      setLinks(initialLinks);
    }
  }, [job?.job_id, initialNodes, initialLinks, filterPort]);

  const trimmedPort = filterPort.trim();

  const filteredLinks = useMemo(() => {
    if (!trimmedPort) return links;
    return links.filter((l) => l.port.toString() === trimmedPort);
  }, [links, trimmedPort]);

  const displayNodes = useMemo(() => {
    if (!trimmedPort) return nodes;
    return nodes.filter((n) => filteredLinks.some((l) => l.source === n.id || l.target === n.id));
  }, [nodes, filteredLinks, trimmedPort]);

  // Keep selected node valid or reset if filtered out
  useEffect(() => {
    if (selectedNode && !displayNodes.some((n) => n.id === selectedNode.id)) {
      setSelectedNode(null);
    }
  }, [displayNodes, selectedNode]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);

    if (displayNodes.length === 0) {
      ctx.fillStyle = "#64748b";
      ctx.font = "12px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(
        trimmedPort
          ? `No observed communication links on destination port :${trimmedPort}.`
          : "No communication topology detected in current telemetry window.",
        width / 2,
        height / 2
      );
      coordsRef.current.clear();
      return;
    }

    // Assign radial positions to nodes
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.36;

    const nodeCoords = new Map<string, { x: number; y: number }>();
    displayNodes.forEach((node, i) => {
      const angle = (i / displayNodes.length) * 2 * Math.PI - Math.PI / 2;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      nodeCoords.set(node.id, { x, y });
    });
    coordsRef.current = nodeCoords;

    // Draw directed communication edges
    filteredLinks.forEach((link) => {
      const src = nodeCoords.get(link.source);
      const dst = nodeCoords.get(link.target);
      if (!src || !dst) return;

      const isNodeLinked =
        selectedNode && (selectedNode.id === link.source || selectedNode.id === link.target);

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(dst.x, dst.y);

      if (selectedNode) {
        ctx.strokeStyle = isNodeLinked ? "rgba(56, 189, 248, 0.9)" : "rgba(51, 65, 85, 0.2)";
        ctx.lineWidth = isNodeLinked ? 2.5 : 1;
      } else {
        ctx.strokeStyle = "rgba(56, 189, 248, 0.4)";
        ctx.lineWidth = Math.min(4, Math.max(1, Math.log10(link.flows + 1)));
      }
      ctx.stroke();

      // Draw port tag midway
      const midX = (src.x + dst.x) / 2;
      const midY = (src.y + dst.y) / 2;
      ctx.fillStyle = isNodeLinked ? "#38bdf8" : "#64748b";
      ctx.font = isNodeLinked ? "bold 10px monospace" : "9px monospace";
      ctx.textAlign = "center";
      ctx.fillText(`:${link.port}`, midX, midY - 2);
    });

    // Draw node vertices
    displayNodes.forEach((node) => {
      const coord = nodeCoords.get(node.id);
      if (!coord) return;

      const isSelected = selectedNode?.id === node.id;
      const isNeighbor =
        selectedNode &&
        filteredLinks.some(
          (l) =>
            (l.source === selectedNode.id && l.target === node.id) ||
            (l.target === selectedNode.id && l.source === node.id)
        );
      const isHighVolume = node.flows > 50;

      ctx.beginPath();
      ctx.arc(coord.x, coord.y, isSelected ? 12 : isNeighbor ? 9 : 7, 0, 2 * Math.PI);

      if (isSelected) {
        ctx.fillStyle = "#38bdf8";
      } else if (isNeighbor) {
        ctx.fillStyle = "#f59e0b";
      } else if (isHighVolume) {
        ctx.fillStyle = "#ef4444";
      } else {
        ctx.fillStyle = "#0284c7";
      }

      ctx.fill();
      ctx.strokeStyle = isSelected ? "#ffffff" : isNeighbor ? "#fde047" : "#0f172a";
      ctx.lineWidth = isSelected ? 2.5 : 1.5;
      ctx.stroke();

      // Node label
      ctx.fillStyle = isSelected ? "#ffffff" : isNeighbor ? "#f1f5f9" : "#cbd5e1";
      ctx.font = isSelected ? "bold 10px monospace" : "9px monospace";
      ctx.textAlign = "center";
      ctx.fillText(node.label, coord.x, coord.y + 18);
    });
  }, [displayNodes, filteredLinks, selectedNode, trimmedPort]);

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    let found: TopologyNode | null = null;
    for (const node of displayNodes) {
      const coord = coordsRef.current.get(node.id);
      if (coord) {
        const dist = Math.hypot(coord.x - clickX, coord.y - clickY);
        if (dist <= 15) {
          found = node;
          break;
        }
      }
    }
    setSelectedNode(found);
  };

  // Connected peers of selected node
  const selectedNodePeers = useMemo(() => {
    if (!selectedNode) return [];
    return filteredLinks
      .filter((l) => l.source === selectedNode.id || l.target === selectedNode.id)
      .map((l) => ({
        peerId: l.source === selectedNode.id ? l.target : l.source,
        direction: l.source === selectedNode.id ? "outbound" : "inbound",
        port: l.port,
        protocol: l.protocol,
        flows: l.flows,
        bytes: l.bytes,
      }));
  }, [selectedNode, filteredLinks]);

  return (
    <div>
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">
            <Share2 size={14} color="#06b6d4" />
            Empirical Communication Topology Graph
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ display: "flex", gap: 4 }}>
              {["", "80", "443", "53", "22"].map((p) => (
                <button
                  key={p}
                  className={`soc-btn ${filterPort === p ? "soc-btn-primary" : ""}`}
                  style={{ padding: "2px 8px", fontSize: 10 }}
                  onClick={() => setFilterPort(p)}
                >
                  {p ? `:${p}` : "All Ports"}
                </button>
              ))}
            </div>
            <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
              <Filter size={12} color="#94a3b8" style={{ position: "absolute", left: 8 }} />
              <input
                type="text"
                placeholder="Port (e.g. 80, 443)..."
                className="soc-input font-mono"
                style={{ width: 140, paddingLeft: 24, fontSize: 11 }}
                value={filterPort}
                onChange={(e) => setFilterPort(e.target.value)}
              />
              {filterPort && (
                <X
                  size={12}
                  color="#94a3b8"
                  style={{ position: "absolute", right: 6, cursor: "pointer" }}
                  onClick={() => setFilterPort("")}
                />
              )}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 16 }}>
          <canvas
            ref={canvasRef}
            width={580}
            height={420}
            onClick={handleCanvasClick}
            style={{
              background: "#090d16",
              borderRadius: 6,
              border: "1px solid #334155",
              cursor: "pointer",
            }}
          />

          {/* Node & Link Details Pane */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="soc-card" style={{ margin: 0, height: "100%", display: "flex", flexDirection: "column" }}>
              <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", marginBottom: 8 }}>
                Topology Statistics {trimmedPort && `(Port :${trimmedPort})`}
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 12 }}>
                <div className="kpi-box" style={{ padding: "8px 10px" }}>
                  <div className="kpi-label">Active Entities</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 16, color: displayNodes.length > 0 ? "#38bdf8" : "#64748b" }}>
                    {displayNodes.length}
                  </div>
                </div>
                <div className="kpi-box" style={{ padding: "8px 10px" }}>
                  <div className="kpi-label">Observed Links</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 16, color: filteredLinks.length > 0 ? "#34d399" : "#64748b" }}>
                    {filteredLinks.length}
                  </div>
                </div>
              </div>

              {/* Selected Node Details Box */}
              {selectedNode ? (
                <div
                  style={{
                    background: "#1e293b",
                    border: "1px solid #38bdf8",
                    borderRadius: 6,
                    padding: "10px 12px",
                    marginBottom: 10,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: "#38bdf8" }}>
                      Focused Node: {selectedNode.label}
                    </div>
                    <button
                      className="soc-btn"
                      style={{ padding: "1px 6px", fontSize: 10 }}
                      onClick={() => setSelectedNode(null)}
                    >
                      Clear Focus
                    </button>
                  </div>
                  <div style={{ fontSize: 11, color: "#94a3b8", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4 }}>
                    <div>Flows: <strong style={{ color: "#f8fafc" }}>{selectedNode.flows}</strong></div>
                    <div>Bytes: <strong style={{ color: "#f8fafc" }}>{(selectedNode.bytes / 1024).toFixed(1)} KB</strong></div>
                  </div>
                  <div style={{ fontSize: 10, color: "#64748b", marginTop: 6, textTransform: "uppercase" }}>
                    Active Peer Connections ({selectedNodePeers.length}):
                  </div>
                  <div style={{ maxHeight: 90, overflowY: "auto", marginTop: 4 }}>
                    {selectedNodePeers.map((p, idx) => (
                      <div
                        key={idx}
                        style={{
                          fontSize: 10,
                          fontFamily: "monospace",
                          color: "#cbd5e1",
                          display: "flex",
                          justifyContent: "space-between",
                          padding: "2px 0",
                          borderBottom: "1px solid #334155",
                        }}
                      >
                        <span>
                          {p.direction === "outbound" ? "→" : "←"} {p.peerId} :{p.port}
                        </span>
                        <span style={{ color: "#94a3b8" }}>
                          {p.flows} flows ({Math.round(p.bytes / 1024)} KB)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: 11, color: "#64748b", marginBottom: 6, fontStyle: "italic" }}>
                  Click any node on the graph or table to isolate its communication peers.
                </div>
              )}

              <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", marginBottom: 6 }}>
                Active Communication Peers ({displayNodes.length})
              </div>
              <div style={{ flex: 1, maxHeight: 220, overflowY: "auto" }}>
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Host Pseudo</th>
                      <th>Flows</th>
                      <th>Volume</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayNodes.map((n) => (
                      <tr
                        key={n.id}
                        style={{
                          cursor: "pointer",
                          background: selectedNode?.id === n.id ? "rgba(56, 189, 248, 0.15)" : undefined,
                          borderLeft: selectedNode?.id === n.id ? "3px solid #38bdf8" : undefined,
                        }}
                        onClick={() => setSelectedNode(n)}
                      >
                        <td className="font-mono" style={{ color: selectedNode?.id === n.id ? "#38bdf8" : "#f1f5f9" }}>
                          {n.label}
                        </td>
                        <td className="font-mono">{n.flows}</td>
                        <td className="font-mono">{(n.bytes / 1024).toFixed(1)} KB</td>
                      </tr>
                    ))}
                    {displayNodes.length === 0 && (
                      <tr>
                        <td colSpan={3} style={{ textAlign: "center", color: "#64748b", padding: 16 }}>
                          No hosts match filter :{trimmedPort}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
