import React, { useEffect, useRef, useState } from "react";
import { Share2, Server, Globe, Filter } from "lucide-react";
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
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [filterPort, setFilterPort] = useState<string>("");

  useEffect(() => {
    if (job?.job_id && (!initialNodes || initialNodes.length === 0)) {
      fetchHosts(job.job_id).then((res) => {
        setNodes(res.nodes);
        setLinks(res.links);
      }).catch(() => {});
    } else if (initialNodes && initialLinks) {
      setNodes(initialNodes);
      setLinks(initialLinks);
    }
  }, [job?.job_id, initialNodes, initialLinks]);

  const filteredLinks = filterPort
    ? links.filter((l) => l.port.toString() === filterPort)
    : links;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);

    if (nodes.length === 0) {
      ctx.fillStyle = "#64748b";
      ctx.font = "12px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("No communication topology detected in current telemetry window.", width / 2, height / 2);
      return;
    }

    // Assign radial positions to nodes
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.35;

    const nodeCoords = new Map<string, { x: number; y: number }>();
    nodes.forEach((node, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      nodeCoords.set(node.id, { x, y });
    });

    // Draw directed communication edges
    filteredLinks.forEach((link) => {
      const src = nodeCoords.get(link.source);
      const dst = nodeCoords.get(link.target);
      if (!src || !dst) return;

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(dst.x, dst.y);
      ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
      ctx.lineWidth = Math.min(4, Math.max(1, Math.log10(link.flows + 1)));
      ctx.stroke();

      // Draw port tag midway
      const midX = (src.x + dst.x) / 2;
      const midY = (src.y + dst.y) / 2;
      ctx.fillStyle = "#64748b";
      ctx.font = "9px monospace";
      ctx.fillText(`:${link.port}`, midX, midY);
    });

    // Draw node vertices
    nodes.forEach((node) => {
      const coord = nodeCoords.get(node.id);
      if (!coord) return;

      const isSelected = selectedNode?.id === node.id;
      const isHighVolume = node.flows > 50;

      ctx.beginPath();
      ctx.arc(coord.x, coord.y, isSelected ? 12 : 9, 0, 2 * Math.PI);
      ctx.fillStyle = isHighVolume ? "#f59e0b" : "#0284c7";
      ctx.fill();
      ctx.strokeStyle = isSelected ? "#ffffff" : "#0f172a";
      ctx.lineWidth = 2;
      ctx.stroke();

      // Node label
      ctx.fillStyle = "#e2e8f0";
      ctx.font = "10px monospace";
      ctx.textAlign = "center";
      ctx.fillText(node.label, coord.x, coord.y + 20);
    });
  }, [nodes, filteredLinks, selectedNode]);

  return (
    <div>
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">
            <Share2 size={14} color="#06b6d4" />
            Empirical Communication Topology Graph
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Filter size={12} color="#94a3b8" />
            <input
              type="text"
              placeholder="Filter by Port (e.g. 80, 443)..."
              className="soc-input font-mono"
              style={{ width: 180 }}
              value={filterPort}
              onChange={(e) => setFilterPort(e.target.value)}
            />
          </div>
        </div>

        <div style={{ display: "flex", gap: 16 }}>
          <canvas
            ref={canvasRef}
            width={580}
            height={400}
            style={{
              background: "#090d16",
              borderRadius: 6,
              border: "1px solid #334155",
              cursor: "pointer",
            }}
          />

          {/* Node & Link Details Pane */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="soc-card" style={{ margin: 0, height: "100%" }}>
              <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", marginBottom: 8 }}>
                Topology Statistics
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 12 }}>
                <div className="kpi-box" style={{ padding: "8px 10px" }}>
                  <div className="kpi-label">Active Entities</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 16 }}>{nodes.length}</div>
                </div>
                <div className="kpi-box" style={{ padding: "8px 10px" }}>
                  <div className="kpi-label">Observed Links</div>
                  <div className="kpi-value font-mono" style={{ fontSize: 16 }}>{filteredLinks.length}</div>
                </div>
              </div>

              <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", marginBottom: 6 }}>
                Active Communication Peers
              </div>
              <div style={{ maxHeight: 240, overflowY: "auto" }}>
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Pseudonymized Host</th>
                      <th>Flows</th>
                      <th>Total Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {nodes.map((n) => (
                      <tr
                        key={n.id}
                        style={{ cursor: "pointer", background: selectedNode?.id === n.id ? "#1e293b" : "transparent" }}
                        onClick={() => setSelectedNode(n)}
                      >
                        <td className="font-mono">{n.label}</td>
                        <td className="font-mono">{n.flows}</td>
                        <td className="font-mono">{(n.bytes / 1024).toFixed(1)} KB</td>
                      </tr>
                    ))}
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
