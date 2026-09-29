import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  Play,
  Pause,
  RotateCcw,
  Zap,
  Shield,
  AlertTriangle,
  Eye,
  Brain,
  Network,
  Lock,
  Radio,
  ServerCrash,
  ShieldAlert,
  ChevronRight,
  Activity,
  Crosshair,
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

interface SimNode {
  id: string;
  label: string;
  x: number;
  y: number;
  type: "attacker" | "gateway" | "server" | "db" | "endpoint" | "internet";
  compromised: boolean;
  targeted: boolean;
  isolated: boolean;
}

interface SimPacket {
  id: number;
  srcId: string;
  dstId: string;
  progress: number; // 0..1
  speed: number;
  color: string;
  size: number;
  malicious: boolean;
}

interface AttackStage {
  id: number;
  name: string;
  mitre: string;
  description: string;
  detail: string;
  duration: number; // ticks
  icon: React.ReactNode;
  color: string;
  aegisAction: string;
  detectionConfidence: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const TICK_MS = 60; // ~16 fps logic tick

const ATTACK_STAGES: AttackStage[] = [
  {
    id: 0,
    name: "Reconnaissance",
    mitre: "TA0043",
    description: "Attacker scans the perimeter for open ports and services",
    detail: "High-rate SYN probes from external IP. 2,312 packets/sec on ports 22, 80, 443, 3306.",
    duration: 120,
    icon: <Eye size={14} />,
    color: "#f59e0b",
    aegisAction: "World-Model encodes port-scan signature; entropy spike detected in flow feature space.",
    detectionConfidence: 0.61,
  },
  {
    id: 1,
    name: "Initial Access",
    mitre: "TA0001",
    description: "CVE-2024-1337 exploit payload delivered via HTTP POST",
    detail: "Malformed HTTP/1.1 POST to /api/upload. Shellcode embedded in multipart body. Gateway breached.",
    duration: 100,
    icon: <Zap size={14} />,
    color: "#ef4444",
    aegisAction: "GNN anomaly score 0.87 on Gateway node. AEGIS-WM raises WATCH alert. Temporal attention spikes.",
    detectionConfidence: 0.87,
  },
  {
    id: 2,
    name: "Execution",
    mitre: "TA0002",
    description: "Reverse shell spawned; attacker gains interactive session",
    detail: "Outbound beaconing on port 4444 to C2 server. Process injection: svchost ← cmd.exe detected.",
    duration: 90,
    icon: <ServerCrash size={14} />,
    color: "#ef4444",
    aegisAction: "Forecasting model predicts Lateral Movement within 3 windows (90 sec). Alert escalated to WARNING.",
    detectionConfidence: 0.93,
  },
  {
    id: 3,
    name: "Lateral Movement",
    mitre: "TA0008",
    description: "Attacker pivots from Gateway to internal App Server via SMB",
    detail: "Pass-the-Hash on port 445. NTLM relay attack. App-Server credential dumped via mimikatz.",
    duration: 110,
    icon: <Network size={14} />,
    color: "#dc2626",
    aegisAction: "Graph Intelligence detects anomalous east-west flow. App-Server node risk score: 0.91.",
    detectionConfidence: 0.91,
  },
  {
    id: 4,
    name: "Exfiltration",
    mitre: "TA0010",
    description: "Sensitive records streamed to C2 via DNS tunnelling",
    detail: "12,400 bytes/sec leaving DB-Server. DNS queries with base64-encoded payloads detected.",
    duration: 100,
    icon: <Radio size={14} />,
    color: "#991b1b",
    aegisAction: "AEGIS-WM issues CRITICAL alert. Automated isolation of DB-Server initiated. SOC notified.",
    detectionConfidence: 0.97,
  },
  {
    id: 5,
    name: "AEGIS Response",
    mitre: "—",
    description: "Automated containment and forensic evidence collection",
    detail: "Compromised nodes isolated. Full packet capture archived. Incident report generated.",
    duration: 130,
    icon: <Shield size={14} />,
    color: "#10b981",
    aegisAction: "Network world-model snapshot saved. Explainability report with SHAP attributions exported.",
    detectionConfidence: 1.0,
  },
];

const PIPELINE_STAGES = [
  { label: "Packet Ingestion", icon: <Activity size={11} />, color: "#06b6d4" },
  { label: "Flow Extraction", icon: <Network size={11} />, color: "#38bdf8" },
  { label: "Graph Construction", icon: <Share2Text />, color: "#818cf8" },
  { label: "World-Model Forecast", icon: <Brain size={11} />, color: "#a78bfa" },
  { label: "IG Attribution", icon: <Crosshair size={11} />, color: "#f472b6" },
  { label: "Alert Generation", icon: <ShieldAlert size={11} />, color: "#ef4444" },
];

function Share2Text() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" />
      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" /><line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
    </svg>
  );
}

// ─── Build static network topology ───────────────────────────────────────────

function buildNodes(W: number, H: number): SimNode[] {
  return [
    { id: "internet", label: "Internet", x: W * 0.08, y: H * 0.5, type: "internet", compromised: false, targeted: false, isolated: false },
    { id: "attacker", label: "Attacker", x: W * 0.18, y: H * 0.5, type: "attacker", compromised: false, targeted: false, isolated: false },
    { id: "gateway", label: "Gateway", x: W * 0.36, y: H * 0.5, type: "gateway", compromised: false, targeted: false, isolated: false },
    { id: "appserver", label: "App-Server", x: W * 0.56, y: H * 0.35, type: "server", compromised: false, targeted: false, isolated: false },
    { id: "dbserver", label: "DB-Server", x: W * 0.56, y: H * 0.65, type: "db", compromised: false, targeted: false, isolated: false },
    { id: "endpoint1", label: "Workstation-1", x: W * 0.76, y: H * 0.25, type: "endpoint", compromised: false, targeted: false, isolated: false },
    { id: "endpoint2", label: "Workstation-2", x: W * 0.76, y: H * 0.5, type: "endpoint", compromised: false, targeted: false, isolated: false },
    { id: "endpoint3", label: "Workstation-3", x: W * 0.76, y: H * 0.75, type: "endpoint", compromised: false, targeted: false, isolated: false },
  ];
}

const TOPOLOGY_LINKS = [
  { src: "internet", dst: "attacker" },
  { src: "attacker", dst: "gateway" },
  { src: "gateway", dst: "appserver" },
  { src: "gateway", dst: "dbserver" },
  { src: "appserver", dst: "endpoint1" },
  { src: "appserver", dst: "endpoint2" },
  { src: "dbserver", dst: "endpoint2" },
  { src: "dbserver", dst: "endpoint3" },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function lerp(a: number, b: number, t: number) {
  return a + (b - a) * t;
}

function nodeColor(node: SimNode) {
  if (node.isolated) return "#475569";
  if (node.compromised) return "#dc2626";
  if (node.targeted) return "#f59e0b";
  switch (node.type) {
    case "attacker": return "#ef4444";
    case "internet": return "#64748b";
    case "gateway": return "#0284c7";
    case "server": return "#818cf8";
    case "db": return "#a78bfa";
    case "endpoint": return "#10b981";
  }
}

function nodeRadius(node: SimNode) {
  if (node.type === "gateway" || node.type === "db") return 16;
  if (node.type === "server") return 15;
  if (node.type === "attacker") return 13;
  return 11;
}

// ─── Main SimulationView ──────────────────────────────────────────────────────

export const SimulationView: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const packetIdRef = useRef(0);
  const packetsRef = useRef<SimPacket[]>([]);
  const frameRef = useRef<number | null>(null);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [running, setRunning] = useState(false);
  const [tick, setTick] = useState(0);
  const [stageIdx, setStageIdx] = useState(0);
  const [stageTick, setStageTick] = useState(0);
  const [nodes, setNodes] = useState<SimNode[]>([]);
  const [pipelineActive, setPipelineActive] = useState(0);
  const [detectedEvents, setDetectedEvents] = useState<string[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [anomalyScore, setAnomalyScore] = useState(0);
  const [riskLevel, setRiskLevel] = useState<"SAFE" | "WATCH" | "WARNING" | "CRITICAL">("SAFE");
  const [canvasDims, setCanvasDims] = useState({ W: 820, H: 340 });
  const nodesRef = useRef<SimNode[]>([]);

  // ── Init ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    const dims = { W: 820, H: 340 };
    setCanvasDims(dims);
    const initial = buildNodes(dims.W, dims.H);
    setNodes(initial);
    nodesRef.current = initial;
  }, []);

  // ── Sync nodesRef ─────────────────────────────────────────────────────────
  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  // ── Canvas render loop ────────────────────────────────────────────────────
  const renderFrame = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const { W, H } = canvasDims;

    ctx.clearRect(0, 0, W, H);

    // Background grid
    ctx.strokeStyle = "rgba(51,65,85,0.35)";
    ctx.lineWidth = 0.5;
    for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
    for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

    const currentNodes = nodesRef.current;
    const nodeMap = new Map(currentNodes.map((n) => [n.id, n]));

    // Draw topology links
    TOPOLOGY_LINKS.forEach((link) => {
      const src = nodeMap.get(link.src);
      const dst = nodeMap.get(link.dst);
      if (!src || !dst) return;
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(dst.x, dst.y);
      ctx.strokeStyle = "rgba(71,85,105,0.6)";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 4]);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    // Move & draw packets
    const alive: SimPacket[] = [];
    packetsRef.current.forEach((pkt) => {
      const src = nodeMap.get(pkt.srcId);
      const dst = nodeMap.get(pkt.dstId);
      if (!src || !dst) return;
      pkt.progress += pkt.speed;
      if (pkt.progress >= 1) return; // expired

      const x = lerp(src.x, dst.x, pkt.progress);
      const y = lerp(src.y, dst.y, pkt.progress);

      // Glow trail
      if (pkt.malicious) {
        const grd = ctx.createRadialGradient(x, y, 0, x, y, pkt.size * 3);
        grd.addColorStop(0, pkt.color + "ff");
        grd.addColorStop(1, pkt.color + "00");
        ctx.beginPath();
        ctx.arc(x, y, pkt.size * 3, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(x, y, pkt.size, 0, Math.PI * 2);
      ctx.fillStyle = pkt.color;
      ctx.fill();
      alive.push(pkt);
    });
    packetsRef.current = alive;

    // Draw nodes
    currentNodes.forEach((node) => {
      const r = nodeRadius(node);
      const color = nodeColor(node);

      // Glow for compromised / targeted
      if (node.compromised || node.targeted) {
        const grd = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 2.5);
        grd.addColorStop(0, color + "55");
        grd.addColorStop(1, color + "00");
        ctx.beginPath();
        ctx.arc(node.x, node.y, r * 2.5, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();
      }

      // Isolation ring
      if (node.isolated) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
        ctx.strokeStyle = "#ef444480";
        ctx.lineWidth = 2;
        ctx.setLineDash([3, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = node.isolated ? "#475569" : "#0f172a";
      ctx.lineWidth = 2;
      ctx.stroke();

      // Label
      ctx.fillStyle = node.isolated ? "#64748b" : "#e2e8f0";
      ctx.font = "9px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.fillText(node.label, node.x, node.y + r + 13);

      // Icon overlay text for type
      ctx.fillStyle = "#0f172a";
      ctx.font = `bold ${r > 12 ? 10 : 9}px monospace`;
      ctx.fillText(
        node.type === "attacker" ? "☠" :
          node.type === "gateway" ? "⬡" :
            node.type === "db" ? "🗄" :
              node.type === "server" ? "⬢" :
                node.type === "internet" ? "🌐" : "⬤",
        node.x, node.y + 4
      );
    });

    frameRef.current = requestAnimationFrame(renderFrame);
  }, [canvasDims]);

  useEffect(() => {
    frameRef.current = requestAnimationFrame(renderFrame);
    return () => { if (frameRef.current) cancelAnimationFrame(frameRef.current); };
  }, [renderFrame]);

  // ── Spawn packets based on stage ─────────────────────────────────────────
  const spawnPackets = useCallback((stage: AttackStage) => {
    const routes: { src: string; dst: string; malicious: boolean }[] = [];
    switch (stage.id) {
      case 0:
        routes.push({ src: "attacker", dst: "gateway", malicious: true });
        routes.push({ src: "attacker", dst: "gateway", malicious: true });
        routes.push({ src: "internet", dst: "gateway", malicious: false });
        break;
      case 1:
        routes.push({ src: "attacker", dst: "gateway", malicious: true });
        routes.push({ src: "gateway", dst: "attacker", malicious: false });
        break;
      case 2:
        routes.push({ src: "gateway", dst: "attacker", malicious: true });
        routes.push({ src: "attacker", dst: "gateway", malicious: true });
        break;
      case 3:
        routes.push({ src: "gateway", dst: "appserver", malicious: true });
        routes.push({ src: "appserver", dst: "endpoint1", malicious: true });
        routes.push({ src: "appserver", dst: "endpoint2", malicious: true });
        break;
      case 4:
        routes.push({ src: "dbserver", dst: "internet", malicious: true });
        routes.push({ src: "dbserver", dst: "attacker", malicious: true });
        break;
      case 5:
        routes.push({ src: "gateway", dst: "attacker", malicious: false });
        routes.push({ src: "appserver", dst: "gateway", malicious: false });
        break;
    }

    routes.forEach((r) => {
      const id = packetIdRef.current++;
      packetsRef.current.push({
        id,
        srcId: r.src,
        dstId: r.dst,
        progress: 0,
        speed: 0.012 + Math.random() * 0.012,
        color: r.malicious ? (stage.id === 5 ? "#10b981" : stage.color) : "#38bdf8",
        size: r.malicious ? 4 : 2.5,
        malicious: r.malicious,
      });
    });
  }, []);

  // ── Logic tick ────────────────────────────────────────────────────────────
  const applyStageEffects = useCallback((stage: AttackStage, prevStage: number) => {
    setNodes((prev) => {
      const updated = prev.map((n) => ({ ...n }));
      // Reset targets
      updated.forEach((n) => (n.targeted = false));

      if (stage.id === 0) {
        updated.find((n) => n.id === "gateway")!.targeted = true;
      } else if (stage.id === 1) {
        updated.find((n) => n.id === "gateway")!.compromised = true;
      } else if (stage.id === 2) {
        // no new compromise yet
      } else if (stage.id === 3) {
        updated.find((n) => n.id === "appserver")!.compromised = true;
        updated.find((n) => n.id === "appserver")!.targeted = true;
      } else if (stage.id === 4) {
        updated.find((n) => n.id === "dbserver")!.compromised = true;
      } else if (stage.id === 5) {
        // Isolate compromised nodes
        updated.forEach((n) => {
          if (n.compromised) { n.isolated = true; n.compromised = false; }
        });
      }
      return updated;
    });

    // Detection event log
    setDetectedEvents((prev) => {
      const ts = new Date().toLocaleTimeString();
      return [`[${ts}] AEGIS: ${stage.aegisAction}`, ...prev].slice(0, 30);
    });

    // Risk level
    if (stage.id <= 0) setRiskLevel("WATCH");
    else if (stage.id === 1) setRiskLevel("WARNING");
    else if (stage.id >= 2 && stage.id <= 4) setRiskLevel("CRITICAL");
    else if (stage.id === 5) setRiskLevel("WATCH");
  }, []);

  useEffect(() => {
    if (!running) {
      if (tickRef.current) clearInterval(tickRef.current);
      return;
    }

    let localTick = tick;
    let localStageTick = stageTick;
    let localStageIdx = stageIdx;
    let localPipelineActive = pipelineActive;
    let localTotalPackets = totalPackets;

    tickRef.current = setInterval(() => {
      localTick++;
      localStageTick++;
      localTotalPackets += Math.floor(Math.random() * 18) + 5;
      localPipelineActive = (localPipelineActive + 1) % PIPELINE_STAGES.length;

      setTick(localTick);
      setStageTick(localStageTick);
      setTotalPackets(localTotalPackets);
      setPipelineActive(localPipelineActive);

      const stage = ATTACK_STAGES[localStageIdx];
      if (!stage) { setRunning(false); return; }

      // Anomaly score ramps with stage id
      const targetScore = stage.detectionConfidence;
      setAnomalyScore((prev) => Math.min(1, prev + (targetScore - prev) * 0.04));

      // Spawn packets periodically
      if (localStageTick % 4 === 0) spawnPackets(stage);

      // Advance stage
      if (localStageTick >= stage.duration) {
        localStageTick = 0;
        localStageIdx = Math.min(localStageIdx + 1, ATTACK_STAGES.length - 1);
        setStageTick(0);
        setStageIdx(localStageIdx);
        applyStageEffects(ATTACK_STAGES[localStageIdx], localStageIdx - 1);
        if (localStageIdx === ATTACK_STAGES.length - 1 && localStageTick >= ATTACK_STAGES[localStageIdx].duration) {
          setRunning(false);
        }
      }
    }, TICK_MS);

    return () => { if (tickRef.current) clearInterval(tickRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  const handleReset = () => {
    setRunning(false);
    setTick(0);
    setStageTick(0);
    setStageIdx(0);
    setStageTick(0);
    setPipelineActive(0);
    setAnomalyScore(0);
    setRiskLevel("SAFE");
    setDetectedEvents([]);
    setTotalPackets(0);
    packetsRef.current = [];
    const initial = buildNodes(canvasDims.W, canvasDims.H);
    setNodes(initial);
    nodesRef.current = initial;
  };

  const handleStart = () => {
    if (stageIdx === ATTACK_STAGES.length - 1 && stageTick >= ATTACK_STAGES[stageIdx].duration) {
      handleReset();
      return;
    }
    setRunning((r) => !r);
    if (stageIdx === 0 && stageTick === 0) {
      applyStageEffects(ATTACK_STAGES[0], -1);
    }
  };

  const currentStage = ATTACK_STAGES[stageIdx];
  const stageProgress = Math.min(1, stageTick / (currentStage?.duration ?? 1));

  const riskColor = {
    SAFE: "#10b981",
    WATCH: "#f59e0b",
    WARNING: "#ef4444",
    CRITICAL: "#dc2626",
  }[riskLevel];

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* ── Title bar ── */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <ShieldAlert size={18} color="#ef4444" />
            <span style={{ fontSize: 16, fontWeight: 700, color: "#f8fafc", letterSpacing: "0.04em" }}>
              ATTACK SIMULATION ENGINE
            </span>
            <span className="badge badge-critical" style={{ fontSize: 9, letterSpacing: "0.08em" }}>AEGIS-WM</span>
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 4 }}>
            Live multi-stage adversarial emulation · MITRE ATT&CK aligned · Real-time anticipatory detection
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {/* Risk badge */}
          <div style={{
            padding: "6px 14px", borderRadius: 6, border: `1px solid ${riskColor}`,
            background: riskColor + "18", display: "flex", alignItems: "center", gap: 8,
          }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%", background: riskColor,
              animation: riskLevel !== "SAFE" ? "pulse-dot 1.2s ease-in-out infinite" : "none",
            }} />
            <span style={{ fontSize: 12, fontWeight: 700, color: riskColor, fontFamily: "monospace" }}>{riskLevel}</span>
          </div>

          <button className="btn btn-secondary" onClick={handleReset} style={{ gap: 6 }}>
            <RotateCcw size={13} /> Reset
          </button>
          <button
            className={`btn ${running ? "btn-danger" : "btn-primary"}`}
            onClick={handleStart}
            style={{ gap: 6, minWidth: 90 }}
          >
            {running ? <><Pause size={13} /> Pause</> : <><Play size={13} /> {tick === 0 ? "Start" : "Resume"}</>}
          </button>
        </div>
      </div>

      {/* ── Stage progress rail ── */}
      <div className="soc-card" style={{ padding: "12px 16px" }}>
        <div style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 10 }}>
          Attack Kill-Chain Progression
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 0 }}>
          {ATTACK_STAGES.map((s, i) => {
            const done = i < stageIdx;
            const active = i === stageIdx;
            return (
              <React.Fragment key={s.id}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flex: 1 }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: "50%",
                    background: done ? "#10b981" : active ? s.color : "#1e293b",
                    border: `2px solid ${done ? "#059669" : active ? s.color : "#334155"}`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: done || active ? "#fff" : "#64748b",
                    boxShadow: active ? `0 0 12px ${s.color}88` : "none",
                    transition: "all 0.3s ease",
                  }}>
                    {done ? <Lock size={13} /> : s.icon}
                  </div>
                  <div style={{ fontSize: 9, color: active ? s.color : done ? "#10b981" : "#64748b", marginTop: 5, fontWeight: active ? 700 : 500, textAlign: "center" }}>
                    {s.name}
                  </div>
                  <div style={{ fontSize: 8, color: "#475569", fontFamily: "monospace" }}>{s.mitre}</div>
                </div>
                {i < ATTACK_STAGES.length - 1 && (
                  <div style={{ flex: 0.5, height: 2, background: i < stageIdx ? "#059669" : "#1e293b", transition: "background 0.5s" }} />
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Current stage progress bar */}
        <div style={{ marginTop: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ fontSize: 10, color: currentStage?.color, fontWeight: 700 }}>
              {currentStage?.name} — {currentStage?.mitre}
            </span>
            <span style={{ fontSize: 10, color: "#64748b", fontFamily: "monospace" }}>
              {Math.round(stageProgress * 100)}%
            </span>
          </div>
          <div style={{ height: 4, background: "#1e293b", borderRadius: 2, overflow: "hidden" }}>
            <div style={{
              height: "100%", width: `${stageProgress * 100}%`,
              background: `linear-gradient(90deg, ${currentStage?.color}88, ${currentStage?.color})`,
              transition: "width 0.1s linear",
            }} />
          </div>
        </div>
      </div>

      {/* ── Main area: Canvas + Right panels ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 310px", gap: 16 }}>

        {/* Canvas */}
        <div className="soc-card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{
            padding: "10px 14px", borderBottom: "1px solid #1e293b",
            display: "flex", alignItems: "center", justifyContent: "space-between",
          }}>
            <span className="soc-card-title">
              <Network size={13} color="#06b6d4" />
              Enterprise Network Graph — Live Topology
            </span>
            <div style={{ display: "flex", gap: 16, fontSize: 10, color: "#64748b" }}>
              <span>● Benign</span>
              <span style={{ color: "#f59e0b" }}>● Targeted</span>
              <span style={{ color: "#ef4444" }}>● Compromised</span>
              <span style={{ color: "#475569" }}>● Isolated</span>
            </div>
          </div>
          <canvas
            ref={canvasRef}
            width={canvasDims.W}
            height={canvasDims.H}
            style={{ display: "block", width: "100%", background: "#090d16" }}
          />
        </div>

        {/* Right column */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

          {/* KPI row */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <div className="kpi-box">
              <div className="kpi-label">Packets Seen</div>
              <div className="kpi-value font-mono" style={{ fontSize: 18, color: "#38bdf8" }}>
                {totalPackets.toLocaleString()}
              </div>
            </div>
            <div className="kpi-box">
              <div className="kpi-label">Anomaly Score</div>
              <div className="kpi-value font-mono" style={{ fontSize: 18, color: anomalyScore > 0.8 ? "#ef4444" : anomalyScore > 0.5 ? "#f59e0b" : "#10b981" }}>
                {anomalyScore.toFixed(2)}
              </div>
            </div>
          </div>

          {/* Anomaly gauge */}
          <div className="soc-card" style={{ padding: "10px 14px" }}>
            <div style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase", marginBottom: 8 }}>
              World-Model Risk Score
            </div>
            <div style={{ height: 10, background: "#0f172a", borderRadius: 5, overflow: "hidden", marginBottom: 6 }}>
              <div style={{
                height: "100%",
                width: `${anomalyScore * 100}%`,
                background: anomalyScore > 0.85 ? "linear-gradient(90deg,#7f1d1d,#ef4444)" :
                  anomalyScore > 0.5 ? "linear-gradient(90deg,#78350f,#f59e0b)" :
                    "linear-gradient(90deg,#064e3b,#10b981)",
                transition: "width 0.3s ease, background 0.5s",
                borderRadius: 5,
              }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#475569", fontFamily: "monospace" }}>
              <span>0.00</span><span>0.50</span><span>1.00</span>
            </div>
          </div>

          {/* AEGIS Pipeline */}
          <div className="soc-card" style={{ padding: "10px 14px" }}>
            <div style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
              <Brain size={11} color="#a78bfa" /> AEGIS-WM Pipeline
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              {PIPELINE_STAGES.map((ps, i) => {
                const isActive = running && i === pipelineActive;
                const isDone = running && i < pipelineActive;
                return (
                  <div key={i} style={{
                    display: "flex", alignItems: "center", gap: 8,
                    padding: "4px 8px", borderRadius: 4,
                    background: isActive ? ps.color + "18" : "transparent",
                    border: `1px solid ${isActive ? ps.color + "55" : "transparent"}`,
                    transition: "all 0.2s",
                  }}>
                    <div style={{ color: isActive ? ps.color : isDone ? "#10b981" : "#334155" }}>
                      {ps.icon}
                    </div>
                    <span style={{ fontSize: 10, color: isActive ? ps.color : isDone ? "#94a3b8" : "#475569", flex: 1, fontWeight: isActive ? 600 : 400 }}>
                      {ps.label}
                    </span>
                    {isActive && (
                      <div style={{ width: 6, height: 6, borderRadius: "50%", background: ps.color, animation: "pulse-dot 0.8s ease-in-out infinite" }} />
                    )}
                    {isDone && !isActive && (
                      <span style={{ fontSize: 9, color: "#10b981" }}>✓</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ── Stage detail + Event log ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

        {/* Current Stage Detail */}
        <div className="soc-card">
          <div className="soc-card-header">
            <span className="soc-card-title">
              <AlertTriangle size={13} color={currentStage?.color} />
              Current Stage Intelligence
            </span>
            <span className="badge" style={{ background: currentStage?.color + "22", color: currentStage?.color, border: `1px solid ${currentStage?.color}44` }}>
              {currentStage?.mitre}
            </span>
          </div>

          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: currentStage?.color, marginBottom: 4 }}>
              {currentStage?.name}
            </div>
            <div style={{ fontSize: 12, color: "#94a3b8", marginBottom: 10 }}>
              {currentStage?.description}
            </div>
            <div style={{ padding: "8px 10px", background: "#0f172a", borderRadius: 4, border: "1px solid #1e293b", fontFamily: "monospace", fontSize: 11, color: "#e2e8f0", lineHeight: 1.6 }}>
              {currentStage?.detail}
            </div>
          </div>

          <div style={{ padding: "8px 10px", background: "#10b98110", border: "1px solid #05966955", borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: "#6ee7b7", fontWeight: 700, marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.06em" }}>
              🛡 AEGIS-WM Response
            </div>
            <div style={{ fontSize: 11, color: "#a7f3d0", lineHeight: 1.5 }}>
              {currentStage?.aegisAction}
            </div>
          </div>

          {/* Detection confidence bar */}
          <div style={{ marginTop: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "#64748b", marginBottom: 4 }}>
              <span>Detection Confidence</span>
              <span className="font-mono">{(currentStage?.detectionConfidence * 100).toFixed(0)}%</span>
            </div>
            <div style={{ height: 6, background: "#0f172a", borderRadius: 3, overflow: "hidden" }}>
              <div style={{
                height: "100%",
                width: `${(currentStage?.detectionConfidence ?? 0) * 100}%`,
                background: "linear-gradient(90deg, #0284c7, #06b6d4)",
                borderRadius: 3,
                transition: "width 0.5s ease",
              }} />
            </div>
          </div>
        </div>

        {/* Event Log */}
        <div className="soc-card">
          <div className="soc-card-header">
            <span className="soc-card-title">
              <Activity size={13} color="#06b6d4" />
              AEGIS Detection Event Log
            </span>
            <span style={{ fontSize: 10, color: "#64748b", fontFamily: "monospace" }}>
              {detectedEvents.length} events
            </span>
          </div>
          <div style={{ height: 220, overflowY: "auto", display: "flex", flexDirection: "column", gap: 3 }}>
            {detectedEvents.length === 0 ? (
              <div style={{ color: "#475569", fontSize: 11, textAlign: "center", paddingTop: 40 }}>
                Press Start to begin the simulation…
              </div>
            ) : (
              detectedEvents.map((ev, i) => (
                <div key={i} style={{
                  padding: "4px 8px", background: "#0f172a", borderRadius: 3,
                  fontSize: 10, color: i === 0 ? "#38bdf8" : "#64748b",
                  fontFamily: "monospace", borderLeft: `2px solid ${i === 0 ? "#0284c7" : "#1e293b"}`,
                  transition: "color 1s",
                }}>
                  <ChevronRight size={9} style={{ display: "inline", marginRight: 4, color: "#334155" }} />
                  {ev}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── MITRE ATT&CK stage table ── */}
      <div className="soc-card">
        <div className="soc-card-header">
          <span className="soc-card-title">
            <Crosshair size={13} color="#f472b6" />
            MITRE ATT&CK Matrix — Simulated Tactics
          </span>
        </div>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Stage</th>
              <th>MITRE ID</th>
              <th>Description</th>
              <th>AEGIS Detection</th>
              <th>Confidence</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {ATTACK_STAGES.map((s, i) => {
              const done = i < stageIdx;
              const active = i === stageIdx;
              return (
                <tr key={s.id} style={{ background: active ? s.color + "0d" : "transparent" }}>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, color: active ? s.color : done ? "#94a3b8" : "#475569" }}>
                      {s.icon} {s.name}
                    </div>
                  </td>
                  <td className="font-mono" style={{ color: "#64748b", fontSize: 11 }}>{s.mitre}</td>
                  <td style={{ color: "#94a3b8", fontSize: 11, maxWidth: 220 }}>{s.description}</td>
                  <td style={{ color: "#6ee7b7", fontSize: 11, maxWidth: 220 }}>{s.aegisAction.slice(0, 80)}…</td>
                  <td>
                    <div className="font-mono" style={{ fontSize: 11, color: s.detectionConfidence > 0.85 ? "#ef4444" : s.detectionConfidence > 0.6 ? "#f59e0b" : "#10b981" }}>
                      {(s.detectionConfidence * 100).toFixed(0)}%
                    </div>
                  </td>
                  <td>
                    {done && <span className="badge badge-benign">Completed</span>}
                    {active && running && <span className="badge badge-critical">Active</span>}
                    {active && !running && tick > 0 && <span className="badge badge-warning">Paused</span>}
                    {active && tick === 0 && <span className="badge badge-info">Ready</span>}
                    {!done && !active && <span className="badge" style={{ background: "#0f172a", color: "#475569", border: "1px solid #1e293b" }}>Pending</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* ── System Architecture: How AEGIS-WM Works ── */}
      <div className="soc-card" style={{ border: "1px solid #1e293b", background: "linear-gradient(180deg, #0f172a 0%, #090d16 100%)" }}>
        <div className="soc-card-header">
          <span className="soc-card-title">
            <Brain size={15} color="#a78bfa" />
            HOW AEGIS-WM WORKS: ANTICIPATORY ENTERPRISE GRAPH INTELLIGENCE SYSTEM
          </span>
          <span className="badge badge-info font-mono" style={{ fontSize: 10 }}>
            NETWORK WORLD MODEL ARCHITECTURE
          </span>
        </div>

        <p style={{ color: "#94a3b8", fontSize: 12, lineHeight: 1.6, marginBottom: 16 }}>
          Unlike reactive Intrusion Detection Systems (IDS) that trigger <strong style={{ color: "#f8fafc" }}>after</strong> malicious payloads execute,
          <strong style={{ color: "#38bdf8" }}> AEGIS-WM</strong> constructs a continuous dynamic graph of network communications and employs a
          <strong style={{ color: "#a78bfa" }}> Latent World Model</strong> to simulate and forecast adversarial trajectory rollouts
          <strong style={{ color: "#10b981" }}> 30 to 180 seconds ahead</strong> of execution.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, marginBottom: 16 }}>
          {/* Card 1 */}
          <div style={{ background: "#0b1220", border: "1px solid #1e293b", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <div style={{ width: 22, height: 22, borderRadius: 4, background: "#0284c722", color: "#38bdf8", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 11 }}>
                1
              </div>
              <span style={{ fontSize: 12, fontWeight: 700, color: "#f8fafc" }}>Dynamic Graph Representation</span>
            </div>
            <p style={{ color: "#64748b", fontSize: 11, lineHeight: 1.5 }}>
              Raw PCAP/NetFlow streams are partitioned into discrete micro-windows. Communicating endpoints become nodes <code className="font-mono" style={{ color: "#06b6d4" }}>V</code> and directional packet exchanges become multi-attributed edges <code className="font-mono" style={{ color: "#06b6d4" }}>E</code>.
            </p>
          </div>

          {/* Card 2 */}
          <div style={{ background: "#0b1220", border: "1px solid #1e293b", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <div style={{ width: 22, height: 22, borderRadius: 4, background: "#818cf822", color: "#818cf8", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 11 }}>
                2
              </div>
              <span style={{ fontSize: 12, fontWeight: 700, color: "#f8fafc" }}>Spatial Graph Neural Net</span>
            </div>
            <p style={{ color: "#64748b", fontSize: 11, lineHeight: 1.5 }}>
              Message-passing GNN layers compress topological relationships, flow distributions, and lateral connection attempts into high-dimensional latent graph embeddings <code className="font-mono" style={{ color: "#818cf8" }}>z_t</code>.
            </p>
          </div>

          {/* Card 3 */}
          <div style={{ background: "#0b1220", border: "1px solid #1e293b", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <div style={{ width: 22, height: 22, borderRadius: 4, background: "#a78bfa22", color: "#a78bfa", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 11 }}>
                3
              </div>
              <span style={{ fontSize: 12, fontWeight: 700, color: "#f8fafc" }}>Latent World-Model Rollout</span>
            </div>
            <p style={{ color: "#64748b", fontSize: 11, lineHeight: 1.5 }}>
              The Recurrent Network World Model predicts forward dynamics in latent space: <code className="font-mono" style={{ color: "#a78bfa" }}>z_(t+k) = f(z_(t+k-1), u_t)</code>. This projects attack paths prior to actual packet transmission.
            </p>
          </div>

          {/* Card 4 */}
          <div style={{ background: "#0b1220", border: "1px solid #1e293b", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <div style={{ width: 22, height: 22, borderRadius: 4, background: "#10b98122", color: "#10b981", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 11 }}>
                4
              </div>
              <span style={{ fontSize: 12, fontWeight: 700, color: "#f8fafc" }}>Anticipatory Defense Action</span>
            </div>
            <p style={{ color: "#64748b", fontSize: 11, lineHeight: 1.5 }}>
              When forecasted risk velocity <code className="font-mono" style={{ color: "#10b981" }}>dv/dt</code> crosses threshold with low predictive entropy, AEGIS triggers pre-emptive containment and isolates critical subnets before data exfiltration occurs.
            </p>
          </div>
        </div>

        {/* Comparison table */}
        <div style={{ background: "#080c14", border: "1px solid #1e293b", borderRadius: 6, padding: "10px 14px" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#94a3b8", textTransform: "uppercase", marginBottom: 8 }}>
            Comparison: Reactive IDS vs. AEGIS-WM World Model
          </div>
          <table className="soc-table" style={{ fontSize: 11 }}>
            <thead>
              <tr>
                <th>Capability</th>
                <th>Legacy Reactive IDS / SIEM</th>
                <th>AEGIS-WM Network World Model</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600, color: "#f8fafc" }}>Detection Timing</td>
                <td style={{ color: "#ef4444" }}>Post-Execution (alerts 5-15 min after breach)</td>
                <td style={{ color: "#10b981", fontWeight: 600 }}>Anticipatory (forecasts 30-180 sec ahead)</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: "#f8fafc" }}>Context Modeling</td>
                <td style={{ color: "#64748b" }}>Isolated signature matching or point tabular logs</td>
                <td style={{ color: "#38bdf8" }}>Full enterprise graph topology + temporal recurrence</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: "#f8fafc" }}>Uncertainty Quantification</td>
                <td style={{ color: "#64748b" }}>Deterministic heuristic or binary score</td>
                <td style={{ color: "#a78bfa" }}>Epistemic & Aleatoric predictive entropy bounds</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: "#f8fafc" }}>Explainability</td>
                <td style={{ color: "#64748b" }}>Opaque rule ID or black-box alert</td>
                <td style={{ color: "#34d399" }}>Integrated Gradients flow attribution & MITRE mapping</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* ── CSS pulse animation ── */}
      <style>{`
        @keyframes pulse-dot {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(0.7); }
        }
        .nav-btn-active {
          background-color: #0369a1 !important;
          color: #ffffff !important;
        }
      `}</style>
    </div>
  );
};
