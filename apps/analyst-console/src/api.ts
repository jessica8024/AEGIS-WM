import {
  AlertRecord,
  AnalysisJob,
  CaptureStats,
  ExplanationResult,
  FlowRecord,
  ReplayStatus,
  TimelinePayload,
  TopologyLink,
  TopologyNode,
} from "./types";

const BASE_URL = "/api/v1";

export async function fetchHealth(): Promise<any> {
  const res = await fetch(`${BASE_URL}/health`);
  return res.json();
}

export async function fetchAnalyses(): Promise<AnalysisJob[]> {
  const res = await fetch(`${BASE_URL}/analyses?limit=50`);
  return res.json();
}

export async function fetchAnalysis(id: string): Promise<AnalysisJob> {
  const res = await fetch(`${BASE_URL}/analyses/${id}`);
  return res.json();
}

export async function startAnalysis(id: string): Promise<any> {
  const res = await fetch(`${BASE_URL}/analyses/${id}/start`, { method: "POST" });
  return res.json();
}

export async function uploadTelemetryFile(file: File): Promise<AnalysisJob> {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${BASE_URL}/analyses`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Upload failed");
  }
  return res.json();
}

export async function fetchTimeline(id: string): Promise<TimelinePayload> {
  const res = await fetch(`${BASE_URL}/analyses/${id}/timeline`);
  if (!res.ok) throw new Error("Timeline not available");
  return res.json();
}

export async function fetchFlows(
  id: string,
  limit: number = 50,
  offset: number = 0,
  port?: number,
  protocol?: number
): Promise<{ flows: FlowRecord[]; total: number }> {
  let url = `${BASE_URL}/analyses/${id}/flows?limit=${limit}&offset=${offset}`;
  if (port !== undefined) url += `&port=${port}`;
  if (protocol !== undefined) url += `&protocol=${protocol}`;
  const res = await fetch(url);
  if (!res.ok) return { flows: [], total: 0 };
  return res.json();
}

export async function fetchHosts(id: string, port?: number): Promise<{ nodes: TopologyNode[]; links: TopologyLink[] }> {
  let url = `${BASE_URL}/analyses/${id}/hosts`;
  if (port !== undefined && port !== null) {
    url += `?port=${port}`;
  }
  const res = await fetch(url);
  if (!res.ok) return { nodes: [], links: [] };
  return res.json();
}

export async function fetchExplanation(id: string, forecastId: string): Promise<ExplanationResult> {
  const res = await fetch(`${BASE_URL}/analyses/${id}/explanations/${forecastId}`);
  if (!res.ok) throw new Error("Explanation not available");
  return res.json();
}

export async function fetchAlerts(analysisId?: string): Promise<AlertRecord[]> {
  const url = analysisId ? `${BASE_URL}/alerts?analysis_id=${analysisId}` : `${BASE_URL}/alerts`;
  const res = await fetch(url);
  return res.json();
}

export async function acknowledgeAlert(alertId: string, analyst: string, notes: string): Promise<any> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/acknowledge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: jsonStringifySafe({ analyst_name: analyst, notes: notes, new_state: "acknowledged" }),
  });
  return res.json();
}

export async function startLiveCapture(interfaceName: string, filter: string): Promise<any> {
  const res = await fetch(`${BASE_URL}/capture/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: jsonStringifySafe({
      interface: interfaceName || null,
      bpf_filter: filter,
      monitoring_authorized: true,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Capture failed");
  }
  return res.json();
}

export async function stopLiveCapture(createAnalysis: boolean = true): Promise<any> {
  const res = await fetch(`${BASE_URL}/capture/stop?create_analysis=${createAnalysis}`, { method: "POST" });
  return res.json();
}

export async function fetchCaptureStats(): Promise<CaptureStats> {
  const res = await fetch(`${BASE_URL}/capture/stats`);
  if (!res.ok) throw new Error("Failed to load capture stats");
  return res.json();
}

export async function startReplay(jobId: string, speedMultiplier: number = 1.0): Promise<any> {
  const res = await fetch(`${BASE_URL}/replay/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: jsonStringifySafe({ job_id: jobId, speed_multiplier: speedMultiplier }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to start replay");
  }
  return res.json();
}

export async function stopReplay(): Promise<any> {
  const res = await fetch(`${BASE_URL}/replay/stop`, { method: "POST" });
  return res.json();
}

export async function fetchReplayStatus(): Promise<ReplayStatus> {
  const res = await fetch(`${BASE_URL}/replay/status`);
  if (!res.ok) throw new Error("Failed to load replay status");
  return res.json();
}

export async function fetchModels(): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/models`);
  return res.json();
}

export async function fetchBenchmarks(): Promise<any> {
  const res = await fetch(`${BASE_URL}/evaluations/benchmarks`);
  if (!res.ok) throw new Error("Failed to load benchmarks");
  return res.json();
}

function jsonStringifySafe(obj: any): string {
  return JSON.stringify(obj);
}
