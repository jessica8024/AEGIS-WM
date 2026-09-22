import React, { useState, useEffect } from "react";
import {
  LayoutDashboard,
  TrendingUp,
  Share2,
  TableProperties,
  SearchCode,
  Award,
  UploadCloud,
  Bell,
  AlertOctagon,
} from "lucide-react";
import { Header } from "./components/Header";
import { OverviewView } from "./components/OverviewView";
import { TimelineView } from "./components/TimelineView";
import { TopologyView } from "./components/TopologyView";
import { FlowEvidenceView } from "./components/FlowEvidenceView";
import { ExplanationView } from "./components/ExplanationView";
import { EvaluationView } from "./components/EvaluationView";
import { ImportCaptureView } from "./components/ImportCaptureView";
import {
  fetchAnalyses,
  fetchAlerts,
  fetchHealth,
  fetchTimeline,
} from "./api";
import { AlertRecord, AnalysisJob, TimelinePayload } from "./types";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<
    "overview" | "timeline" | "topology" | "flows" | "explanation" | "evaluation" | "capture"
  >("overview");

  const [health, setHealth] = useState<any>(null);
  const [analyses, setAnalyses] = useState<AnalysisJob[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string>("");
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [timeline, setTimeline] = useState<TimelinePayload | undefined>(undefined);
  const [loadingTimeline, setLoadingTimeline] = useState(false);

  // Load initial health and analyses
  const loadInitialData = async () => {
    try {
      const [h, a, al] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchAnalyses().catch(() => []),
        fetchAlerts().catch(() => []),
      ]);
      setHealth(h);
      setAnalyses(a);
      setAlerts(al);

      if (a.length > 0 && !selectedJobId) {
        setSelectedJobId(a[0].job_id);
      }
    } catch (e) {
      console.error("Failed to load initial data", e);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  // Poll active analysis status every 3 seconds if job is in progress
  useEffect(() => {
    const activeJob = analyses.find((a) => a.job_id === selectedJobId);
    if (!activeJob || ["completed", "failed", "cancelled"].includes(activeJob.status)) {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const freshAnalyses = await fetchAnalyses();
        setAnalyses(freshAnalyses);
        const freshAlerts = await fetchAlerts();
        setAlerts(freshAlerts);
      } catch (e) {
        console.error("Polling error", e);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [selectedJobId, analyses]);

  // Load timeline whenever selected analysis changes
  useEffect(() => {
    if (!selectedJobId) {
      setTimeline(undefined);
      return;
    }

    let isMounted = true;
    setLoadingTimeline(true);

    fetchTimeline(selectedJobId)
      .then((t) => {
        if (isMounted) {
          setTimeline(t);
          setLoadingTimeline(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setTimeline(undefined);
          setLoadingTimeline(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [selectedJobId]);

  const currentJob = analyses.find((a) => a.job_id === selectedJobId);
  const activeAlertCount = alerts.filter((a) => a.state === "active").length;

  return (
    <div className="app-container">
      {/* Top Header Bar */}
      <Header
        health={health}
        analyses={analyses}
        selectedJobId={selectedJobId}
        onSelectJob={(id) => setSelectedJobId(id)}
        onRefresh={loadInitialData}
      />

      {/* Main Workspace Frame */}
      <div className="main-content">
        {/* Sidebar Navigation */}
        <aside className="sidebar-nav">
          <button
            className={`nav-btn ${activeTab === "overview" ? "nav-btn-active" : ""}`}
            onClick={() => setActiveTab("overview")}
          >
            <LayoutDashboard size={16} />
            <span>Overview</span>
          </button>

          <button
            className={`nav-btn ${activeTab === "timeline" ? "nav-btn-active" : ""}`}
            onClick={() => setActiveTab("timeline")}
          >
            <TrendingUp size={16} />
            <span>Forecast Rollout</span>
          </button>

          <button
            className={`nav-btn ${activeTab === "topology" ? "nav-btn-active" : ""}`}
            onClick={() => setActiveTab("topology")}
          >
            <Share2 size={16} />
            <span>Graph Topology</span>
          </button>

          <button
            className={`nav-btn ${activeTab === "flows" ? "nav-btn-active" : ""}`}
            onClick={() => setActiveTab("flows")}
          >
            <TableProperties size={16} />
            <span>Flow Evidence</span>
          </button>

          <button
            className={`nav-btn ${activeTab === "explanation" ? "nav-btn-active" : ""}`}
            onClick={() => setActiveTab("explanation")}
          >
            <SearchCode size={16} />
            <span>Attribution & IG</span>
          </button>

          <div style={{ height: 1, background: "#334155", margin: "8px 0" }} />

          <button
            className={`nav-btn ${activeTab === "evaluation" ? "nav-btn-active" : ""}`}
            onClick={() => setActiveTab("evaluation")}
          >
            <Award size={16} />
            <span>Model Benchmarks</span>
          </button>

          <button
            className={`nav-btn ${activeTab === "capture" ? "nav-btn-active" : ""}`}
            onClick={() => setActiveTab("capture")}
          >
            <UploadCloud size={16} />
            <span>Import / Capture</span>
          </button>

          {/* Active Alert Indicator Badge at bottom of sidebar */}
          <div style={{ marginTop: "auto", padding: "12px 8px" }}>
            <div
              style={{
                padding: "8px 10px",
                background: activeAlertCount > 0 ? "rgba(239, 68, 68, 0.1)" : "#0f172a",
                border: `1px solid ${activeAlertCount > 0 ? "#7f1d1d" : "#334155"}`,
                borderRadius: 6,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Bell size={14} color={activeAlertCount > 0 ? "#ef4444" : "#64748b"} />
                <span style={{ fontSize: 11, color: activeAlertCount > 0 ? "#fca5a5" : "#94a3b8" }}>
                  Active Alerts
                </span>
              </div>
              <span
                className="badge font-mono"
                style={{
                  background: activeAlertCount > 0 ? "#ef4444" : "#1e293b",
                  color: "#ffffff",
                  fontSize: 10,
                  padding: "1px 6px",
                }}
              >
                {activeAlertCount}
              </span>
            </div>
          </div>
        </aside>

        {/* Content Workspace Pane */}
        <main className="content-pane">
          {activeTab === "overview" && (
            <OverviewView
              job={currentJob}
              timeline={timeline}
              alerts={alerts}
              onRefreshAlerts={() => fetchAlerts().then(setAlerts)}
            />
          )}

          {activeTab === "timeline" && (
            <TimelineView job={currentJob} timeline={timeline} />
          )}

          {activeTab === "topology" && (
            <TopologyView job={currentJob} />
          )}

          {activeTab === "flows" && (
            <FlowEvidenceView job={currentJob} />
          )}

          {activeTab === "explanation" && (
            <ExplanationView job={currentJob} timeline={timeline} />
          )}

          {activeTab === "evaluation" && (
            <EvaluationView />
          )}

          {activeTab === "capture" && (
            <ImportCaptureView
              onAnalysisCreated={(newJob) => {
                setAnalyses((prev) => [newJob, ...prev]);
                setSelectedJobId(newJob.job_id);
              }}
              analyses={analyses}
              onRefreshAnalyses={() => fetchAnalyses().then(setAnalyses)}
            />
          )}
        </main>
      </div>
    </div>
  );
};
