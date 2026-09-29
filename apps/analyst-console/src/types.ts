export interface AnalysisJob {
  job_id: string;
  filename: string;
  file_type: string;
  file_size_bytes: number;
  source_file_sha256: string;
  status: "pending" | "ingesting" | "windowing" | "forecasting" | "explaining" | "completed" | "failed" | "cancelled";
  progress_percent: number;
  status_message: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  total_packets_parsed: number;
  total_flows_extracted: number;
  total_windows_generated: number;
  total_alerts_generated: number;
  parquet_flow_path?: string;
  parquet_state_path?: string;
  report_pdf_path?: string;
  error_details?: string;
}

export interface TimelineHistoricalPoint {
  window_index: number;
  timestamp: number;
  active_flows: number;
  packet_rate: number;
  byte_rate: number;
  observed_stage: string;
  is_compromised: boolean;
}

export interface TimelineForecastPoint {
  horizon_step: number;
  timestamp: number;
  infiltration_probability: number;
  uncertainty_lower: number;
  uncertainty_upper: number;
  predictive_entropy: number;
  predicted_stage: string;
  stage_probabilities: Record<string, number>;
  risk_velocity: number;
}

export interface TimelinePayload {
  analysis_id: string;
  history: TimelineHistoricalPoint[];
  forecast: TimelineForecastPoint[];
  max_risk_in_horizon: number;
  peak_stage: string;
}

export interface FeatureAttribution {
  feature_name: string;
  contribution: number;
  direction: "increases_risk" | "decreases_risk";
  relative_importance: number;
}

export interface TemporalAttribution {
  window_index: number;
  relative_window_offset: number;
  timestamp: number;
  contribution: number;
  active_flow_count: number;
}

export interface SupportingFlow {
  flow_id: string;
  src_ip_pseudo: string;
  dst_ip_pseudo: string;
  dst_port: number;
  protocol: number;
  packets: number;
  bytes: number;
  timestamp: number;
  anomaly_flags: string[];
}

export interface ExplanationResult {
  forecast_id: string;
  forecast_horizon: number;
  infiltration_probability: number;
  predicted_stage: number;
  uncertainty_bounds: {
    lower?: number;
    upper?: number;
    entropy?: number;
  };
  top_features: FeatureAttribution[];
  temporal_attributions: TemporalAttribution[];
  supporting_entities: Array<{
    host_pseudo: string;
    role: string;
    risk_score: number;
    unique_peers_contacted: number;
    top_dst_ports: number[];
    top_protocols: string[];
  }>;
  supporting_flows: SupportingFlow[];
  evidence_level: string;
  explanation_stability_score: number;
}

export interface AlertRecord {
  alert_id: string;
  analysis_id: string;
  forecast_id: string;
  created_at: string;
  severity: "informational" | "watch" | "warning" | "critical";
  state: "active" | "acknowledged" | "investigating" | "resolved" | "false_positive";
  forecast_horizon_seconds: number;
  forecast_horizon_steps: number;
  infiltration_probability: number;
  uncertainty_range: number;
  predicted_stage: number;
  primary_host_pseudo?: string;
  top_indicator_features: string[];
  supporting_flow_count: number;
  policy_rule_triggered: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
  analyst_notes?: string;
}

export interface FlowRecord {
  flow_id: string;
  src_ip_pseudo: string;
  dst_ip_pseudo: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  start_timestamp: number;
  end_timestamp: number;
  duration: number;
  fwd_packets: number;
  bwd_packets: number;
  fwd_bytes: number;
  bwd_bytes: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  syn_ack_ratio: number;
  rst_syn_ratio: number;
  tcp_handshake_completed: boolean;
  source_label?: string;
}

export interface TopologyNode {
  id: string;
  label: string;
  flows: number;
  bytes: number;
}

export interface TopologyLink {
  source: string;
  target: string;
  protocol: string;
  port: number;
  flows: number;
  bytes: number;
}

export interface CaptureStats {
  is_running: boolean;
  total_captured: number;
  dropped_packets: number;
  queue_size: number;
  max_queue_size: number;
  queue_pressure_pct: number;
  active_sessions_count: number;
}

export interface ReplayStatus {
  is_running: boolean;
  job_id: string | null;
  speed_multiplier: number;
  total_flows: number;
  replayed_flows: number;
  current_timestamp: number;
}

