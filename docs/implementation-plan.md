# AEGIS-WM Implementation Plan

## System Overview
AEGIS-WM (Anticipatory Enterprise Graph Intelligence System using Network World Models) is an offline-capable, open-source cyber defense framework that learns temporal state transition dynamics:
$$P(S_{t+1} \mid S_{t-m+1}, \dots, S_t)$$
and recursively simulates attacker progression over $K$ future time windows.

## Core Phases & Milestones

### Phase 1: Foundation & Data Architecture
- Canonical Pydantic schemas for flows, states, forecasts, explanations, and alerts.
- SQLite metadata and audit store + Parquet telemetry engine.
- Structured YAML configuration system.
- Initial ADRs and continuous project status tracking.

### Phase 2: Telemetry Ingestion & Extraction
- Authentic CICFlowMeter CSV adapter with schema canonicalization and validation.
- Native Scapy streaming PCAP parser with bidirectional session reconstruction.
- Calculation of flow features (counts, bytes, IAT, duration, TCP flags) and packet features (TTL variance, window stats, fragmentation, entropy, scan scores).
- Offline timestamp-accurate replay engine and safe authorized live capture module.

### Phase 3: Temporal State Construction & Attack Stages
- Sliding time-window aggregator ($\Delta t = 5$s, context length $m = 12$, forecast horizon $K = 6$).
- HMAC-SHA256 address pseudonymization to eliminate spatial memorization.
- Global network state vector $S_t \in \mathbb{R}^D$ and host-level communication graph.
- 9-class attack stage ontology and MITRE ATT&CK mapping with evidence confidence levels.
- Strict chronological and session-isolated split generator with automated leakage tests.

### Phase 4: Baseline Models & Evaluation Harness
- Persistence Forecaster ($S_{t+k} = S_t$).
- Logistic Regression on current window.
- Random Forest on current window.
- LSTM sequence classifier (without next-state transition loss).
- Evaluation metrics suite: Stage Macro/Weighted F1, Infiltration AUROC/AUPRC, Brier score, ECE, K-step MAE/RMSE, Lead Time.

### Phase 5: Temporal World Model & Recursive Rollout
- Temporal encoder (continuous feature projection, mask embedding, positional encoding, temporal transformer / gated recurrent unit).
- Distributional state transition head with Gaussian negative log-likelihood (bounded log variance).
- Multi-task decoders: Next-state reconstruction, attack stage softmax, horizon infiltration probability, uncertainty head.
- Scheduled sampling training loop with multi-task loss.
- Recursive $K$-step rollout engine supporting deterministic and Monte Carlo stochastic rollouts.
- Graph neural network extension (`TemporalGraphWorldModel`).

### Phase 6: Explainability, Attribution & Detection Policy
- Integrated Gradients & Temporal Occlusion via Captum for feature attribution.
- Temporal attribution identifying high-impact historical windows.
- Entity & flow evidence linking predictions to real underlying network flows.
- Configurable detection policy engine with alert states and deduplication.

### Phase 7: Service API & Analyst Console
- Production-grade FastAPI backend with streaming ingest, SSE progress, and REST endpoints.
- Restrained, information-dense React + TypeScript analyst console.
- Interactive timeline (observed history vs $K$-step forecast), network topology, flow evidence table, and explanation inspector.
- Offline HTML and PDF analysis report generator.

### Phase 8: Validation, Ablations & Packaging
- Ablation study execution (packet features, transition loss, rollout training, model architectures).
- Held-out attack family generalization testing.
- Two-page architecture document (`docs/architecture/AEGIS-WM-Architecture.pdf`), 5-slide presentation, and 2-minute demo plan (`docs/demo-script.md`).
- Dockerfile, docker-compose.yml, and Makefile.
