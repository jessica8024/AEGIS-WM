# AEGIS-WM: Architectural Specification

## Anticipatory Enterprise Graph Intelligence System using Network World Models

---

### Executive Overview

**AEGIS-WM** is an open-source, fully offline cyber defense framework that transforms enterprise threat detection from reactive, point-in-time signature matching into **anticipatory behavioral rollout**. Rather than asking *"is this packet or flow malicious right now?"*, AEGIS-WM models the underlying network environment as a continuous-state dynamical system, learning the transition distribution:

$$P(S_{t+1} \mid S_{t-m+1}, \dots, S_t)$$

where $S_t \in \mathbb{R}^{36}$ represents a comprehensive graph-statistical network state observed over sliding 5-second windows, and $m=12$ represents the historical context window (60 seconds). By iteratively unrolling this transition head over $K=6$ future steps (30 seconds), AEGIS-WM forecasts attacker progression, maps future network states to 9 canonical attack stages, estimates predictive uncertainty, and links every forecast to evidentiary flows.

---

### 1. Ingestion Pipeline & Session Reconstruction

```
Raw Telemetry (PCAP / PCAPNG / CSV / Live Interface)
       │
       ▼
[PcapStreamingParser / CICFlowCSVAdapter]
       │
       ▼
[BidirectionalFlowTracker]
  ├── 5-Tuple Key: (SrcIP, DstIP, SrcPort, DstPort, Protocol)
  ├── Directional Packet / Byte Statistics
  ├── TCP State Tracker (SYN, SYN-ACK, ACK, FIN, RST)
  └── Inter-Arrival Timing & Jitter
       │
       ▼
[DuckDB / PyArrow Parquet TelemetryStore]
       │
       ▼
[WindowStateAggregator (5.0s Windows, 5.0s Slide)]
  ├── 36-Dimensional Continuous State Vector S_t
  └── Dynamic Graph Snapshot G_t = (V_t, E_t)
```

1. **Streaming Packet Parsing**: Built on Scapy with high-throughput streaming generator processing, decoding Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS headers without loading full capture files into memory.
2. **Bidirectional Flow Reassembly**: Tracks bidirectional flow metrics with microsecond timestamp resolution, sliding expiry timeouts (120s TCP inactive, 30s UDP), and handshake completion verification.
3. **HMAC-SHA256 Pseudonymization**: All IP addresses are deterministically pseudonymized using an operator-configured secret salt before persistence or display, preserving graph topological structure while guaranteeing GDPR/HIPAA compliance.

---

### 2. Temporal State Space ($S_t \in \mathbb{R}^{36}$)

The enterprise communication state at window $t$ is encoded into a 36-dimensional continuous feature vector:

| Feature Dimension | Name | Description |
|---|---|---|
| 0 | `active_flow_count` | Number of concurrent bidirectional flows in window |
| 1 | `packet_rate` | Total packets observed per second |
| 2 | `byte_rate` | Total bytes observed per second |
| 3 | `syn_flag_ratio` | Ratio of TCP SYN packets to total TCP packets |
| 4 | `rst_flag_ratio` | Ratio of TCP RST packets to total TCP packets |
| 5 | `fin_flag_ratio` | Ratio of TCP FIN packets to total TCP packets |
| 6 | `ack_flag_ratio` | Ratio of TCP ACK packets to total TCP packets |
| 7 | `syn_ack_ratio` | Ratio of SYN packets to SYN-ACK packets (scanner indicator) |
| 8 | `rst_syn_ratio` | Ratio of RST packets to SYN packets (connection rejection indicator) |
| 9 | `dst_port_entropy` | Shannon entropy of destination port distribution |
| 10 | `src_port_entropy` | Shannon entropy of source port distribution |
| 11 | `dst_ip_entropy` | Shannon entropy of targeted IP address distribution |
| 12 | `src_ip_entropy` | Shannon entropy of transmitting IP address distribution |
| 13 | `mean_flow_duration` | Average active duration of completed flows in window |
| 14 | `std_flow_duration` | Standard deviation of flow duration in window |
| 15 | `mean_fwd_pkt_size` | Average size of forward packets (bytes) |
| 16 | `std_fwd_pkt_size` | Standard deviation of forward packet size |
| 17 | `mean_bwd_pkt_size` | Average size of backward/response packets (bytes) |
| 18 | `std_bwd_pkt_size` | Standard deviation of backward packet size |
| 19 | `tcp_handshake_ratio`| Fraction of TCP sessions successfully completing 3-way handshake |
| 20 | `tcp_window_mean` | Average TCP advertised receive window size |
| 21 | `tcp_window_zero_cnt`| Count of zero-window flow control packets |
| 22 | `ttl_mean` | Mean IP Time-To-Live (detects OS fingerprinting & hop anomalies) |
| 23 | `ttl_std` | Standard deviation of IP TTL |
| 24 | `dns_query_count` | Count of DNS request queries |
| 25 | `dns_error_ratio` | Ratio of NXDOMAIN / SRVFAIL responses to total DNS queries |
| 26 | `unique_src_hosts` | Count of unique transmitting hosts in window |
| 27 | `unique_dst_hosts` | Count of unique destination hosts in window |
| 28 | `unique_dst_ports` | Count of distinct destination ports targeted |
| 29 | `graph_density` | Communication graph edge density |
| 30 | `graph_degree_mean` | Average node degree in bipartite communication graph |
| 31 | `graph_degree_max` | Maximum node out-degree (hub/scanner detection) |
| 32 | `external_conn_ratio`| Fraction of connections crossing enterprise perimeter |
| 33 | `priv_port_ratio` | Fraction of connections targeting privileged ports (<1024) |
| 34 | `web_port_ratio` | Fraction of connections targeting HTTP/HTTPS (80, 443, 8080, 8443) |
| 35 | `ssh_rdp_port_ratio`| Fraction of connections targeting remote access (22, 3389) |

---

### 3. Network World Model Architecture

```
Context Window Sequence X = [S_{t-m+1}, ..., S_t]   (m=12, D=36)
                           │
                           ▼
          [Linear Input Projection: 36 -> 128]
                           │
          [Sinusoidal Positional Encoding]
                           │
       [Multi-Head Self-Attention (4 Heads, 2 Layers)]
                           │
                           ▼
              Context Latent State z_t (64-D)
                           │
        ┌──────────────────┴──────────────────┐
        ▼                                     ▼
[Probabilistic Transition Head]       [State Reconstruction Head]
 P(z_{t+1} | z_t) ~ N(mu, diag(sigma^2))      Reconstructs S_t (Loss Regularizer)
        │
        ▼
Latent Sample z_{t+1}
        │
        ├─────────────────────────────────────────────────┐
        ▼                                                 ▼
[Continuous State Decoder]                         [Multi-Task Decoders]
  mu_{S_{t+1}}, logvar_{S_{t+1}}                     ├── 9-Stage Logits (Focal Loss)
                                                      ├── Infiltration Risk (BCE Loss)
                                                      └── Epistemic Uncertainty
```

#### Training Objective: Multi-Task Loss Formulation

$$\mathcal{L}_{\text{total}} = \lambda_{\text{state}} \mathcal{L}_{\text{NLL}} + \lambda_{\text{stage}} \mathcal{L}_{\text{Focal}} + \lambda_{\text{risk}} \mathcal{L}_{\text{BCE}} + \lambda_{\text{recon}} \mathcal{L}_{\text{MSE}} + \lambda_{\text{cons}} \mathcal{L}_{\text{Rollout}}$$

1. **Gaussian Transition Negative Log-Likelihood**:
   $$\mathcal{L}_{\text{NLL}} = \frac{1}{2} \sum_{d=1}^{D} \left[ \log \sigma_d^2 + \frac{(S_{t+1, d} - \mu_d)^2}{\sigma_d^2} \right]$$
   where $\log \sigma_d^2$ is bounded to $[-7.0, 2.0]$ to prevent numerical divergence.
2. **Focal Loss for Extreme Imbalance**:
   $$\mathcal{L}_{\text{Focal}} = -\alpha_c (1 - p_c)^\gamma \log(p_c)$$
   with $\gamma = 2.0$, ensuring that rare attack stages (e.g., C2, Infiltration) receive sufficient gradient signal relative to predominant BENIGN traffic.
3. **Scheduled Sampling**: During training, the decoder transitions smoothly from ground-truth teacher forcing to autoregressive model-generated inputs with probability $\epsilon_k = \frac{k}{k + \exp(k / k_0)}$, preventing exposure bias during long multi-step rollouts.

---

### 4. Zero-Data-Leakage Certification

1. **Strict Chronological Splitting**: $t_{\text{train}} < t_{\text{val}} < t_{\text{test}}$. Random sample shuffling is strictly prohibited.
2. **Purge Isolation Buffer**: An explicit buffer of $m + K = 18$ windows (90 seconds) is discarded between adjacent splits, guaranteeing that no sliding sequence spans split boundaries.
3. **Train-Only Parameter Fitting**: Standard scalers and normalization statistics are computed exclusively on training windows and persisted to `models/state_scaler.json`.
4. **SafeTensors Serialization**: Model checkpoints are stored in SafeTensors format with cryptographically verified SHA-256 digests.

---

### 5. Deployment Topology

```
                       ┌─────────────────────────┐
                       │  Network Telemetry TAP  │
                       │  (PCAP / NetFlow / CSV) │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │  AEGIS-WM Core Engine   │
                       │  (FastAPI + Python)     │
                       │                         │
                       │  ├── Window Aggregator  │
                       │  ├── PyTorch Model      │
                       │  ├── Captum Attribution │
                       │  └── Policy Engine      │
                       └─────┬─────────────┬─────┘
                             │             │
                    SQLite / │             │ JSON / REST
                   DuckDB DB │             │
                             ▼             ▼
                       ┌───────────┐ ┌─────────────────────────┐
                       │ Telemetry │ │   SOC Analyst Console   │
                       │ & Alerts  │ │   (React / TypeScript)  │
                       └───────────┘ └─────────────────────────┘
```
