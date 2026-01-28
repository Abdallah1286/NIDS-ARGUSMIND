# 🛡️ ArgusMind — Intelligent Network Vigilance

ArgusMind is a lightweight, real-time Network Intrusion Detection System (NIDS) designed to protect networked devices and IoT ecosystems from evolving threats such as botnets, DoS/DDoS, port scanning,[...]

## Key Features
- Hybrid detection: signature-based + anomaly-based machine learning (XGBoost).
- Real-time monitoring and alerts with minimal CPU/memory footprint.
- Integrates Tshark/Wireshark for packet capture and inspection.
- FastAPI backend for inference and a CustomTkinter GUI for easy local monitoring.
- Scalable and adaptable for multi-camera and IoT deployments.
- Open-source (MIT License).

## Technologies
- Python 3.8+
- XGBoost (pre-trained model: `model.pkl`)
- scikit-learn `StandardScaler` (`scaler.pkl`)
- Tshark / Wireshark for packet capture
- FastAPI for model inference (API.py)
- CustomTkinter for GUI (main app)
- Suricata (optional integration for signature-based detection)

## Repository Structure
Plaintext
```
├── docs/               # Project report (PDF) and diagrams
├── configs/            # System and API configuration files
├── API.py              # FastAPI server for ML inference
├── MY project .py      # Main GUI and monitoring application
├── model.pkl           # Pre-trained XGBoost model
├── scaler.pkl          # StandardScaler for feature normalization
└── README.md           # Project documentation
```

## Network Topology (textual description)
Below is a textual representation and explanation of the deployment topology from the provided diagram. This describes the placement of the IDS gateway (ArgusMind), the AI inference API, and the target virtual machine, including IPs, NIC roles, and the primary data flows.

ASCII-style diagram (text):
```text
                          Internet
                             |
                         Public IP:
                       20.203.57.169
                             |
                    [External admin access]
                             |
                         +-------+
                         |  FW/  |
                         |  LB   |
                         +---+---+
                             |
                   -----------------------
                   |  IDS Server (Gateway) |
                   |  - ArgusMind IDS      |
                   |  - NAT and Routing    |
                   |  NIC1: External (10.0.1.4)
                   |  NIC2: Internal (10.0.2.4)
                   -----------------------
                             |
       Extracted flow features |  ---->  AI Attack Detection API
       (custom flow features)  |         Public IP: 20.174.2.116
                             |          (AI model identifies attack & type)
       Replies with attack status & type <-----
                             |
                       Forced Tunnel
                       (0.0.0.0/0 -> through IDS)
                             |
                    Target Virtual Machine
                    IP: 10.0.2.5 (Windows 10 LTSC)
                    No public IP (isolated behind IDS)
```

Topology explanation and mapping
- Internet / Admin access:
  - Public admin access (example public IP shown in diagram): 20.203.57.169
  - Admin connects remotely to the IDS/Gateway for management and (optionally) to the target VM management port (example uses port 100 for target VM admin access).
- IDS Server (Gateway):
  - Acts as the network gateway and inspection point for the monitored environment.
  - Runs ArgusMind IDS (the project) and optionally Suricata for signature-based detection.
  - Performs NAT and routing for the target VM and other internal hosts.
  - NIC1 (External): 10.0.1.4 — faces upstream/internet, receives inbound traffic and admin connections.
  - NIC2 (Internal): 10.0.2.4 — faces the internal network where the Target VM resides.
  - Forced tunnel/route: traffic from the target may be forced through the IDS (0.0.0.0/0) so that all traffic is observed/filtered by ArgusMind.
- Target Virtual Machine:
  - Example IP: 10.0.2.5 — Windows 10 LTSC (no public IP).
  - All external traffic to/from the target is routed via the IDS gateway (so the IDS can capture/inspect flows).
- AI Attack Detection API:
  - Remote inference API with a public IP (example in diagram: 20.174.2.116).
  - ArgusMind extracts custom flow features from observed traffic and sends those features to the AI API for classification.
  - The AI model replies with attack status and (optionally) attack type, which ArgusMind consumes to generate alerts and take appropriate actions (logs, GUI alerts, or automated responses).
- Data flow summary:
  1. Live traffic (or pcap) passes through the IDS gateway.
  2. ArgusMind extracts flow-level and custom features from observed packets.
  3. Features are normalized (e.g., using `scaler.pkl`) and sent to the AI Attack Detection API (FastAPI inference endpoint).
  4. The AI model classifies the features and returns an attack label and metadata (type, confidence).
  5. ArgusMind correlates model replies with signature results (if Suricata used) and emits alerts in the GUI and logs.

Notes and deployment considerations
- Example IPs in the diagram are illustrative — replace them with your actual public/private IPs or dynamic addressing in production.
- Be mindful of privacy: do not store or expose private network captures or sensitive payload data in public repositories. Only use sanitized/synthetic samples for demos.
- If the AI API is remote/public, secure the feature transport channel (TLS) and authenticate requests (API keys, mutual TLS) to prevent tampering or data leakage.
- The forced route (0.0.0.0/0) in the diagram indicates that the Gateway is the next-hop for outbound traffic; in cloud deployments this could be implemented via user-defined routes, NAT gateway, or VM routing rules.
- Admin access (IDS management and target VM admin) should be protected by strong authentication and restricted to trusted admin hosts/IPs (e.g., jump host, VPN).
- Optionally add signature-based detection (Suricata) alongside ML-based detection for hybrid coverage (faster known-signature detection + ML for unknown anomalies).

## Quickstart

Prerequisites
- Python 3.8+
- pip
- Tshark installed and in PATH (for live capture)
- Optional: Suricata for signature-based detection

Install dependencies
```bash
python -m venv venv
source venv/bin/activate    # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Run the API (inference server)
```bash
python API.py
# or use uvicorn for production-like dev:
uvicorn API:app --host 0.0.0.0 --port 8000
```

Run the GUI
```bash
python "MY project .py"
```

Workflow overview
1. Capture traffic (pcap files or live via Tshark).
2. Features extracted from packets are normalized using `scaler.pkl`.
3. Features are scored by `model.pkl` (XGBoost) via the FastAPI inference endpoint.
4. GUI consumes inference results and displays real-time alerts and logs.

## Model & Data
- `scaler.pkl` — StandardScaler used to normalize features before inference.
- `model.pkl` — Pre-trained XGBoost classifier for anomaly/malware detection.

Note: Do not store or expose private network captures in the repository. Use sanitized or synthetic data for public demos.

## Results & Performance
- Detects Mirai-like botnet behavior, port scanning, DoS patterns, and RTSP exploit attempts.
- Designed for low resource overhead to preserve device/network performance during monitoring.

## Roadmap / Future Work
- Adaptive online learning for evolving anomaly detection.
- Support for 5GHz networks and industrial IoT protocols.
- Centralized cloud dashboard for multi-site monitoring.
- Expand training using public IoT attack datasets.


## Contact

Abdalla Osama Mohamed

- Email: [ao62811@gmail.com](mailto:ao62811@gmail.com)
- LinkedIn: [Abdullah Osama](https://www.linkedin.com/in/abdullah-osama-a5bb4839a/?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base_contact_details%3Bf1WlSKQHRMSzMAwPqQ%2FYig%3D%3D)
