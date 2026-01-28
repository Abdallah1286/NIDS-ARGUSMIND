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

## Contributing
Contributions, bug reports, and feature requests are welcome — please open an issue or submit a PR. Include tests and updated docs where applicable.

## License
MIT License — see LICENSE file.

## Contact

Abdalla Osama Mohamed

- Email: [ao62811@gmail.com](mailto:ao62811@gmail.com)
- LinkedIn: [Abdullah Osama](https://www.linkedin.com/in/abdullah-osama-a5bb4839a/?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base_contact_details%3Bf1WlSKQHRMSzMAwPqQ%2FYig%3D%3D)