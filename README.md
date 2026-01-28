This project, ArgusMind, is an intelligent Network Intrusion Detection System (NIDS) designed to provide high-fidelity threat monitoring and real-time classification using machine learning.

🛡️ ArgusMind
[ Intelligent-Network-Vigilance ]

ArgusMind is a state-of-the-art Network Intrusion Detection System (NIDS) that monitors and protects network infrastructure against evolving cyber threats. By leveraging a high-performance XGBoost Classifier, the system achieves an AUC of 99.86% and an F1-Score of 98% in identifying malicious traffic patterns.

📌 Overview
This project addresses critical cybersecurity vulnerabilities in modern network environments where devices are often targeted by botnets, DoS/DDoS attacks, and unauthorized access attempts. ArgusMind implements a lightweight, real-time solution using a FastAPI backend for model inference and a modern CustomTkinter GUI for seamless user interaction.

🎯 Key Features

ML-Powered Detection: Utilizes an optimized XGBoost model to classify 8 distinct attack types, including DDoS, Backdoor, and Port Scanning.

Real-Time Monitoring: Integrated packet capture via TShark (Wireshark) for live traffic analysis and instant threat detection.


Automatic Feature Engineering: Dynamically calculates complex network metrics like packets per millisecond and average packet size for increased accuracy.

Interactive Dashboard: Features live attack timelines, severity-coded alerts, and detailed traffic statistics.

Secure Logging: maintains a local SQLite database for threat history and supports professional attack report exports.

🛠️ Implementation
Tools & Technologies

Machine Learning: XGBoost, Scikit-learn (StandardScaler), Joblib.
+1


Backend: FastAPI with Pydantic for robust data validation and WebSocket support for real-time updates.


Frontend GUI: CustomTkinter for a modern "Dark Mode" interface, Matplotlib for live data visualization.

Traffic Analysis: TShark / Wireshark for packet inspection and extraction.

Workflow
Data Collection: Real-time capture of network traffic (TCP/UDP) via the selected network interface.


Pre-processing: Raw packet data is transformed into engineered features and scaled via a pre-trained StandardScaler.


Threat Detection: The API processes features and returns a classification with a confidence score.

Alerting & Visualization: Detected attacks trigger audible alarms and are immediately displayed on the Security Alerts timeline.

📊 Results

High Precision: Successfully identifies Mirai botnets, brute force, and various DoS/DDoS vectors with a ~98% overall accuracy.
📂 Repository Structure
Plaintext
├── API.py               # FastAPI server for ML model inference
├── MY project.py        # Main CustomTkinter GUI & Monitoring engine
├── model.pkl            # Pre-trained XGBoost Classifier
├── scaler.pkl           # Trained StandardScaler for feature normalization
├── requirements.txt     # Project dependencies
└── sounds/              # Alert and background audio assets
🚀 Future Work
Integrate deep learning for adaptive anomaly detection against zero-day threats.

Extend support for 5GHz networks and industrial IoT specialized protocols.

Develop a cloud-based centralized monitoring dashboard for multi-site management.

📜 License
Open-source under the MIT License.



Low Latency: Optimized inference pipeline ensures minimal impact on network performance.

Scalability: Adaptable to various network environments, from home IoT setups to industrial local networks.
