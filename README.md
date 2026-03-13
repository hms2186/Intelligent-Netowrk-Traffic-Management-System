INTMS: Intelligent Network Traffic Management System
I built this project to solve a specific problem: static firewalls are too slow for modern, zero-day threats. If a security system only looks for known signatures, it misses anything it hasn't seen before.

INTMS (Intelligent Network Traffic Management System) takes a different approach. Instead of looking for "bad" IPs, it looks for "weird" math. It establishes a baseline of what your network normally looks like and uses statistical heuristics to flag anomalies the moment they happen.

How it handles detection

The core logic relies on the 3-Sigma (3σ) rule. The backend captures live packet metadata and calculates a rolling Z-Score for traffic volume (PPS), byte frequency (BPS), and entropy.

In a standard distribution, 99.7% of data falls within three standard deviations of the mean. When the system detects a data point where Z>3, it identifies it as a mathematical anomaly. This allows the system to catch DDoS attempts, packet floods, and port scans that haven't been "blacklisted" yet.

The Architecture

Packet Processing: I used Scapy for the raw network interface and FastAPI to build a high-performance bridge between the sniffer and the UI.

Statistical Engine: The backend uses a rolling window to calculate the mean and standard deviation on the fly, ensuring the "baseline" evolves as the network environment changes.

Real-time Dashboard: The frontend is built with React and Vite. It uses a WebSocket-style polling system to visualize the traffic flow and Z-Score gauges in real-time.

Setup and Installation

Backend Setup

Navigate to the backend directory: cd intms_backend

Create and activate a virtual environment: python3 -m venv venv && source venv/bin/activate

Install dependencies: pip install -r requirements.txt

Run the engine: python3 main.py

Frontend Setup

Navigate to the frontend directory: cd frontend

Install packages: npm install

Launch the dashboard: npm run dev

Future Development

The next step for this project is moving the filtering logic into the kernel space using eBPF. This would allow the system to drop malicious packets before they even reach the CPU's application layer, significantly reducing overhead during a high-volume attack.
