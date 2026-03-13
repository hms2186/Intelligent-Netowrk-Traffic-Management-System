# INTMS v2 — Backend Integration Plan

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  React Frontend (INTMS v2)                                  │
│  Monitoring · Multi-Network · IPS · DPI · Threats           │
└──────────────────┬──────────────────────────────────────────┘
                   │  REST + WebSocket
┌──────────────────▼──────────────────────────────────────────┐
│  FastAPI Backend (Python)                                   │
│  /api/networks  /api/ips  /api/dpi  /api/alerts  /ws/live   │
└──────┬───────────┬──────────────┬───────────────────────────┘
       │           │              │
  ┌────▼───┐  ┌───▼────┐  ┌─────▼──────┐
  │ Scapy  │  │  IPS   │  │  Z-Score   │
  │ pcap   │  │ Engine │  │  Engine    │
  │ ingest │  │ (rules)│  │  (per net) │
  └────┬───┘  └───┬────┘  └─────┬──────┘
       │           │              │
  ┌────▼───────────▼──────────────▼──────┐
  │  PostgreSQL / InfluxDB               │
  │  alerts · flows · baselines          │
  └──────────────────────────────────────┘
```

---

## 1. Project Structure

```
intms-backend/
├── main.py                  # FastAPI app entry
├── capture/
│   ├── sniffer.py           # Scapy packet capture per interface
│   └── parser.py            # Protocol dissection (DPI layer)
├── heuristics/
│   ├── zscore.py            # Rolling z-score engine
│   └── classifier.py        # Threat classification logic
├── ips/
│   ├── rules.py             # Rule definitions & matching
│   └── enforcer.py          # iptables / tc enforcement
├── models/
│   ├── alert.py             # Pydantic schemas
│   └── network.py
├── db/
│   ├── timeseries.py        # InfluxDB write/query
│   └── postgres.py          # Alert history
├── api/
│   ├── networks.py          # /api/networks endpoints
│   ├── alerts.py            # /api/alerts endpoints
│   ├── ips.py               # /api/ips endpoints
│   └── dpi.py               # /api/dpi endpoints
└── ws/
    └── live.py              # WebSocket broadcaster
```

---

## 2. Multi-Network Monitoring

### Network Interface Binding

```python
# capture/sniffer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading, time
from collections import defaultdict, deque

NETWORKS = {
    "srm_main":   {"iface": "eth0", "subnet": "192.168.1.0/24"},
    "srm_hostel": {"iface": "eth1", "subnet": "10.10.0.0/24"},
    "srm_admin":  {"iface": "eth2", "subnet": "172.16.0.0/24"},
    "srm_lab":    {"iface": "eth3", "subnet": "10.20.0.0/24"},
}

class NetworkSniffer:
    def __init__(self, net_id: str, config: dict):
        self.net_id = net_id
        self.iface = config["iface"]
        self.pps_window = deque(maxlen=60)     # 60s rolling
        self.bps_window = deque(maxlen=60)
        self.flow_table = defaultdict(lambda: {"pps": 0, "bps": 0})
        self._lock = threading.Lock()

    def start(self):
        threading.Thread(
            target=sniff,
            kwargs={"iface": self.iface, "prn": self._handle, "store": False},
            daemon=True
        ).start()
        threading.Thread(target=self._tick_loop, daemon=True).start()

    def _handle(self, pkt):
        if not pkt.haslayer(IP): return
        with self._lock:
            src = pkt[IP].src
            self.flow_table[src]["pps"] += 1
            self.flow_table[src]["bps"] += len(pkt)

    def _tick_loop(self):
        while True:
            with self._lock:
                total_pps = sum(v["pps"] for v in self.flow_table.values())
                total_bps = sum(v["bps"] for v in self.flow_table.values())
                self.pps_window.append(total_pps)
                self.bps_window.append(total_bps)
                # reset per-flow counters each second
                for k in self.flow_table:
                    self.flow_table[k] = {"pps": 0, "bps": 0}
            time.sleep(1)
```

---

## 3. Z-Score Heuristic Engine

```python
# heuristics/zscore.py
import numpy as np
from collections import deque
from dataclasses import dataclass
from typing import Dict

SIGMA_THRESHOLDS = {
    "warning":  2.0,
    "elevated": 3.0,
    "critical": 4.0,
}

@dataclass
class ZResult:
    value: float
    mean: float
    std: float
    z: float
    verdict: str      # baseline / elevated / critical
    anomaly: bool

class NetworkBaseline:
    """Per-network, per-metric rolling z-score baseline."""

    def __init__(self, window: int = 60):
        self.window = window
        self._buffers: Dict[str, deque] = {}

    def feed(self, metric: str, value: float) -> ZResult:
        if metric not in self._buffers:
            self._buffers[metric] = deque(maxlen=self.window)
        buf = self._buffers[metric]
        buf.append(value)

        if len(buf) < 5:
            return ZResult(value, value, 0, 0.0, "baseline", False)

        arr = np.array(buf)
        m, s = arr.mean(), arr.std()
        z = (value - m) / s if s > 0 else 0.0

        if abs(z) >= SIGMA_THRESHOLDS["critical"]:
            verdict = "critical"
        elif abs(z) >= SIGMA_THRESHOLDS["elevated"]:
            verdict = "elevated"
        elif abs(z) >= SIGMA_THRESHOLDS["warning"]:
            verdict = "warning"
        else:
            verdict = "baseline"

        return ZResult(value, round(m, 2), round(s, 2), round(z, 3),
                       verdict, abs(z) >= SIGMA_THRESHOLDS["elevated"])
```

### Alert trigger from z-score

```python
# heuristics/classifier.py
from .zscore import NetworkBaseline, ZResult
from models.alert import Alert

baselines = {net_id: NetworkBaseline(60) for net_id in NETWORKS}

def evaluate(net_id: str, src_ip: str, pps: int, bps: int) -> Alert | None:
    result: ZResult = baselines[net_id].feed("pps", pps)
    baselines[net_id].feed("bps", bps)

    if result.anomaly:
        return Alert(
            network=net_id,
            src_ip=src_ip,
            pps=pps,
            z_score=result.z,
            verdict=result.verdict,
            reason=f"PPS deviated {result.z:.2f}σ from {result.mean:.0f} baseline",
        )
    return None
```

---

## 4. Intrusion Prevention System

```python
# ips/rules.py
from dataclasses import dataclass
from typing import Callable

@dataclass
class IPSRule:
    id: str
    name: str
    condition: Callable[[dict], bool]
    action: str   # BLOCK_IP | RATE_LIMIT | SYN_PROXY | RRL | DROP_ICMP

RULES = [
    IPSRule("IPS-001", "PPS Rate Limiter",
        condition=lambda ctx: ctx["z_score"] > 3.0,
        action="RATE_LIMIT"),

    IPSRule("IPS-002", "SYN Flood Guard",
        condition=lambda ctx: ctx.get("syn_ratio", 0) > 0.9,
        action="SYN_PROXY"),

    IPSRule("IPS-003", "Port Scan Detector",
        condition=lambda ctx: ctx.get("unique_ports_per_sec", 0) > 20,
        action="BLOCK_IP"),

    IPSRule("IPS-004", "DNS Amplification",
        condition=lambda ctx: ctx.get("udp_dns_ratio", 0) > 0.6,
        action="RRL"),

    IPSRule("IPS-005", "ICMP Flood Guard",
        condition=lambda ctx: ctx.get("icmp_pps", 0) > 100,
        action="DROP_ICMP"),

    IPSRule("IPS-008", "Entropy Anomaly",
        condition=lambda ctx: ctx.get("payload_entropy", 0) > 7.2,
        action="DPI_FLAG"),
]
```

```python
# ips/enforcer.py — actual kernel-level enforcement
import subprocess, shlex

def enforce(action: str, ip: str):
    commands = {
        "BLOCK_IP":    f"iptables -A INPUT -s {ip} -j DROP",
        "RATE_LIMIT":  f"iptables -A INPUT -s {ip} -m limit --limit 10/s -j ACCEPT",
        "DROP_ICMP":   f"iptables -A INPUT -s {ip} -p icmp -j DROP",
        "RRL":         f"iptables -A INPUT -s {ip} -p udp --dport 53 -m limit --limit 5/s -j ACCEPT",
    }
    cmd = commands.get(action)
    if cmd:
        subprocess.run(shlex.split(cmd), check=True)
        return True
    return False
```

---

## 5. Deep Packet Inspection

```python
# capture/parser.py
from scapy.all import IP, TCP, UDP, DNS, ICMP, Raw, HTTPRequest
import math, struct

def entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [data.count(b) / len(data) for b in set(data)]
    return -sum(f * math.log2(f) for f in freq if f > 0)

def dissect(pkt) -> dict:
    if not pkt.haslayer(IP): return {}
    ip = pkt[IP]
    result = {
        "src": ip.src, "dst": ip.dst, "ttl": ip.ttl,
        "size": len(pkt), "proto": "OTHER", "fields": {}, "entropy": 0.0,
        "anomaly_fields": []
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        result["proto"] = "HTTP" if tcp.dport == 80 else "HTTPS" if tcp.dport == 443 else "TCP"
        result["sport"], result["dport"] = tcp.sport, tcp.dport
        result["fields"] = {
            "Flags":    tcp.sprintf("%TCP.flags%"),
            "Seq":      tcp.seq,
            "Ack":      tcp.ack,
            "Window":   tcp.window,
        }
        # Flag anomaly: bare SYN flood check
        if str(tcp.flags) == "S":
            result["anomaly_fields"].append("Flags")

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        result["proto"] = "DNS" if udp.dport == 53 else "UDP"
        result["sport"], result["dport"] = udp.sport, udp.dport
        payload = bytes(udp.payload)
        e = entropy(payload)
        result["entropy"] = round(e, 2)
        result["fields"] = {"Length": udp.len, "Payload Len": len(payload), "Entropy": round(e, 2)}
        if e > 7.2:
            result["anomaly_fields"].append("Entropy")

    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        result["proto"] = "ICMP"
        result["fields"] = {"Type": icmp.type, "Code": icmp.code, "Seq": icmp.seq}

    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw])
        result["entropy"] = round(entropy(raw), 2)

    return result
```

---

## 6. FastAPI Endpoints

```python
# main.py
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import asyncio, json

app = FastAPI(title="INTMS API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# WebSocket — pushes live data to React frontend every second
@app.websocket("/ws/live")
async def live_feed(ws: WebSocket):
    await ws.accept()
    while True:
        payload = {
            "networks": {
                net_id: {
                    "pps":    list(sniffer.pps_window),
                    "bps":    list(sniffer.bps_window),
                    "alerts": [a.dict() for a in alert_store[net_id][:10]],
                    "z":      baselines[net_id].feed("pps", 0).z,  # last z
                }
                for net_id, sniffer in sniffers.items()
            },
            "ips_fires":  [r.id for r in RULES if rule_fired[r.id]],
            "dpi_packets": dpi_queue[-20:],
        }
        await ws.send_text(json.dumps(payload))
        await asyncio.sleep(1)

# REST: per-network snapshot
@app.get("/api/networks/{net_id}")
async def get_network(net_id: str):
    sniffer = sniffers[net_id]
    return {
        "pps": list(sniffer.pps_window),
        "bps": list(sniffer.bps_window),
        "top_flows": sorted(sniffer.flow_table.items(),
                            key=lambda x: x[1]["pps"], reverse=True)[:10],
    }

# REST: IPS rules status
@app.get("/api/ips/rules")
async def get_ips_rules():
    return [{"id": r.id, "name": r.name, "action": r.action,
             "fires": rule_fires[r.id]} for r in RULES]

@app.post("/api/ips/enforce")
async def enforce_rule(body: dict):
    success = enforce(body["action"], body["ip"])
    return {"success": success}

# REST: DPI stream
@app.get("/api/dpi/packets")
async def get_dpi(limit: int = 50, proto: str = None):
    pkts = dpi_queue[-limit:]
    if proto:
        pkts = [p for p in pkts if p["proto"] == proto]
    return pkts
```

---

## 7. React Frontend — Connecting to Real Backend

Replace simulated data in `INTMS_v2.jsx` with WebSocket:

```javascript
// In INTMS component, replace the setInterval simulation with:
useEffect(() => {
  const ws = new WebSocket("ws://localhost:8000/ws/live");

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);

    setNetData(prev => {
      const next = { ...prev };
      for (const [netId, nd] of Object.entries(data.networks)) {
        next[netId] = {
          pps:    nd.pps,
          alerts: nd.alerts,
          z:      { pps: { z: nd.z } }
        };
      }
      return next;
    });

    setDpiPackets(data.dpi_packets || []);
    // update IPS fires from data.ips_fires
  };

  ws.onerror = () => console.error("WS connection failed — is backend running?");
  return () => ws.close();
}, []);
```

---

## 8. Database Schema

```sql
-- PostgreSQL: alert history
CREATE TABLE alerts (
    id          SERIAL PRIMARY KEY,
    net_id      VARCHAR(32) NOT NULL,
    src_ip      INET NOT NULL,
    pps         INTEGER,
    z_score     FLOAT,
    verdict     VARCHAR(16),
    reason      TEXT,
    mitigated   BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_alerts_net ON alerts(net_id, created_at DESC);
```

```
# InfluxDB: time-series PPS/BPS per network
Measurement: network_traffic
Tags:         net_id, src_ip
Fields:       pps (int), bps (int), z_score (float)
Retention:    7 days (raw), 90 days (1-min downsampled)
```

---

## 9. Setup & Run

```bash
# 1. Install dependencies
pip install fastapi uvicorn scapy numpy influxdb-client psycopg2 python-dotenv

# 2. Configure interfaces in .env
NET_IFACES=eth0,eth1,eth2,eth3
DB_URL=postgresql://user:pass@localhost/intms
INFLUX_URL=http://localhost:8086
INFLUX_TOKEN=your-token

# 3. Run (requires root for packet capture)
sudo uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 4. Frontend
npm install && npm run dev
# React runs on :5173, proxies /api & /ws to :8000
```

---

## 10. Deployment Topology

```
Internet
    │
[Router / ISP Edge]
    │
[Mirror/TAP Port]──────► INTMS Sensor (eth0–eth3)
    │                           │
[Campus Switch]           FastAPI :8000
    │                           │
[SRM Networks]          React Frontend :5173
```

> **TAP vs SPAN**: For production use a passive network TAP (e.g. Gigamon) on the uplink to the core switch. This gives INTMS a full copy of all campus traffic without impacting performance. SPAN ports drop packets under load.

---

*INTMS v2 Backend Plan — generated for SRM_Campus_Net deployment*
