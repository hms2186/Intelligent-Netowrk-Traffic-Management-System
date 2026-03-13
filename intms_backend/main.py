"""
main.py — INTMS Backend
FastAPI application entry point.

Start with:
    sudo uvicorn main:app --host 0.0.0.0 --port 8000 --reload

sudo is needed for Scapy raw socket packet capture.
For development without root, set DRY_RUN=true in .env — the app
will start normally but sniffers will not capture real traffic.

Environment variables (.env):
    NET_MAIN_IFACE    = en0          # macOS Wi-Fi
    NET_HOSTEL_IFACE  = en1
    NET_ADMIN_IFACE   = en2
    NET_LAB_IFACE     = en3
    GMAIL_FROM        = h3manth2000@gmail.com
    GMAIL_TO          = xdhemanth2000@gmail.com
    GMAIL_PASS        = xxxx xxxx xxxx xxxx   # Gmail app password
    DRY_RUN           = false                  # Set true to skip iptables
"""

import asyncio
import logging
import os
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from capture.sniffer import NetworkSniffer
from heuristics.classifier import NetworkClassifier
from ips.engine import IPSEngine
from ws.broadcaster import manager
from db.store import save_alert

import api.networks as api_networks
import api.ips      as api_ips
import api.alerts   as api_alerts
import api.dpi      as api_dpi

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
log = logging.getLogger("intms")

# ── Network config ────────────────────────────────────────────────
# Maps logical network ID → OS interface name
# Edit these to match your machine's actual interface names.
# Run `ifconfig` or `ip link` to list interfaces.
NETWORK_IFACES = {
    "main":   os.getenv("NET_MAIN_IFACE",   "en0"),
    "hostel": os.getenv("NET_HOSTEL_IFACE", "en1"),
    "admin":  os.getenv("NET_ADMIN_IFACE",  "en2"),
    "lab":    os.getenv("NET_LAB_IFACE",    "en3"),
}

NETWORK_META = {
    "main":   {"label": "SRM Main",     "subnet": "192.168.1.0/24"},
    "hostel": {"label": "Hostel Block", "subnet": "10.10.0.0/24"},
    "admin":  {"label": "Admin Net",    "subnet": "172.16.0.0/24"},
    "lab":    {"label": "CS Lab",       "subnet": "10.20.0.0/24"},
}

# ── App & global objects ──────────────────────────────────────────
app = FastAPI(title="INTMS API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# One sniffer + one classifier per network
sniffers:     dict[str, NetworkSniffer]      = {}
classifiers:  dict[str, NetworkClassifier]   = {}
ips_engine:   IPSEngine                      = IPSEngine()


# ── Startup ───────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    log.info("=== INTMS Backend starting ===")

    # Create and start sniffers + classifiers
    for net_id, iface in NETWORK_IFACES.items():
        sniffer    = NetworkSniffer(net_id, iface)
        classifier = NetworkClassifier(net_id)
        sniffers[net_id]    = sniffer
        classifiers[net_id] = classifier
        sniffer.start()
        log.info(f"  Network [{net_id}] on interface {iface}")

    # Wire API routers
    api_networks.init(sniffers, classifiers)
    api_ips.init(ips_engine)
    api_dpi.init(sniffers)

    # Start the main 1-second broadcast loop
    asyncio.create_task(broadcast_loop())
    log.info("=== Startup complete — WebSocket broadcasting on /ws/live ===")


# ── WebSocket endpoint ────────────────────────────────────────────
@app.websocket("/ws/live")
async def live_feed(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep the connection alive; data is pushed by broadcast_loop
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)


# ── Main broadcast loop ───────────────────────────────────────────
async def broadcast_loop():
    """
    Fires every 1 second.
    1. Collects current stats from all sniffers + classifiers
    2. Evaluates IPS rules
    3. Broadcasts the full payload to all connected WebSocket clients
    """
    while True:
        await asyncio.sleep(1)
        try:
            now = datetime.now().strftime("%H:%M:%S")
            networks_payload = {}
            all_stream_logs  = []

            for net_id, sniffer in sniffers.items():
                classifier = classifiers[net_id]
                pps_window = sniffer.snapshot_pps()
                bps        = sniffer.current_bps()
                top_flows  = sniffer.get_top_flows(10)
                cur_pps    = pps_window[-1] if pps_window else 0

                # Top source IP for IPS context
                top_src = top_flows[0]["src"] if top_flows else "0.0.0.0"

                # Z-score evaluation + alert generation
                # Use mean entropy from recent DPI packets
                recent_entropy = 0.0
                if sniffer.dpi_queue:
                    entropies = [float(p.get("entropy", 0)) for p in list(sniffer.dpi_queue)[:20]]
                    recent_entropy = sum(entropies) / len(entropies) if entropies else 0.0

                alert = classifier.evaluate(cur_pps, bps, recent_entropy, top_src)
                if alert:
                    save_alert(alert)

                zs = classifier.get_z_scores()

                # IPS context for this network
                ips_ctx = {
                    "z_pps":           zs.get("z", 0),
                    "top_src":         top_src,
                    "payload_entropy": recent_entropy,
                    # These would come from deeper flow analysis in production
                    "syn_ratio":       0.0,
                    "unique_ports":    0,
                    "udp_dns_ratio":   0.0,
                    "icmp_pps":        0,
                    "conn_duration":   0,
                    "asn_rep":         100,
                }
                ips_engine.evaluate(ips_ctx)

                networks_payload[net_id] = {
                    "net_id":    net_id,
                    "label":     NETWORK_META[net_id]["label"],
                    "subnet":    NETWORK_META[net_id]["subnet"],
                    "pps":       pps_window,
                    "bps":       bps,
                    "top_flows": top_flows,
                    "alerts":    classifier.get_alerts(10),
                    **zs,
                }

                # Collect stream log entries from this sniffer
                for entry in list(sniffer.stream_log)[:5]:
                    all_stream_logs.append(entry)

            # Build full WS payload
            payload = {
                "networks":    networks_payload,
                "ips_fires":   ips_engine.get_fire_summary(),
                "ips_log":     ips_engine.get_log(40),
                "dpi_packets": _collect_dpi_packets(20),
                "stream_log":  all_stream_logs[:30],
            }

            await manager.broadcast(payload)

        except Exception as e:
            log.error(f"[broadcast_loop] Error: {e}", exc_info=True)


def _collect_dpi_packets(n: int) -> list:
    """Collect the most recent DPI packets across all networks."""
    pkts = []
    for sniffer in sniffers.values():
        pkts.extend(list(sniffer.dpi_queue)[:n])
    pkts.sort(key=lambda p: p.get("ts", ""), reverse=True)
    return pkts[:n]


# ── Include routers ───────────────────────────────────────────────
app.include_router(api_networks.router)
app.include_router(api_ips.router)
app.include_router(api_alerts.router)
app.include_router(api_dpi.router)


# ── Health check ─────────────────────────────────────────────────
@app.get("/")
async def health():
    return {
        "status":   "ok",
        "networks": list(sniffers.keys()),
        "version":  "2.0.0",
    }
