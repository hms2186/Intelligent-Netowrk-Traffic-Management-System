"""
db/store.py
Simple in-memory store for alert history and blocked IPs.
Replace with Postgres / InfluxDB calls when deploying to production.

Postgres schema (for when you add it):

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

InfluxDB measurement (for time-series PPS/BPS history):

    Measurement : network_traffic
    Tags        : net_id, src_ip
    Fields      : pps (int), bps (int), z_score (float)
    Retention   : 7 days raw, 90 days 1-min downsampled
"""

from collections import defaultdict, deque
from threading import Lock
from typing import List, Dict, Set

_lock = Lock()

# net_id → list of alert dicts (most recent first, max 200)
_alerts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

# Set of currently blocked IPs
_blocked_ips: Set[str] = set()


# ── Alerts ────────────────────────────────────────────────────────

def save_alert(alert: dict):
    with _lock:
        _alerts[alert["net_id"]].appendleft(alert)


def get_alerts(net_id: str, limit: int = 20) -> List[dict]:
    with _lock:
        return list(_alerts[net_id])[:limit]


def get_all_alerts(limit: int = 100) -> List[dict]:
    with _lock:
        all_a = []
        for q in _alerts.values():
            all_a.extend(q)
        all_a.sort(key=lambda a: a.get("created_at", ""), reverse=True)
        return all_a[:limit]


def mark_mitigated(net_id: str, src_ip: str):
    with _lock:
        for a in _alerts[net_id]:
            if a.get("src_ip") == src_ip:
                a["mitigated"] = True


# ── Blocked IPs ───────────────────────────────────────────────────

def add_blocked(ip: str):
    with _lock:
        _blocked_ips.add(ip)


def remove_blocked(ip: str):
    with _lock:
        _blocked_ips.discard(ip)


def is_blocked(ip: str) -> bool:
    with _lock:
        return ip in _blocked_ips


def list_blocked() -> List[str]:
    with _lock:
        return list(_blocked_ips)
