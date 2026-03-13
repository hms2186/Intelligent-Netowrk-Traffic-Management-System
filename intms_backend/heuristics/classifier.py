"""
heuristics/classifier.py
Generates Alert objects when z-score baselines detect anomalies.
One Classifier instance per network.
"""

import logging
from datetime import datetime
from typing import List, Optional

from heuristics.zscore import NetworkBaseline, ZResult

log = logging.getLogger(__name__)

THRESH = 230  # PPS hard threshold (matches frontend THRESH constant)


class NetworkClassifier:
    """
    Wraps a NetworkBaseline and generates structured alert dicts
    whenever a metric crosses the elevated threshold.
    """

    def __init__(self, net_id: str):
        self.net_id   = net_id
        self.baseline = NetworkBaseline(window=60)
        self._alerts: List[dict] = []      # in-memory alert store (max 50)

    def evaluate(self, pps: int, bps: int, entropy: float = 0.0, top_src: str = "0.0.0.0") -> Optional[dict]:
        """
        Feed current second's metrics.
        Returns an alert dict if anomaly detected, else None.
        """
        z_pps     = self.baseline.feed("pps",     float(pps))
        z_bps     = self.baseline.feed("bps",     float(bps))
        z_entropy = self.baseline.feed("entropy", entropy)

        alert = None

        if z_pps.anomaly or pps >= THRESH:
            alert = {
                "net_id":   self.net_id,
                "src_ip":   top_src,
                "pps":      pps,
                "z_score":  z_pps.z,
                "verdict":  z_pps.verdict,
                "reason":   f"PPS deviated {z_pps.z:+.2f}σ from {z_pps.mean:.0f} baseline",
                "mitigated": False,
                "ts":       datetime.now().strftime("%H:%M:%S"),
                "created_at": datetime.utcnow().isoformat(),
            }
            log.warning(f"[{self.net_id}] ALERT {top_src} → {pps} PPS  z={z_pps.z:+.2f}σ")
            self._alerts.insert(0, alert)
            self._alerts = self._alerts[:50]

        return alert

    def get_alerts(self, n: int = 10) -> List[dict]:
        return self._alerts[:n]

    def get_z_scores(self) -> dict:
        return {
            "z":         self.baseline.last_z("pps"),
            "z_bps":     self.baseline.last_z("bps"),
            "z_entropy": self.baseline.last_z("entropy"),
            "z_conn":    self.baseline.last_z("conn"),
        }
