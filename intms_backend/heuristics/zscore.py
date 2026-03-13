"""
heuristics/zscore.py
Rolling z-score baseline engine.
One NetworkBaseline instance per network, per metric.
"""

import math
from collections import deque
from dataclasses import dataclass
from typing import Dict


SIGMA = {
    "warning":  2.0,
    "elevated": 3.0,
    "critical": 4.0,
}


@dataclass
class ZResult:
    value:   float
    mean:    float
    std:     float
    z:       float
    verdict: str   # "baseline" | "warning" | "elevated" | "critical"
    anomaly: bool  # True when |z| >= elevated threshold


def _mean(buf) -> float:
    return sum(buf) / len(buf) if buf else 0.0


def _std(buf) -> float:
    if len(buf) < 2:
        return 0.0
    m = _mean(buf)
    variance = sum((x - m) ** 2 for x in buf) / len(buf)
    return math.sqrt(variance)


class NetworkBaseline:
    """
    Per-network rolling z-score baseline.
    Tracks multiple metrics independently (pps, bps, entropy, conn_rate …).

    Usage:
        baseline = NetworkBaseline(window=60)
        result   = baseline.feed("pps", 450)
        if result.anomaly:
            ...
    """

    def __init__(self, window: int = 60):
        self.window = window
        self._buffers: Dict[str, deque] = {}

    def feed(self, metric: str, value: float) -> ZResult:
        if metric not in self._buffers:
            self._buffers[metric] = deque(maxlen=self.window)

        buf = self._buffers[metric]
        buf.append(value)

        if len(buf) < 5:
            # Not enough history — treat as baseline
            return ZResult(
                value=value, mean=value, std=0.0, z=0.0,
                verdict="baseline", anomaly=False
            )

        m = _mean(buf)
        s = _std(buf)
        z = (value - m) / s if s > 0 else 0.0

        if abs(z) >= SIGMA["critical"]:
            verdict = "critical"
        elif abs(z) >= SIGMA["elevated"]:
            verdict = "elevated"
        elif abs(z) >= SIGMA["warning"]:
            verdict = "warning"
        else:
            verdict = "baseline"

        return ZResult(
            value=value,
            mean=round(m, 2),
            std=round(s, 2),
            z=round(z, 3),
            verdict=verdict,
            anomaly=abs(z) >= SIGMA["elevated"],
        )

    def last_z(self, metric: str) -> float:
        """Return the z-score of the most recently fed value for a metric."""
        buf = self._buffers.get(metric)
        if not buf or len(buf) < 5:
            return 0.0
        m = _mean(buf)
        s = _std(buf)
        return round((buf[-1] - m) / s, 3) if s > 0 else 0.0
