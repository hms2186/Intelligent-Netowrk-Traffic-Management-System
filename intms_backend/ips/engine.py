"""
ips/engine.py
IPS Engine — evaluates all rules against the current network context
every second and maintains fire counters + log.
"""

import logging
import time
import threading
from collections import deque
from datetime import datetime
from typing import Dict, List

from ips.rules import RULES, IPSRule
from ips.enforcer import enforce

log = logging.getLogger(__name__)


class IPSEngine:
    """
    Runs all IPS rules against a live context dict pushed by the main loop.

    Usage:
        engine = IPSEngine()
        engine.start()
        # every second from main loop:
        engine.evaluate(ctx)
    """

    def __init__(self):
        # Per-rule state
        self.enabled: Dict[str, bool]  = {rid: True  for rid in RULES}
        self.fires:   Dict[str, int]   = {rid: 0      for rid in RULES}
        self.fired:   Dict[str, bool]  = {rid: False  for rid in RULES}

        # Live log of enforcement events (max 200)
        self.log: deque = deque(maxlen=200)

        self._lock = threading.Lock()

    # ── Public ──────────────────────────────────────────────────────

    def evaluate(self, ctx: dict):
        """
        Evaluate all enabled rules against ctx.
        ctx keys: z_pps, syn_ratio, unique_ports, udp_dns_ratio,
                  icmp_pps, conn_duration, asn_rep, payload_entropy,
                  top_src (str IP of top flow)
        """
        now = datetime.now().strftime("%H:%M:%S")
        src = ctx.get("top_src", "0.0.0.0")

        with self._lock:
            for rid, rule in RULES.items():
                if not self.enabled.get(rid, True):
                    self.fired[rid] = False
                    continue

                try:
                    triggered = rule.condition(ctx)
                except Exception:
                    triggered = False

                self.fired[rid] = triggered

                if triggered:
                    self.fires[rid] += 1
                    log.info(f"[IPS] {rule.name} fired → {rule.action} on {src}")

                    # Append to live log
                    self.log.appendleft({
                        "ts":     now,
                        "rule":   rule.name,
                        "action": rule.action,
                        "src":    src,
                    })

                    # Enforce at kernel level for hard-block actions
                    if rule.action in ("BLOCK_IP", "RATE_LIMIT", "DROP_ICMP", "RRL") and src != "0.0.0.0":
                        threading.Thread(
                            target=enforce,
                            args=(rule.action, src),
                            daemon=True,
                        ).start()

    def toggle(self, rule_id: str, enabled: bool):
        with self._lock:
            if rule_id in self.enabled:
                self.enabled[rule_id] = enabled
                log.info(f"[IPS] Rule {rule_id} {'enabled' if enabled else 'disabled'}")

    def get_fire_summary(self) -> List[dict]:
        with self._lock:
            return [
                {"id": rid, "fires": self.fires[rid], "fired": self.fired[rid]}
                for rid in RULES
            ]

    def get_log(self, n: int = 40) -> List[dict]:
        with self._lock:
            return list(self.log)[:n]
