"""
capture/sniffer.py
Per-network-interface packet sniffer using Scapy.
One NetworkSniffer instance per interface.
Each sniffer maintains:
  - 60-second rolling PPS and BPS windows
  - per-source-IP flow table (pps + bps counters reset each second)
  - a deque of recent DPI-dissected packets
  - a deque of raw stream log entries for the frontend matrix view
"""

import threading
import time
import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional

from capture.parser import dissect

log = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    log.warning("Scapy not available — sniffers will not capture real packets.")


class NetworkSniffer:
    """
    Listens on a single network interface and maintains rolling statistics.

    Parameters
    ----------
    net_id : str      Logical network ID matching frontend NETS array ("main", "hostel" …)
    iface  : str      OS interface name ("en0", "eth0", "lo" …)
    window : int      Rolling window size in seconds (default 60)
    """

    def __init__(self, net_id: str, iface: str, window: int = 60):
        self.net_id = net_id
        self.iface  = iface

        # Rolling 1-second-per-slot windows
        self.pps_window: deque = deque([0] * window, maxlen=window)
        self.bps_window: deque = deque([0] * window, maxlen=window)

        # Per-source flow counters — reset every second by _tick_loop
        self._flow_table: Dict[str, Dict[str, int]] = defaultdict(lambda: {"pps": 0, "bps": 0})

        # Recent DPI packets (max 100)
        self.dpi_queue: deque = deque(maxlen=100)

        # Raw stream log entries for the matrix view (max 60)
        self.stream_log: deque = deque(maxlen=60)

        self._lock     = threading.Lock()
        self._running  = False

    # ── Public API ───────────────────────────────────────────────────

    def start(self):
        """Launch capture and tick threads."""
        if not SCAPY_OK:
            log.warning(f"[{self.net_id}] Scapy unavailable — starting tick loop only.")
            threading.Thread(target=self._tick_loop, daemon=True).start()
            return

        self._running = True
        threading.Thread(
            target=self._sniff_loop,
            name=f"sniff-{self.net_id}",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._tick_loop,
            name=f"tick-{self.net_id}",
            daemon=True,
        ).start()
        log.info(f"[{self.net_id}] Sniffer started on {self.iface}")

    def stop(self):
        self._running = False

    def get_top_flows(self, n: int = 10) -> List[dict]:
        """Return top-n flows sorted by current-second PPS."""
        with self._lock:
            flows = [
                {"src": src, "pps": v["pps"], "bps": v["bps"]}
                for src, v in self._flow_table.items()
                if v["pps"] > 0
            ]
        flows.sort(key=lambda x: x["pps"], reverse=True)
        return flows[:n]

    def snapshot_pps(self) -> List[int]:
        with self._lock:
            return list(self.pps_window)

    def current_bps(self) -> int:
        with self._lock:
            return self.bps_window[-1] if self.bps_window else 0

    # ── Internal ─────────────────────────────────────────────────────

    def _sniff_loop(self):
        """Blocking Scapy sniff — runs in its own thread."""
        try:
            sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            log.error(f"[{self.net_id}] Sniff error on {self.iface}: {e}")

    def _handle_packet(self, pkt):
        """Called for every captured packet."""
        if not pkt.haslayer(IP):
            return
        src  = pkt[IP].src
        size = len(pkt)

        with self._lock:
            self._flow_table[src]["pps"] += 1
            self._flow_table[src]["bps"] += size

        # DPI dissection (non-blocking — just append)
        parsed = dissect(pkt)
        if parsed:
            self.dpi_queue.appendleft(parsed)

    def _tick_loop(self):
        """
        Fires every second.
        Snapshots aggregate counters into rolling windows,
        resets per-flow counters, and appends a stream-log entry.
        """
        while True:
            time.sleep(1)
            now = datetime.now().strftime("%H:%M:%S")

            with self._lock:
                total_pps = sum(v["pps"] for v in self._flow_table.values())
                total_bps = sum(v["bps"] for v in self._flow_table.values())
                self.pps_window.append(total_pps)
                self.bps_window.append(total_bps)

                # Identify top source for stream log
                top_src = "—"
                top_pps = 0
                for src, v in self._flow_table.items():
                    if v["pps"] > top_pps:
                        top_pps = v["pps"]
                        top_src = src

                # Reset per-second counters
                for k in self._flow_table:
                    self._flow_table[k] = {"pps": 0, "bps": 0}

            self.stream_log.appendleft({
                "ts":  now,
                "src": top_src,
                "hot": total_pps >= 230,
            })
