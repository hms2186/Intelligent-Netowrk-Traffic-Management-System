"""
ips/rules.py
IPS rule definitions.
Each rule has a condition function that receives a context dict
built from the current network snapshot + z-score results.
"""

from dataclasses import dataclass
from typing import Callable, Dict


@dataclass
class IPSRule:
    id:        str
    name:      str
    cond:      str           # human-readable condition shown in UI
    condition: Callable[[dict], bool]
    action:    str           # BLOCK_IP | RATE_LIMIT | SYN_PROXY | RRL | DROP_ICMP | TIMEOUT | GEO_DROP | DPI_FLAG
    sev:       str           # high | medium | low


RULES: Dict[str, IPSRule] = {r.id: r for r in [
    IPSRule(
        id="R01", name="PPS Rate Limiter",
        cond="z(pps) > 3σ",
        condition=lambda ctx: ctx.get("z_pps", 0) > 3.0,
        action="RATE_LIMIT", sev="high",
    ),
    IPSRule(
        id="R02", name="SYN Cookie Enforcer",
        cond="syn_ratio > 0.9",
        condition=lambda ctx: ctx.get("syn_ratio", 0) > 0.9,
        action="SYN_PROXY", sev="high",
    ),
    IPSRule(
        id="R03", name="Port Scan Blocker",
        cond="unique_ports > 20/s",
        condition=lambda ctx: ctx.get("unique_ports", 0) > 20,
        action="BLOCK_IP", sev="medium",
    ),
    IPSRule(
        id="R04", name="DNS Amp Guard",
        cond="udp_dns_ratio > 0.6",
        condition=lambda ctx: ctx.get("udp_dns_ratio", 0) > 0.6,
        action="RRL", sev="high",
    ),
    IPSRule(
        id="R05", name="ICMP Flood Shield",
        cond="icmp_pps > 100",
        condition=lambda ctx: ctx.get("icmp_pps", 0) > 100,
        action="DROP_ICMP", sev="medium",
    ),
    IPSRule(
        id="R06", name="Slow HTTP Timeout",
        cond="conn_duration > 60s",
        condition=lambda ctx: ctx.get("conn_duration", 0) > 60,
        action="TIMEOUT", sev="low",
    ),
    IPSRule(
        id="R07", name="Geo-block Suspicious",
        cond="asn_rep < 20",
        condition=lambda ctx: ctx.get("asn_rep", 100) < 20,
        action="GEO_DROP", sev="medium",
    ),
    IPSRule(
        id="R08", name="Entropy Analyzer",
        cond="payload_entropy > 7.2",
        condition=lambda ctx: ctx.get("payload_entropy", 0) > 7.2,
        action="DPI_FLAG", sev="high",
    ),
]}
