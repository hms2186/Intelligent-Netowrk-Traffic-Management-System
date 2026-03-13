"""
capture/parser.py
Deep Packet Inspection — dissects Scapy packets into structured DPIPacket dicts.
Computes Shannon entropy on payload bytes.
"""

import math
from datetime import datetime
from typing import Dict, List

# Scapy is imported lazily so the module loads even if scapy is not yet installed.
try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# Proto → accent colour (matches frontend PROTOS array)
PROTO_COLORS: Dict[str, str] = {
    "TCP":   "#00f5c4",
    "UDP":   "#f5c400",
    "HTTP":  "#a855f7",
    "HTTPS": "#a3e635",
    "DNS":   "#fb923c",
    "ICMP":  "#f87171",
}

# Proto → field names shown in the DPI card (order must match fields list)
PROTO_FIELDS: Dict[str, List[str]] = {
    "TCP":   ["Flags", "Seq", "Ack", "Window", "Checksum"],
    "UDP":   ["Length", "Checksum", "Payload Len", "Entropy", "Frag"],
    "HTTP":  ["Method", "Host", "User-Agent", "Status", "Content-Type"],
    "HTTPS": ["TLS Ver", "Cipher", "SNI", "Cert CN", "ALPN"],
    "DNS":   ["Query", "Type", "TTL", "Answer", "Flags"],
    "ICMP":  ["Type", "Code", "Checksum", "Seq", "TTL"],
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def dissect(pkt) -> dict | None:
    """
    Dissect a Scapy packet into a dict matching the DPIPacket schema.
    Returns None if the packet is not IP.
    """
    if not SCAPY_OK:
        return None
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto     = "OTHER"
    sport     = 0
    dport     = 0
    fields    = []
    anomaly_f = []
    ent       = 0.0

    # ── TCP / HTTP / HTTPS ──────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp   = pkt[TCP]
        sport = tcp.sport
        dport = tcp.dport
        flags = tcp.sprintf("%TCP.flags%")

        if dport == 80 or sport == 80:
            proto = "HTTP"
        elif dport == 443 or sport == 443:
            proto = "HTTPS"
        else:
            proto = "TCP"

        fields = [
            flags,
            str(tcp.seq),
            str(tcp.ack),
            str(tcp.window),
            str(tcp.chksum),
        ]

        # Bare SYN — possible SYN flood
        if flags == "S":
            anomaly_f.append("Flags")

        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            ent = _entropy(raw)
            if ent > 7.2:
                anomaly_f.append("Entropy")

    # ── UDP / DNS ───────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp   = pkt[UDP]
        sport = udp.sport
        dport = udp.dport
        payload = bytes(udp.payload)
        ent     = _entropy(payload)

        if dport == 53 or sport == 53:
            proto = "DNS"
            qname = "—"
            qtype = "—"
            ttl   = "—"
            ans   = "—"
            flags = "—"
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qd:
                    qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                    qtype = str(dns.qd.qtype)
                if dns.an:
                    try:
                        ans = dns.an.rdata
                        if isinstance(ans, bytes):
                            ans = ans.decode(errors="replace")
                        ans = str(ans)
                        ttl = str(dns.an.ttl)
                    except Exception:
                        ans = "—"
                flags = "RD" if dns.rd else "—"
            # Long subdomain = possible DNS exfiltration
            if len(qname) > 40:
                anomaly_f.append("Query")
            fields = [qname, qtype, ttl, ans, flags]
        else:
            proto = "UDP"
            fields = [
                str(udp.len),
                str(udp.chksum),
                str(len(payload)),
                f"{ent:.2f}",
                "NO",
            ]
            if ent > 7.2:
                anomaly_f.append("Entropy")

    # ── ICMP ────────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        icmp  = pkt[ICMP]
        proto = "ICMP"
        fields = [
            str(icmp.type),
            str(icmp.code),
            str(icmp.chksum),
            str(getattr(icmp, "seq", 0)),
            str(ip.ttl),
        ]
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            ent = _entropy(raw)
            if ent > 6.0:
                anomaly_f.append("Type")   # flag ICMP tunneling

    # ── Pad fields to 5 ────────────────────────────────────────────
    while len(fields) < 5:
        fields.append("—")

    return {
        "proto":         proto,
        "col":           PROTO_COLORS.get(proto, "#00f5c4"),
        "ts":            _ts(),
        "src":           ip.src,
        "dst":           ip.dst,
        "sport":         sport,
        "dport":         dport,
        "size":          len(pkt),
        "ttl":           ip.ttl,
        "fields":        [str(f) for f in fields[:5]],
        "anomaly_fields": anomaly_f,
        "entropy":       f"{ent:.2f}",
        "flagged":       len(anomaly_f) > 0,
    }
