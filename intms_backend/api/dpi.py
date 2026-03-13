"""
api/dpi.py
REST endpoint for DPI packet history.
"""

from fastapi import APIRouter
from typing import Optional

router = APIRouter(prefix="/api/dpi", tags=["dpi"])

_sniffers = {}


def init(sniffers: dict):
    global _sniffers
    _sniffers = sniffers


@router.get("/packets")
async def get_packets(limit: int = 50, proto: Optional[str] = None, net_id: Optional[str] = None):
    """
    Returns recent DPI packets.
    Optionally filter by protocol or network.
    """
    pkts = []

    nets = [net_id] if net_id else list(_sniffers.keys())
    for nid in nets:
        sniffer = _sniffers.get(nid)
        if sniffer:
            pkts.extend(list(sniffer.dpi_queue))

    # Sort by ts descending (lexicographic HH:MM:SS is fine)
    pkts.sort(key=lambda p: p.get("ts", ""), reverse=True)

    if proto:
        pkts = [p for p in pkts if p.get("proto") == proto.upper()]

    return pkts[:limit]
