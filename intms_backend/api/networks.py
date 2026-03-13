"""
api/networks.py
REST endpoints for per-network data.
"""

from fastapi import APIRouter, HTTPException
from typing import Any

router = APIRouter(prefix="/api/networks", tags=["networks"])

# Injected by main.py after sniffers + classifiers are created
_sniffers    = {}
_classifiers = {}


def init(sniffers: dict, classifiers: dict):
    global _sniffers, _classifiers
    _sniffers    = sniffers
    _classifiers = classifiers


@router.get("/{net_id}")
async def get_network(net_id: str) -> dict[str, Any]:
    sniffer    = _sniffers.get(net_id)
    classifier = _classifiers.get(net_id)

    if not sniffer:
        raise HTTPException(status_code=404, detail=f"Network '{net_id}' not found")

    zs = classifier.get_z_scores() if classifier else {}

    return {
        "net_id":     net_id,
        "pps":        sniffer.snapshot_pps(),
        "bps":        sniffer.current_bps(),
        "top_flows":  sniffer.get_top_flows(10),
        "alerts":     classifier.get_alerts(10) if classifier else [],
        **zs,
    }


@router.get("/")
async def list_networks():
    return [{"net_id": k} for k in _sniffers]
