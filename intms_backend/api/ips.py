"""
api/ips.py
REST endpoints for IPS rule management and enforcement.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ips.rules import RULES
from ips.enforcer import enforce, unblock
from db.store import add_blocked, remove_blocked, list_blocked, mark_mitigated

router = APIRouter(prefix="/api/ips", tags=["ips"])

_engine = None   # Injected by main.py


def init(engine):
    global _engine
    _engine = engine


# ── Rules ─────────────────────────────────────────────────────────

@router.get("/rules")
async def get_rules():
    summary = {e["id"]: e for e in (_engine.get_fire_summary() if _engine else [])}
    return [
        {
            "id":      r.id,
            "name":    r.name,
            "action":  r.action,
            "cond":    r.cond,
            "sev":     r.sev,
            "enabled": _engine.enabled.get(r.id, True) if _engine else True,
            "fires":   summary.get(r.id, {}).get("fires", 0),
            "fired":   summary.get(r.id, {}).get("fired", False),
        }
        for r in RULES.values()
    ]


class ToggleBody(BaseModel):
    enabled: bool


@router.patch("/rules/{rule_id}")
async def toggle_rule(rule_id: str, body: ToggleBody):
    if rule_id not in RULES:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    if _engine:
        _engine.toggle(rule_id, body.enabled)
    return {"rule_id": rule_id, "enabled": body.enabled}


# ── Enforcement ───────────────────────────────────────────────────

class EnforceBody(BaseModel):
    ip:     str
    action: str = "BLOCK_IP"
    net_id: Optional[str] = None


@router.post("/enforce")
async def enforce_rule(body: EnforceBody):
    success, message = enforce(body.action, body.ip)
    if success and body.action == "BLOCK_IP":
        add_blocked(body.ip)
        if body.net_id:
            mark_mitigated(body.net_id, body.ip)
    return {"success": success, "message": message}


@router.delete("/enforce/{ip}")
async def unblock_ip(ip: str):
    success, message = unblock(ip)
    if success:
        remove_blocked(ip)
    return {"success": success, "message": message}


@router.get("/blocked")
async def get_blocked():
    return {"blocked_ips": list_blocked()}
