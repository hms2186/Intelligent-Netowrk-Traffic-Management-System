"""
models/schemas.py
All Pydantic request/response models used across the API.
"""

from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ── Network ────────────────────────────────────────────────────────

class NetworkSnapshot(BaseModel):
    net_id:    str
    label:     str
    subnet:    str
    pps:       List[int]        = Field(default_factory=list)
    bps:       int              = 0
    z:         float            = 0.0
    z_bps:     float            = 0.0
    z_entropy: float            = 0.0
    z_conn:    float            = 0.0
    top_flows: List[Any]        = Field(default_factory=list)
    alerts:    List["AlertOut"] = Field(default_factory=list)


# ── Alerts ─────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id:         Optional[int]  = None
    net_id:     str
    src_ip:     str
    pps:        int
    z_score:    float
    verdict:    str
    reason:     str
    mitigated:  bool           = False
    ts:         str            = ""          # HH:MM:SS shorthand for frontend
    created_at: Optional[str]  = None


class EscalateRequest(BaseModel):
    network: str
    pps:     int
    src_ip:  Optional[str] = None


class EscalateResponse(BaseModel):
    success: bool
    message: str


# ── IPS ────────────────────────────────────────────────────────────

class IPSRuleOut(BaseModel):
    id:      str
    name:    str
    action:  str
    cond:    str
    sev:     str
    enabled: bool
    fires:   int
    fired:   bool


class IPSToggleRequest(BaseModel):
    enabled: bool


class EnforceRequest(BaseModel):
    ip:     str
    action: str = "BLOCK_IP"


class EnforceResponse(BaseModel):
    success: bool
    message: str


# ── DPI ────────────────────────────────────────────────────────────

class DPIPacket(BaseModel):
    proto:         str
    col:           str            = "#00f5c4"
    ts:            str
    src:           str
    dst:           str
    sport:         int
    dport:         int
    size:          int
    ttl:           int
    fields:        List[str]      = Field(default_factory=list)
    anomaly_fields: List[str]     = Field(default_factory=list)
    entropy:       str            = "0.00"
    flagged:       bool           = False


# ── WebSocket push payload ─────────────────────────────────────────

class IPSFireEntry(BaseModel):
    id:    str
    fires: int
    fired: bool


class IPSLogEntry(BaseModel):
    ts:     str
    rule:   str
    action: str
    src:    str


class StreamLogEntry(BaseModel):
    ts:  str
    src: str
    hot: bool


class WSPayload(BaseModel):
    networks:    Dict[str, NetworkSnapshot]
    ips_fires:   List[IPSFireEntry]         = Field(default_factory=list)
    ips_log:     List[IPSLogEntry]          = Field(default_factory=list)
    dpi_packets: List[DPIPacket]            = Field(default_factory=list)
    stream_log:  List[StreamLogEntry]       = Field(default_factory=list)
