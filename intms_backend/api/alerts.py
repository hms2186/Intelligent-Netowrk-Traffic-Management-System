"""
api/alerts.py
REST endpoints for alert history and escalation.
Escalation sends email via Gmail SMTP.
"""

import smtplib
import logging
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from db.store import get_all_alerts, get_alerts

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# ── Gmail config from environment ─────────────────────────────────
GMAIL_FROM   = os.getenv("GMAIL_FROM",   "h3manth2000@gmail.com")
GMAIL_TO     = os.getenv("GMAIL_TO",     "xdhemanth2000@gmail.com")
GMAIL_PASS   = os.getenv("GMAIL_PASS",   "")   # App password from .env
GMAIL_ENABLED = bool(GMAIL_PASS)


# ── Models ────────────────────────────────────────────────────────

class EscalateBody(BaseModel):
    network: str
    pps:     int
    src_ip:  Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────

@router.get("/")
async def all_alerts(limit: int = 100):
    return get_all_alerts(limit)


@router.get("/{net_id}")
async def net_alerts(net_id: str, limit: int = 20):
    return get_alerts(net_id, limit)


@router.post("/escalate")
async def escalate(body: EscalateBody):
    """
    Dispatches an email alert to the SOC admin via Gmail SMTP.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    subject = f"[INTMS ALERT] {body.network.upper()} — {body.pps} PPS flood detected"
    html = f"""
    <html><body style="font-family:monospace;background:#060c14;color:#9bbdd0;padding:24px">
    <h2 style="color:#ff4560">⚠ INTMS Security Alert</h2>
    <table style="border-collapse:collapse;width:100%">
      <tr><td style="padding:6px 12px;color:#3a5060">Network</td><td style="color:#e2f0f8">{body.network}</td></tr>
      <tr><td style="padding:6px 12px;color:#3a5060">Source IP</td><td style="color:#00f5c4">{body.src_ip or "—"}</td></tr>
      <tr><td style="padding:6px 12px;color:#3a5060">PPS</td><td style="color:#ff4560;font-weight:bold">{body.pps}</td></tr>
      <tr><td style="padding:6px 12px;color:#3a5060">Time</td><td style="color:#e2f0f8">{now}</td></tr>
    </table>
    <p style="margin-top:20px;color:#1e3048">This alert was dispatched automatically by INTMS v2.<br>
    Log in to the dashboard to review and deploy mitigation.</p>
    </body></html>
    """

    if not GMAIL_ENABLED:
        log.warning("[ESCALATE] Gmail not configured (GMAIL_PASS not set) — skipping email")
        return {
            "success": False,
            "message": "Email not configured. Set GMAIL_PASS in .env",
        }

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = GMAIL_FROM
        msg["To"]      = GMAIL_TO
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_FROM, GMAIL_PASS)
            server.sendmail(GMAIL_FROM, GMAIL_TO, msg.as_string())

        log.info(f"[ESCALATE] Email sent to {GMAIL_TO} for {body.network}")
        return {"success": True, "message": f"Email dispatched to {GMAIL_TO}"}

    except smtplib.SMTPAuthenticationError:
        msg = "Gmail auth failed — check GMAIL_PASS app password"
        log.error(f"[ESCALATE] {msg}")
        return {"success": False, "message": msg}
    except Exception as e:
        msg = str(e)
        log.error(f"[ESCALATE] {msg}")
        return {"success": False, "message": msg}
