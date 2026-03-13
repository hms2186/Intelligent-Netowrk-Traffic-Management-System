"""
ips/enforcer.py
Runs actual iptables commands to enforce IPS decisions.
Requires root / CAP_NET_ADMIN.

In development (non-root) the commands are logged but not executed —
set DRY_RUN=true in your .env to force dry-run mode.
"""

import subprocess
import shlex
import logging
import os

log = logging.getLogger(__name__)

DRY_RUN: bool = os.getenv("DRY_RUN", "false").lower() == "true"

# Maps action name → iptables command template (%s = IP address)
COMMANDS: dict[str, str] = {
    "BLOCK_IP":   "iptables -A INPUT -s %s -j DROP",
    "RATE_LIMIT": "iptables -A INPUT -s %s -m limit --limit 100/s --limit-burst 200 -j ACCEPT",
    "DROP_ICMP":  "iptables -A INPUT -s %s -p icmp -j DROP",
    "RRL":        "iptables -A INPUT -s %s -p udp --dport 53 -m limit --limit 5/s -j ACCEPT",
    "SYN_PROXY":  "iptables -A INPUT -s %s -p tcp --syn -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460",
    "TIMEOUT":    "iptables -A INPUT -s %s -p tcp -m conntrack --ctstate ESTABLISHED -m time --kerneltz --timestart 0:0:0 --timestop 0:1:0 -j DROP",
    "GEO_DROP":   "iptables -A INPUT -s %s -j DROP",
    "DPI_FLAG":   None,   # DPI_FLAG is a software-only action — no iptables rule
}


def enforce(action: str, ip: str) -> tuple[bool, str]:
    """
    Execute the iptables rule for the given action + IP.

    Returns (success: bool, message: str)
    """
    # Basic IP validation
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False, f"Invalid IP address: {ip}"

    template = COMMANDS.get(action)

    if template is None:
        # Software-only action (DPI_FLAG etc.)
        log.info(f"[IPS] Software action {action} noted for {ip} — no iptables rule")
        return True, f"{action} noted for {ip} (software-only)"

    cmd = template % ip
    log.info(f"[IPS] Enforcing: {cmd}")

    if DRY_RUN:
        log.info(f"[IPS] DRY RUN — skipping execution")
        return True, f"DRY RUN: {cmd}"

    try:
        subprocess.run(
            shlex.split(cmd),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return True, f"Rule applied: {cmd}"
    except subprocess.CalledProcessError as e:
        msg = f"iptables error: {e.stderr.strip()}"
        log.error(f"[IPS] {msg}")
        return False, msg
    except PermissionError:
        msg = "Permission denied — run backend as root or with CAP_NET_ADMIN"
        log.error(f"[IPS] {msg}")
        return False, msg
    except Exception as e:
        msg = str(e)
        log.error(f"[IPS] Unexpected error: {msg}")
        return False, msg


def unblock(ip: str) -> tuple[bool, str]:
    """Remove a previously applied BLOCK_IP rule."""
    cmd = f"iptables -D INPUT -s {ip} -j DROP"
    log.info(f"[IPS] Unblocking: {cmd}")

    if DRY_RUN:
        return True, f"DRY RUN: {cmd}"

    try:
        subprocess.run(shlex.split(cmd), check=True, capture_output=True, text=True, timeout=5)
        return True, f"Unblocked {ip}"
    except Exception as e:
        return False, str(e)
