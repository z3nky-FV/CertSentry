"""Telegram notification subsystem with deduplication."""

from __future__ import annotations
import asyncio
from html import escape
import logging
from datetime import datetime, timezone
import httpx

log = logging.getLogger(__name__)

_sent: set[tuple[str, int, str, str]] = set()
_pending: set[tuple[str, int, str, str]] = set()
_send_limit = asyncio.Semaphore(10)


def _build_message(host: str, port: int, cn: str | None, days: int,
                   risk: int, status: str, reasons: list[str]) -> str:
    e = {"EXPIRED": "🔴", "CRITICAL": "🔴", "WARNING": "🟡", "INFORMATION": "🔵", "OK": "🟢", "CHANGE": "🟠"}
    lines = [
        f"{e.get(status, '⚪')} <b>{'CertSentry ChangeGuard' if status == 'CHANGE' else 'Certificate Radar Alert'}</b>",
        f"<b>Host:</b> <code>{escape(host)}:{port}</code>  <b>CN:</b> <code>{escape(cn or 'N/A')}</code>",
        f"<b>Status:</b> <code>{escape(status)}</code>  <b>Risk:</b> <code>{risk}/100</code>  <b>Days:</b> <code>{days}</code>",
    ]
    if reasons:
        lines.append("<b>Factors:</b>\n" + "\n".join(f"• {escape(r)}" for r in reasons))
    lines.append(f"🕐 <i>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</i>")
    return "\n".join(lines)


async def send_alert(token: str, chat_id: str, host: str, port: int,
                     cn: str | None, thumb: str, days: int, risk: int,
                     status: str, reasons: list[str], trigger: str) -> bool:
    key = (host, port, thumb, trigger)
    if key in _sent or key in _pending:
        return False
    _pending.add(key)

    msg = _build_message(host, port, cn, days, risk, status, reasons)
    try:
        async with _send_limit:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post(f"https://api.telegram.org/bot{token}/sendMessage",
                                 json={"chat_id": chat_id, "text": msg,
                                       "parse_mode": "HTML", "disable_web_page_preview": True})
                r.raise_for_status()
                _sent.add(key)
                return True
    except Exception as e:
        log.error("Telegram send failed: %s", e)
        return False
    finally:
        _pending.discard(key)


async def check_and_notify(token: str | None, chat_id: str | None,
                           host: str, port: int, cn: str | None, thumb: str,
                           days: int, risk: int, status: str, reasons: list[str],
                           thresholds: list[int] | None = None,
                           previous_days: int | None = None) -> bool:
    if not token or not chat_id:
        return False
    th = sorted(set(thresholds or [60, 30, 14, 7, 1]), reverse=True)
    if previous_days is None:
        crossed = [t for t in th if days <= t]
        milestone = min(crossed, key=lambda t: abs(days - t)) if crossed else None
    else:
        crossed = [t for t in th if previous_days > t >= days]
        milestone = min(crossed) if crossed else None
    trigger = f"days:{milestone}" if milestone is not None else ""
    if not trigger and status in ("CRITICAL", "EXPIRED"):
        trigger = f"status:{status}"
    if not trigger and any("chain" in r.lower() for r in reasons):
        trigger = "chain"
    if not trigger:
        return False
    return await send_alert(token, chat_id, host, port, cn, thumb, days, risk, status, reasons, trigger)


async def notify_certificate_change(token: str | None, chat_id: str | None,
                                    host: str, port: int, cn: str | None, thumb: str,
                                    days: int, risk: int, change: dict) -> bool:
    if not token or not chat_id:
        return False
    reasons = [f"Certificate changed since the previous scan: {item['field']}"
               for item in change.get("differences", [])]
    old = change.get("old_thumbprint") or "N/A"
    new = change.get("new_thumbprint") or thumb
    reasons.append(f"SHA-256: {old} → {new}")
    trigger = f"change:{change.get('detected_at')}:{thumb}"
    return await send_alert(token, chat_id, host, port, cn, thumb, days, risk,
                            "CHANGE", reasons, trigger)
