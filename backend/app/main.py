"""Certificate Radar — FastAPI REST API."""

from __future__ import annotations
import asyncio
import csv, io, json, logging
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("audit.log", encoding="utf-8"), logging.StreamHandler()]
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .config import DATABASE_PATH, FRONTEND_ORIGINS, SCAN_TIMEOUT, SCAN_CONCURRENCY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, NOTIFY_THRESHOLDS
from .risk_engine import calculate_risk
from .scanner import scan_targets
from .notifier import check_and_notify, notify_certificate_change
from .storage import CertificateStore

app = FastAPI(title="Certificate Radar API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=FRONTEND_ORIGINS, allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])

# SQLite keeps the service inventory across restarts without an external DB.
_store = CertificateStore(DATABASE_PATH)
_certs: dict[tuple[str, int], dict] = {
    (c["hostname"].lower(), c["port"]): c for c in _store.load_all()
}
_next_cert_id = max((c["id"] for c in _certs.values()), default=0) + 1

# ── Schemas ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1, max_length=1024)
    criticality: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    owner: str = Field(default="", max_length=200)

class MetricsSummary(BaseModel):
    total_certificates: int
    overall_risk_score: float
    status_distribution: dict[str, int]
    critical_count: int
    expiring_soon: int
    expired_count: int
    self_signed_count: int
    avg_days_left: float
    pending_changes: int


def _csv_safe(value: object) -> object:
    if isinstance(value, str) and value.lstrip(" \t\r\n")[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


_CHANGE_FIELDS = {
    "thumbprint_sha256": "SHA-256 thumbprint",
    "common_name": "CN",
    "issuer": "Issuer",
    "sans": "SAN",
    "valid_from": "Дата начала действия",
    "valid_to": "Дата окончания действия",
    "is_chain_valid": "Доверие к TLS-цепочке",
    "is_hostname_match": "Соответствие имени",
    "is_self_signed": "Self-signed",
    "is_weak_crypto": "Криптографические параметры",
}


def _certificate_changes(previous: dict, current: dict) -> list[dict]:
    return [
        {"field": label, "old": previous.get(key), "new": current.get(key)}
        for key, label in _CHANGE_FIELDS.items()
        if key in previous and previous.get(key) != current.get(key)
    ]


# ── Endpoints ────────────────────────────────────────────────

@app.post("/api/v1/scan/run")
async def run_scan(req: ScanRequest):
    global _next_cert_id
    logging.info(f"User initiated scan for {len(req.targets)} targets (Criticality: {req.criticality}, Owner: {req.owner})")
    try:
        results = await scan_targets(req.targets, timeout=SCAN_TIMEOUT, concurrency=SCAN_CONCURRENCY)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    certs, errors, notifications = [], [], []
    changes_detected = 0

    for r in results:
        if not r.success or not r.certificate:
            errors.append({"hostname": r.hostname, "port": r.port, "error": r.error})
            continue

        c = r.certificate
        key = (r.hostname.lower(), r.port)
        existing = _certs.get(key)
        owner = req.owner.strip() or (existing.get("owner", "") if existing else "")
        previous_days = existing.get("days_left") if existing else None
        a = calculate_risk(
            c.days_left, c.is_chain_valid, c.is_hostname_match, 
            c.is_self_signed, c.is_weak_crypto, bool(owner),
            req.criticality
        )
        if existing:
            cert_id = existing["id"]
        else:
            cert_id = _next_cert_id
            _next_cert_id += 1
        d = {
            "id": cert_id, "hostname": r.hostname, "port": r.port,
            "common_name": c.common_name, "sans": list(c.sans), "issuer": c.issuer,
            "thumbprint_sha256": c.thumbprint_sha256,
            "valid_from": c.valid_from.isoformat() if c.valid_from else None,
            "valid_to": c.valid_to.isoformat() if c.valid_to else None,
            "days_left": c.days_left, "is_self_signed": c.is_self_signed,
            "is_chain_valid": c.is_chain_valid, "is_hostname_match": c.is_hostname_match,
            "is_weak_crypto": c.is_weak_crypto,
            "status": a.status, "risk_score": a.score,
            "risk_factors": [{"name": f.name, "score": f.score, "description": f.description,
                              "recommendation": f.recommendation} for f in a.factors],
            "criticality": req.criticality, "owner": owner, "scanned_at": r.scanned_at.isoformat(),
        }
        differences = _certificate_changes(existing, d) if existing else []
        baseline_thumbprint = (existing or {}).get("baseline_thumbprint") or (existing or {}).get("thumbprint_sha256") or c.thumbprint_sha256
        d["baseline_thumbprint"] = baseline_thumbprint
        d["change_count"] = (existing or {}).get("change_count", 0)
        d["change_pending"] = (existing or {}).get("change_pending", False)
        d["last_change"] = (existing or {}).get("last_change")
        if differences:
            changes_detected += 1
            d["change_count"] += 1
            d["change_pending"] = True
            d["last_change"] = {
                "detected_at": d["scanned_at"],
                "old_thumbprint": existing.get("thumbprint_sha256"),
                "new_thumbprint": c.thumbprint_sha256,
                "old_status": existing.get("status"),
                "new_status": a.status,
                "old_risk_score": existing.get("risk_score", 0),
                "new_risk_score": a.score,
                "differences": differences,
                "acknowledged": False,
            }
        _certs[key] = d
        certs.append(d)

        reasons = [f.description for f in a.factors]
        pending_change = d["last_change"] if d["change_pending"] and d["last_change"] and not d["last_change"].get("acknowledged") else None
        notifications.append((r.hostname, r.port, c.common_name, c.thumbprint_sha256,
                              c.days_left, a.score, a.status, reasons, previous_days, pending_change))

    _store.save_many(certs)
    alert_tasks = []
    for host, port, cn, thumb, days, score, status, reasons, previous_days, change in notifications:
        alert_tasks.append(check_and_notify(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, host, port,
                                            cn, thumb, days, score, status, reasons,
                                            NOTIFY_THRESHOLDS, previous_days))
        if change:
            alert_tasks.append(notify_certificate_change(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
                                                        host, port, cn, thumb, days, score, change))
    await asyncio.gather(*alert_tasks)

    return {"total_targets": len(results), "successful": len(certs), "failed": len(errors),
            "changes_detected": changes_detected, "certificates": certs, "errors": errors}


@app.get("/api/v1/certificates")
async def list_certificates(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    status: str | None = None, sort_by: str = "risk_score", sort_order: str = "desc",
    query: str | None = None, changed_only: bool = False,
):
    data = [c for c in _certs.values() if not status or c["status"] == status]
    if changed_only:
        data = [c for c in data if c.get("change_pending", False)]
    if query:
        q = query.lower()
        data = [c for c in data if any(q in str(c.get(field) or "").lower()
                                       for field in ("hostname", "common_name", "owner", "issuer", "status", "valid_to", "days_left"))]
    sortable = {"hostname", "owner", "issuer", "valid_to", "days_left", "status", "risk_score", "criticality", "change_pending", "change_count"}
    if sort_by not in sortable:
        raise HTTPException(status_code=422, detail=f"Unsupported sort field: {sort_by}")
    if sort_order not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="sort_order must be asc or desc")
    data.sort(key=lambda c: str(c.get(sort_by) or "").lower() if isinstance(c.get(sort_by), str)
              else (c.get(sort_by) if c.get(sort_by) is not None else -1), reverse=(sort_order == "desc"))
    total = len(data)
    start = (page - 1) * page_size
    return {"items": data[start:start + page_size], "total": total, "page": page,
            "page_size": page_size, "total_pages": (total + page_size - 1) // page_size if total else 0}


@app.get("/api/v1/metrics/summary", response_model=MetricsSummary)
async def get_metrics():
    if not _certs:
        return MetricsSummary(total_certificates=0, overall_risk_score=0, status_distribution={
            "OK": 0, "INFORMATION": 0, "WARNING": 0, "CRITICAL": 0, "EXPIRED": 0},
            critical_count=0, expiring_soon=0, expired_count=0, self_signed_count=0,
            avg_days_left=0, pending_changes=0)

    certs = list(_certs.values())
    n = len(certs)
    dist: dict[str, int] = {"OK": 0, "INFORMATION": 0, "WARNING": 0, "CRITICAL": 0, "EXPIRED": 0}
    for c in certs:
        dist[c["status"]] = dist.get(c["status"], 0) + 1

    return MetricsSummary(
        total_certificates=n,
        overall_risk_score=round(sum(c["risk_score"] for c in certs) / n, 1),
        status_distribution=dist,
        critical_count=sum(1 for c in certs if c["status"] in ("CRITICAL", "EXPIRED")),
        expiring_soon=sum(1 for c in certs if 0 <= c["days_left"] <= 14),
        expired_count=sum(1 for c in certs if c["days_left"] < 0),
        self_signed_count=sum(1 for c in certs if c["is_self_signed"]),
        avg_days_left=round(sum(c["days_left"] for c in certs) / n, 1),
        pending_changes=sum(1 for c in certs if c.get("change_pending", False)),
    )


@app.post("/api/v1/certificates/{certificate_id}/acknowledge-change")
async def acknowledge_certificate_change(certificate_id: int):
    cert = next((c for c in _certs.values() if c["id"] == certificate_id), None)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if cert.get("change_pending"):
        cert["change_pending"] = False
        cert["baseline_thumbprint"] = cert["thumbprint_sha256"]
        if cert.get("last_change"):
            cert["last_change"]["acknowledged"] = True
        _store.save_many([cert])
        logging.info("Certificate change acknowledged for %s:%s", cert["hostname"], cert["port"])
    return {"certificate": cert}


@app.get("/api/v1/reports/export")
async def export_csv():
    if not _certs:
        raise HTTPException(404, "No data")
    buf = io.StringIO()
    cols = ["hostname", "port", "owner", "criticality", "common_name", "sans", "issuer",
            "thumbprint_sha256", "valid_from", "valid_to", "days_left", "is_self_signed",
            "is_chain_valid", "is_hostname_match", "is_weak_crypto", "status", "risk_score",
            "risk_factors", "baseline_thumbprint", "change_count", "change_pending", "last_change", "scanned_at"]
    w = csv.DictWriter(buf, cols, extrasaction="ignore")
    w.writeheader()
    for c in _certs.values():
        safe = {key: _csv_safe(value) for key, value in c.items()
                if key not in ("risk_factors", "sans", "last_change")}
        safe["sans"] = _csv_safe(", ".join(c.get("sans", [])))
        safe["risk_factors"] = _csv_safe(" | ".join(
            f"{f['description']}: {f['recommendation']}" for f in c["risk_factors"]
        ))
        safe["last_change"] = _csv_safe(json.dumps(c.get("last_change"), ensure_ascii=False))
        w.writerow(safe)
    buf.seek(0)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(iter([buf.getvalue().encode("utf-8-sig")]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f"attachment; filename=report_{ts}.csv"})


@app.get("/health")
async def health():
    return {"status": "ok"}
