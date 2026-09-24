"""Risk scoring engine — composite Risk Score 0..100."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from .config import THRESHOLD_OK, THRESHOLD_INFO, THRESHOLD_WARNING

# ── Configurable weights ─────────────────────────────────────

RISK_WEIGHTS: dict[str, Any] = {
    "chain_invalid": 30,
    "hostname_mismatch": 25,
    "self_signed": 20,
    "weak_crypto": 25,
    "no_owner": 10,
    "criticality": {"LOW": 1.0, "MEDIUM": 1.1, "HIGH": 1.3, "CRITICAL": 1.5},
}


@dataclass
class RiskFactor:
    name: str
    score: int
    description: str
    recommendation: str


@dataclass
class RiskAssessment:
    score: int
    grade: str       # Low / Medium / High / Critical
    status: str      # OK / INFORMATION / WARNING / CRITICAL / EXPIRED
    factors: list[RiskFactor] = field(default_factory=list)


def _expiry_score(days: int) -> tuple[int, str]:
    if days < 0:
        return 100, f"Срок действия истёк {abs(days)} дн. назад"
    if days > THRESHOLD_OK:
        return 0, f"Действует ещё {days} дн."
    if days > THRESHOLD_INFO:
        return 15, f"Истекает через {days} дн. (уровень Information)"
    if days > THRESHOLD_WARNING:
        return 40, f"Истекает через {days} дн. (уровень Warning)"
    return 80, f"Истекает через {days} дн. (уровень Critical)"


def calculate_risk(
    days_left: int,
    is_chain_valid: bool,
    is_hostname_match: bool,
    is_self_signed: bool,
    is_weak_crypto: bool,
    has_owner: bool,
    criticality: str = "MEDIUM",
) -> RiskAssessment:
    w = RISK_WEIGHTS
    factors: list[RiskFactor] = []
    raw = 0

    # Expiry
    es, ed = _expiry_score(days_left)
    if es > 0:
        recommendation = "Продлите или замените сертификат до окончания срока действия." if days_left >= 0 else "Немедленно замените истёкший сертификат."
        factors.append(RiskFactor("expiry", es, ed, recommendation))
    raw += es

    # Chain
    if not is_chain_valid:
        p = w["chain_invalid"]
        factors.append(RiskFactor("chain_invalid", p, "Не удалось проверить цепочку доверия сертификата", "Установите полную цепочку сертификата от доверенного центра сертификации."))
        raw += p

    # Hostname
    if not is_hostname_match:
        p = w["hostname_mismatch"]
        factors.append(RiskFactor("hostname_mismatch", p, "Имя сервиса не совпадает с DNS/IP в CN или SAN", "Выпустите сертификат, в SAN которого указано DNS-имя или IP сервиса."))
        raw += p

    # Self-signed
    if is_self_signed:
        p = w["self_signed"]
        factors.append(RiskFactor("self_signed", p, "Сертификат подписан самим собой", "Замените его сертификатом от доверенного центра сертификации."))
        raw += p
        
    # Weak Crypto
    if is_weak_crypto:
        p = w["weak_crypto"]
        factors.append(RiskFactor("weak_crypto", p, "Слабые криптографические параметры (например SHA-1/MD5 или RSA менее 2048 бит)", "Перевыпустите сертификат с современным алгоритмом подписи и ключом RSA не менее 2048 бит."))
        raw += p
        
    # Owner missing
    if not has_owner:
        p = w["no_owner"]
        factors.append(RiskFactor("no_owner", p, "Не назначен ответственный за сервис", "Назначьте владельца или команду, которая будет контролировать продление и устранение проблем."))
        raw += p

    # Criticality multiplier
    mult = w["criticality"].get(criticality.upper(), 1.0)
    if mult != 1.0:
        factors.append(RiskFactor("criticality", 0, f"Множитель ×{mult} для критичности {criticality}", "Учитывайте критичность сервиса при планировании устранения проблем."))

    score = min(100, max(0, int(raw * mult)))

    grade = "Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"

    if days_left < 0:
        status = "EXPIRED"
    elif score >= 80:
        status = "CRITICAL"
    elif score >= 40:
        status = "WARNING"
    elif score >= 15:
        status = "INFORMATION"
    else:
        status = "OK"

    return RiskAssessment(score=score, grade=grade, status=status, factors=factors)
