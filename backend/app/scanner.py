"""Async TLS scanner — certificate retrieval and parsing."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import ssl
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Optional, Sequence
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger(__name__)

# ── Data models ──────────────────────────────────────────────

@dataclass(frozen=True)
class CertificateInfo:
    common_name: Optional[str] = None
    sans: list[str] = field(default_factory=list)
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    thumbprint_sha256: str = ""
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_left: int = 0
    is_self_signed: bool = False
    is_chain_valid: bool = True
    is_hostname_match: bool = True
    is_weak_crypto: bool = False


@dataclass
class ScanResult:
    hostname: str
    port: int
    certificate: Optional[CertificateInfo] = None
    error: Optional[str] = None
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def success(self) -> bool:
        return self.certificate is not None and self.error is None


# ── Helpers ──────────────────────────────────────────────────

_OID_SHORT = {
    NameOID.COMMON_NAME: "CN", NameOID.ORGANIZATION_NAME: "O",
    NameOID.COUNTRY_NAME: "C", NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
}


MAX_TARGETS = 1024


def _parse_target(entry: str, default_port: int) -> tuple[str, int]:
    """Accept a hostname/IP with optional port, an HTTPS URL, or an IPv6 URL."""
    value = entry.strip()
    if not value:
        raise ValueError("Target cannot be empty")

    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https":
            raise ValueError(f"Only HTTPS targets are supported: {value}")
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f"Invalid HTTPS target: {value}")
        try:
            port = parsed.port if parsed.port is not None else default_port
        except ValueError as exc:
            raise ValueError(f"Invalid port in target: {value}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port in target: {value}")
        return parsed.hostname.rstrip(".").lower(), port

    if value.startswith("["):
        parsed = urlsplit(f"//{value}")
        if not parsed.hostname:
            raise ValueError(f"Invalid IPv6 target: {value}")
        try:
            port = parsed.port if parsed.port is not None else default_port
        except ValueError as exc:
            raise ValueError(f"Invalid port in target: {value}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port in target: {value}")
        return parsed.hostname.lower(), port

    try:
        address = ipaddress.ip_address(value)
        return str(address), default_port
    except ValueError:
        pass

    host, port = value, default_port
    if value.count(":") == 1:
        possible_host, possible_port = value.rsplit(":", 1)
        if possible_port.isdigit():
            host, port = possible_host, int(possible_port)
    if not host or not 1 <= port <= 65535:
        raise ValueError(f"Invalid target: {value}")
    return host.rstrip(".").lower(), port


def _expand_targets(raw: Sequence[str], default_port: int = 443) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for entry in raw:
        value = entry.strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        if network is not None:
            host_port = _parse_target(str(network.network_address), default_port)
            host_count = network.num_addresses
            if isinstance(network, ipaddress.IPv4Network) and network.prefixlen < 31:
                host_count -= 2
            if host_count > MAX_TARGETS:
                raise ValueError(f"Network {value} contains more than {MAX_TARGETS} targets")
            candidates = ((str(address), host_port[1]) for address in network.hosts())
        else:
            candidates = (_parse_target(value, default_port),)
        for target in candidates:
            if target not in seen:
                seen.add(target)
                out.append(target)
                if len(out) > MAX_TARGETS:
                    raise ValueError(f"A scan can include at most {MAX_TARGETS} unique targets")
    return out


def _x509_name(name: x509.Name) -> str:
    return ", ".join(
        f"{_OID_SHORT.get(a.oid, a.oid.dotted_string)}={a.value}" for a in name
    )


def _match_hostname(hostname: str, dns_sans: list[str], ip_sans: list[str],
                    cn: Optional[str], has_san_extension: bool) -> bool:
    try:
        address = str(ipaddress.ip_address(hostname))
        return address in ip_sans
    except ValueError:
        candidates = dns_sans if has_san_extension else ([cn] if cn else [])
    hl = hostname.rstrip(".").lower()
    for n in candidates:
        nl = n.lower()
        if nl == hl:
            return True
        if nl.startswith("*."):
            wd = nl[2:]
            if hl.endswith(f".{wd}") and hl.count(".") == wd.count(".") + 1:
                return True
    return False


def _parse_cert(der: bytes, hostname: str) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der)

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else None

    dns_sans: list[str] = []
    ip_sans: list[str] = []
    has_san_extension = False
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        has_san_extension = True
        dns_sans = ext.value.get_values_for_type(x509.DNSName)
        ip_sans = [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    sans = dns_sans + ip_sans

    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    thumbprint = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))

    now = datetime.now(timezone.utc)
    is_self = False
    if cert.issuer == cert.subject:
        try:
            cert.verify_directly_issued_by(cert)
            is_self = True
        except Exception:
            pass

    # Weak crypto check
    try:
        sig_alg = cert.signature_hash_algorithm.name
    except Exception:
        sig_alg = "unknown"
        
    try:
        pk = cert.public_key()
        key_size = getattr(pk, "key_size", 0)
    except Exception:
        pk, key_size = None, 0
        
    is_weak_crypto = False
    if sig_alg in ("md5", "sha1"):
        is_weak_crypto = True
    if isinstance(pk, rsa.RSAPublicKey) and key_size < 2048:
        is_weak_crypto = True
    if isinstance(pk, ec.EllipticCurvePublicKey) and key_size < 256:
        is_weak_crypto = True
    if isinstance(pk, dsa.DSAPublicKey) and key_size < 2048:
        is_weak_crypto = True

    return CertificateInfo(
        common_name=cn, sans=sans,
        issuer=_x509_name(cert.issuer),
        serial_number=format(cert.serial_number, "x").upper(),
        thumbprint_sha256=thumbprint,
        valid_from=cert.not_valid_before_utc,
        valid_to=cert.not_valid_after_utc,
        days_left=(cert.not_valid_after_utc - now).days,
        is_self_signed=is_self,
        is_chain_valid=not is_self,
        is_hostname_match=_match_hostname(hostname, dns_sans, ip_sans, cn, has_san_extension),
        is_weak_crypto=is_weak_crypto,
    )


# ── Core scanner ─────────────────────────────────────────────

async def _get_peer_certificate(host: str, port: int, timeout: float, verify: bool) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    if not verify:
        ctx.verify_mode = ssl.CERT_NONE

    _, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout,
    )
    try:
        ssl_object = writer.transport.get_extra_info("ssl_object")
        return ssl_object.getpeercert(binary_form=True) if ssl_object else b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def _scan_one(host: str, port: int, timeout: float) -> ScanResult:
    try:
        try:
            der = await _get_peer_certificate(host, port, timeout, verify=True)
            chain_valid = True
        except ssl.SSLError:
            # Preserve visibility into untrusted/expired chains by retrieving
            # the leaf certificate once without verification.
            der = await _get_peer_certificate(host, port, timeout, verify=False)
            chain_valid = False

        if not der:
            return ScanResult(host, port, error="No certificate presented")
        cert = replace(_parse_cert(der, host), is_chain_valid=chain_valid)
        return ScanResult(host, port, certificate=cert)
    except asyncio.TimeoutError:
        return ScanResult(host, port, error=f"Timeout ({timeout}s)")
    except ssl.SSLError as e:
        return ScanResult(host, port, error=f"SSL error: {e}")
    except socket.gaierror as e:
        return ScanResult(host, port, error=f"DNS failed: {e}")
    except ConnectionRefusedError:
        return ScanResult(host, port, error="Connection refused")
    except OSError as e:
        return ScanResult(host, port, error=f"Network: {e}")
    except Exception as e:
        log.exception("Unexpected: %s:%d", host, port)
        return ScanResult(host, port, error=str(e))


async def scan_targets(
    raw_targets: Sequence[str], timeout: float = 10.0, concurrency: int = 50,
) -> list[ScanResult]:
    targets = _expand_targets(raw_targets)
    if not targets:
        raise ValueError("Provide at least one non-empty target")
    sem = asyncio.Semaphore(concurrency)

    async def go(h: str, p: int) -> ScanResult:
        async with sem:
            return await _scan_one(h, p, timeout)

    return list(await asyncio.gather(*(go(h, p) for h, p in targets)))
