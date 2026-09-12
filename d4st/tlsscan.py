"""Lightweight TLS / certificate hygiene scan (stdlib `ssl` only).

testssl.sh is the gold standard but is far too slow against some hosts (Azure App Service TLS
probing blew past a 240 s budget on APP). This covers the high-value, Burp-parity classes fast:
certificate validity/expiry/issuer (Burp's "TLS certificate") + deprecated-protocol support
(TLS 1.0/1.1). Read-only handshakes; no attack traffic.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone


def _peer_cert(host: str, port: int, timeout: float = 10.0):
    """Handshake with full validation and return (cert_dict, negotiated_version)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            return ss.getpeercert(), ss.version()


def tls_scan(host: str, port: int = 443) -> list[dict]:
    """Return TLS/cert hygiene findings [{category, param, detail}]. Best-effort + isolated."""
    findings: list[dict] = []
    host = (host or "").split("://")[-1].split("/")[0].split(":")[0]
    if not host:
        return findings

    # ---- 1) certificate validity + details (Burp: "TLS certificate") ----------------------
    try:
        cert, ver = _peer_cert(host, port)
        na = cert.get("notAfter")
        issuer = {}
        for _rdn in cert.get("issuer", []):
            for _k, _v in _rdn:
                issuer[_k] = _v
        org = issuer.get("organizationName") or issuer.get("commonName") or "?"
        if na:
            try:
                exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
            except ValueError:
                days = None
            if days is not None and days < 0:
                findings.append({"category": "tls-configuration", "param": "certificate-expired",
                                 "detail": f"TLS certificate EXPIRED {abs(days)} day(s) ago "
                                           f"(notAfter {na}, issuer {org})"})
            elif days is not None and days < 30:
                findings.append({"category": "tls-configuration", "param": "certificate-expiring",
                                 "detail": f"TLS certificate expires in {days} day(s) "
                                           f"(notAfter {na}, issuer {org})"})
            else:
                findings.append({"category": "tls-configuration", "param": "certificate-info",
                                 "detail": f"TLS certificate: issuer={org}, expires {na} "
                                           f"({days if days is not None else '?'} days), "
                                           f"negotiated {ver}"})
    except ssl.SSLCertVerificationError as e:
        msg = getattr(e, "verify_message", "") or str(e)
        findings.append({"category": "tls-configuration", "param": "certificate-invalid",
                         "detail": f"TLS certificate validation FAILED: {msg} "
                                   "(expired / self-signed / hostname mismatch / untrusted chain)"})
    except Exception:  # noqa: BLE001 - host not reachable on 443 / not a TLS service
        return findings

    # ---- 2) deprecated protocol support (TLS 1.0 / 1.1) --------------------------------------
    # Best-effort: if the local OpenSSL itself refuses old protocols we simply can't confirm
    # (reported as not-detected, never a false negative claim).
    for name, ver_enum in (("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                           ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if ver_enum is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver_enum
            ctx.maximum_version = ver_enum
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    findings.append({"category": "tls-configuration", "param": f"deprecated-{name}",
                                     "detail": f"Deprecated {name} protocol is ENABLED — disable it "
                                               "(PCI/modern-TLS requires >= TLS 1.2)"})
        except Exception:  # noqa: BLE001 - refused (good) or locally unsupported
            continue
    return findings
