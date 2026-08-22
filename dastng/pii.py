"""PII / PHI disclosure detection — industry-grade passive scanning, Burp-style.

Modeled on how Burp's passive scanner flags disclosed sensitive data: inspect every response
body the engagement sees, detect PII entities with confidence scoring + checksum validation
(Luhn for cards, format/context for SSN), and report the TYPE + a MASKED value + confidence +
location. It never stores the raw value in plaintext — a security tool must not itself become
a PHI store (matters for healthcare clients like FHC).

Backed by Microsoft Presidio (presidio-analyzer + spaCy NER + validators). Degrades to a
minimal built-in recognizer set (email / SSN-format / Luhn-checked card) if Presidio is not
installed, so the stage never hard-fails.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

# Entities relevant to web-app PII/PHI disclosure. NER/loose ones are gated to high confidence
# to keep false positives Burp-low.
_ENTITIES = [
    "EMAIL_ADDRESS", "US_SSN", "CREDIT_CARD", "PHONE_NUMBER", "US_DRIVER_LICENSE",
    "US_PASSPORT", "US_ITIN", "MEDICAL_LICENSE", "IBAN_CODE", "IP_ADDRESS", "PERSON",
]
_HIGH_CONF_ONLY = {"PERSON", "IP_ADDRESS"}   # NER / loose -> require higher score
_HIGH_CONF = 0.85

# PHI/PII severity: disclosure is Low/Info like Burp; SSN/CC/medical lean Low, rest Info.
_SEVERITY = {"US_SSN": "low", "CREDIT_CARD": "low", "MEDICAL_LICENSE": "low",
             "US_PASSPORT": "low", "US_DRIVER_LICENSE": "low", "US_ITIN": "low"}


@dataclass
class PiiHit:
    entity: str
    masked: str          # value with all-but-last-4 masked; never the raw PII
    score: float
    url: str
    severity: str = "info"


def _mask(v: str) -> str:
    """Mask so evidence is auditable but not a PHI leak: emails keep 1 char + domain, others
    keep last 4."""
    v = (v or "").strip()
    if "@" in v:
        user, _, dom = v.partition("@")
        return (user[:1] + "***@" + dom) if user else "***@" + dom
    tail = v[-4:] if len(v) > 4 else ""
    return "*" * max(0, len(v) - len(tail)) + tail


def _luhn(num: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", num)]
    if len(d) < 13:
        return False
    s, alt = 0, False
    for x in reversed(d):
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        s += x
        alt = not alt
    return s % 10 == 0


class PiiScanner:
    """Detect PII in response text. Presidio if present, minimal fallback otherwise."""

    def __init__(self, min_score: float = 0.35):
        self.min_score = min_score
        self._engine = None
        try:
            from presidio_analyzer import AnalyzerEngine
            self._engine = AnalyzerEngine()
        except Exception:  # noqa: BLE001 - optional dep; fall back
            self._engine = None

    @property
    def available(self) -> bool:
        return self._engine is not None

    @property
    def backend(self) -> str:
        return "presidio" if self._engine else "builtin-fallback"

    def scan_text(self, text: str, url: str = "") -> list[PiiHit]:
        if not text:
            return []
        hits = self._presidio(text, url) if self._engine else self._fallback(text, url)
        # dedup by (entity, masked) so we don't spam identical values per page
        seen: set = set()
        out: list[PiiHit] = []
        for h in hits:
            k = (h.entity, h.masked)
            if k in seen:
                continue
            seen.add(k)
            out.append(h)
        return out

    def _presidio(self, text: str, url: str) -> list[PiiHit]:
        try:
            results = self._engine.analyze(text=text[:200000], entities=_ENTITIES, language="en")
        except Exception:  # noqa: BLE001
            return self._fallback(text, url)
        out = []
        for r in results:
            thr = _HIGH_CONF if r.entity_type in _HIGH_CONF_ONLY else self.min_score
            if r.score < thr:
                continue
            val = text[r.start:r.end]
            if r.entity_type == "CREDIT_CARD" and not _luhn(val):
                continue   # format-only match without Luhn -> drop (kills the FPs)
            out.append(PiiHit(r.entity_type, _mask(val), round(float(r.score), 2), url,
                              _SEVERITY.get(r.entity_type, "info")))
        return out

    # --- minimal fallback (no Presidio): high-signal patterns only -----------------
    _RX: ClassVar[dict] = {
        "EMAIL_ADDRESS": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
        "US_SSN": re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    }

    def _fallback(self, text: str, url: str) -> list[PiiHit]:
        out = []
        for ent, rx in self._RX.items():
            for m in rx.finditer(text[:200000]):
                val = m.group(0)
                if ent == "CREDIT_CARD" and not _luhn(val):
                    continue
                out.append(PiiHit(ent, _mask(val), 0.6, url, _SEVERITY.get(ent, "info")))
        return out


def scan_urls(urls: list[str], cookie: str = "", min_score: float = 0.35,
              cap: int = 0) -> list[PiiHit]:
    """Fetch each URL once and PII-scan the body (Burp-style passive pass over the crawled
    surface). cap>0 limits pages scanned."""
    import httpx
    scanner = PiiScanner(min_score=min_score)
    headers = {"Cookie": cookie} if cookie else {}
    targets = urls[:cap] if cap else urls
    out: list[PiiHit] = []
    with httpx.Client(follow_redirects=True, timeout=15, headers=headers) as client:
        for u in targets:
            try:
                body = client.get(u).text
            except Exception:  # noqa: BLE001,S112 - one bad page must not sink the pass
                continue
            out.extend(scanner.scan_text(body, u))
    return out
