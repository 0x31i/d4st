"""LFI / path-traversal fuzz adapter (detection, active).

The blind WAVSEP benchmark exposed a payload-breadth gap: our deterministic verify_lfi and
nuclei's 3 core LFI templates caught ~12% of reached cases. WAVSEP's LFI section is a
permutation stress-test (traversal depth x encoding x OS path x wrapper x null-byte), so
recall tracks payload breadth. This adapter drives ffuf (fast, parallel) over the curated
PayloadsAllTheThings traversal corpus and confirms a hit by matching a filesystem signature
(root:x:0:0, win.ini [extensions], /proc environ) in the response body, so every hit is a
deterministic true positive, not a heuristic.
"""

from __future__ import annotations

import os
from urllib.parse import parse_qs, urlsplit

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

# Vendor wordlists (cloned from PayloadsAllTheThings). Ordered small -> large so a cheap
# depth pass runs first; the big Traversal.txt is opt-in via options["lfi_deep"].
_VENDOR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "vendor",
                       "PayloadsAllTheThings", "File Inclusion", "Intruders")
_WORDLISTS = {
    "jhaddix": os.path.join(_VENDOR, "JHADDIX_LFI.txt"),
    "nullbyte": os.path.join(_VENDOR, "List_Of_File_To_Include_NullByteAdded.txt"),
    "deep": os.path.join(_VENDOR, "Traversal.txt"),           # 378KB, opt-in
    "windows": os.path.join(_VENDOR, "LFI-WindowsFileCheck.txt"),
}
# Response signatures that PROVE inclusion of a real system file (no heuristics).
_SIGNATURES = [
    "root:x:0:0", "root:.*:0:0:",          # /etc/passwd
    "\\[extensions\\]", "\\[fonts\\]",     # win.ini
    "DOCUMENT_ROOT=", "HTTP_USER_AGENT=",  # /proc/self/environ
    "; for 16-bit app support",            # win.ini variant
    "daemon:.*:/usr/sbin",                 # passwd variant
]


def _first_param(url: str) -> str | None:
    q = parse_qs(urlsplit(url).query)
    return next(iter(q), None)


@register
class LfiFuzzAdapter(ToolAdapter):
    name = "lfi_fuzz"
    stage = "scan"
    discovers = False
    detects = True
    active = True  # emits traversal payloads; authorization-gated
    binary = "ffuf"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True, note="no parameterized URLs")

        lists = ["jhaddix", "nullbyte"]
        if ctx.options.get("lfi_windows"):
            lists.append("windows")
        if ctx.options.get("lfi_deep"):
            lists.append("deep")
        matcher = "|".join(_SIGNATURES)
        cmd = f"ffuf FUZZ over {len(targets)} url(s) x {lists} (sig-matched)"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="ffuf binary not found on PATH")

        cookie = _cookie_header(ctx.session, ctx.target)
        findings: list[dict] = []
        seen: set[str] = set()
        for url in targets:
            param = _first_param(url)
            if not param:
                continue
            base = url.split("?")[0]
            fuzz_url = f"{base}?{param}=FUZZ"
            for wl in lists:
                path = _WORDLISTS.get(wl)
                if not path or not os.path.exists(path):
                    continue
                # -s makes ffuf print ONLY matched payloads (the FUZZ values) to stdout, one
                # per line. (-o - -of json does NOT stream JSON to stdout, it drops it.)
                # Throttle: ffuf defaults to 40 threads. Honor the scan politeness (workers +
                # request rate) so LFI fuzzing doesn't DoS a fragile target.
                args = ["ffuf", "-u", fuzz_url, "-w", f"{path}:FUZZ", "-mr", matcher,
                        "-s", "-t", str(ctx.options.get("workers", ctx.options.get("ffuf_threads", 40))),
                        "-timeout", str(ctx.options.get("http_timeout", 6))]
                # Rate: LFI fuzzing is READ-ONLY GET file-reading (content-discovery risk class,
                # like feroxbuster), NOT attack traffic — so it uses the faster read-only tier,
                # not the 2-rps injection throttle. Pinning it to the injection rate over a
                # ~5.4k-payload corpus took ~12min PER non-vulnerable URL (benchmark-intractable).
                _rate = ctx.options.get("lfi_rate") or max(int(ctx.options.get("rps", 2) or 2) * 6, 12)
                args += ["-rate", str(int(_rate))]
                if cookie:
                    args += ["-H", f"Cookie: {cookie}"]
                try:
                    # Tight per-wordlist wall-time: a vulnerable case hits fast (small list first,
                    # then break); a non-vulnerable one must not burn the roster's 1800s budget
                    # grinding the whole corpus. Cap at 90s regardless of the roster timeout.
                    proc = self._exec(args, timeout=min(int(ctx.options.get("timeout", 120)), 90))
                except Exception:  # noqa: BLE001,S112 - one URL's tool error must not sink the scan
                    continue
                payloads = _parse_ffuf(proc.stdout)
                if payloads and base not in seen:
                    seen.add(base)
                    findings.append({
                        "type": "lfi", "url": base, "param": param,
                        "matched-at": base, "wordlist": wl,
                        "payload": payloads[0], "hits": len(payloads),
                        "evidence": "filesystem signature reflected in response",
                    })
                    break  # confirmed for this URL; stop trying wordlists
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} confirmed LFI/traversal")


def _parse_ffuf(raw: str) -> list[str]:
    """ffuf -s prints one matched payload (the FUZZ value) per line; each line is a traversal
    payload whose response matched a filesystem signature -> a confirmed hit."""
    return [ln.strip() for ln in (raw or "").splitlines()
            if ln.strip() and not ln.startswith("[")]
