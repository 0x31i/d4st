"""Tests for the gap-closing adapters (lfi_fuzz, rfi_oast, ghauri, dotdotpwn) + OAST server.

Focus on the parse/wiring logic that silently broke in the field (ffuf plaintext output, OAST
callback bookkeeping), not on live tool execution.
"""

from __future__ import annotations

import httpx

from d4st.oast import OAST_BODY_TOKEN, OastServer
from d4st.orchestrator.adapters import REGISTRY
from d4st.orchestrator.adapters.lfi_fuzz import _parse_ffuf


def test_gap_adapters_registered():
    for name in ("lfi_fuzz", "rfi_oast", "ghauri", "dotdotpwn"):
        assert name in REGISTRY, f"{name} not registered"
        assert REGISTRY[name].detects is True


def test_parse_ffuf_reads_plaintext_matched_payloads():
    # ffuf -s emits one matched FUZZ payload per line (NOT json); banner-ish [..] lines ignored.
    raw = "../../../../etc/passwd\n%2e%2e/%2e%2e/etc/passwd\n\n[INFO] banner\n"
    out = _parse_ffuf(raw)
    assert out == ["../../../../etc/passwd", "%2e%2e/%2e%2e/etc/passwd"]
    assert _parse_ffuf("") == []


def test_oast_server_records_callback_and_reflects_token():
    with OastServer(bind="127.0.0.1", port=0) as oast:
        token = "abc123"
        url = oast.probe_url("127.0.0.1", token)
        r = httpx.get(url, timeout=5)
        assert OAST_BODY_TOKEN in r.text          # in-band channel
        assert oast.saw(token) is True             # callback channel
        assert oast.saw("never-requested") is False


def test_lfi_fuzz_no_params_is_ok_not_error():
    from d4st.orchestrator.adapters.base import RunContext
    res = REGISTRY["lfi_fuzz"].run(RunContext(target="http://x/no-params", seed_urls=[]))
    assert res.ok is True
    assert res.findings == []
