"""Art must be cosmetic and OUTPUT-SAFE: it may only ever touch stderr, and it must be
silent whenever stderr is not an interactive terminal or the user opted out. These tests
guard the invariant so a future change can't start polluting --json / piped output."""

from __future__ import annotations

import io
import sys

from d4st import art


def test_disabled_when_not_a_tty(monkeypatch):
    # pytest already captures stderr (not a tty), but be explicit.
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.delenv("D4ST_NO_ART", raising=False)
    monkeypatch.delenv("CI", raising=False)
    assert art.art_enabled() is False


def test_env_optout_disables_even_on_tty(monkeypatch):
    fake = io.StringIO()
    fake.isatty = lambda: True  # pretend it's a terminal
    monkeypatch.setattr(sys, "stderr", fake)
    monkeypatch.setenv("D4ST_NO_ART", "1")
    assert art.art_enabled() is False


def test_json_flag_env_disables(monkeypatch):
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr(sys, "stderr", fake)
    monkeypatch.delenv("D4ST_NO_ART", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("D4ST_JSON", "1")
    assert art.art_enabled() is False


def test_banner_and_phase_write_nothing_when_disabled(monkeypatch, capsys):
    monkeypatch.setenv("D4ST_NO_ART", "1")
    art.banner()
    art.phase("CRAWLER", "mapping", "crawl")
    art.wink("aside")
    out = capsys.readouterr()
    assert out.out == ""   # never stdout, ever
    assert out.err == ""   # silent when disabled


def test_banner_and_phase_emit_only_to_stderr_when_enabled(monkeypatch):
    fake_err = io.StringIO()
    fake_err.isatty = lambda: True
    fake_out = io.StringIO()
    monkeypatch.setattr(sys, "stderr", fake_err)
    monkeypatch.setattr(sys, "stdout", fake_out)
    monkeypatch.delenv("D4ST_NO_ART", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("D4ST_JSON", raising=False)
    art.banner()
    art.phase("CRAWLER", "mapping", "crawl")   # 'crawl' phase -> pikachu
    assert fake_out.getvalue() == ""          # stdout stays pristine
    err = fake_err.getvalue()
    assert "-PIKACHU" in err                  # name tag identifies the creature
    assert "A wild" not in err                # no "appeared" framing


def test_every_phase_creature_resolves():
    for key in art._PHASE_CREATURE.values():
        assert key in art._CREATURES
    # unknown phase still maps to a real creature via rotation
    assert art._pick("totallyunknownphase") in art._CREATURES
