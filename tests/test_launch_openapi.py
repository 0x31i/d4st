"""launch now seeds the documented API surface from an OpenAPI/Swagger spec (the depth an API-only
app — Flutter/CanvasKit, headless API — otherwise never gets because the crawler reaches ~1 URL).
Covers the spec->endpoint-URL expansion used to enrich the launch seed list."""
import json
import types
import pytest

from d4st import engagement as E


class _R:
    def __init__(self, spec, status=200):
        self._spec = spec
        self.status_code = status
    def json(self):
        return self._spec
    @property
    def text(self):
        return json.dumps(self._spec)


def _patch_httpx(monkeypatch, spec):
    fake = types.SimpleNamespace(
        get=lambda *a, **k: _R(spec),
        post=lambda *a, **k: _R(spec),
    )
    monkeypatch.setitem(__import__("sys").modules, "httpx", fake)


def test_openapi3_spec_expands_to_endpoint_urls(monkeypatch):
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.x/v1"}],
        "paths": {
            "/users/{id}": {"get": {"parameters": [
                {"name": "id", "in": "path"}, {"name": "q", "in": "query"}]}},
            "/pay": {"post": {}},
        },
    }
    _patch_httpx(monkeypatch, spec)
    targets, urls = E.seed_targets_from_openapi("https://api.x/swagger.json", "")
    assert "https://api.x/v1/users/1" in urls   # {id} path param -> concrete test value
    assert "https://api.x/v1/pay" in urls
    # a GET with query/path params becomes an injection target
    assert any(t.url.endswith("/users/1") for t in targets)


def test_swagger2_basepath(monkeypatch):
    spec = {
        "swagger": "2.0",
        "basePath": "/api",
        "paths": {"/thing": {"get": {}}},
    }
    _patch_httpx(monkeypatch, spec)
    _targets, urls = E.seed_targets_from_openapi("https://h.example/swagger.json", "")
    assert "https://h.example/api/thing" in urls


def test_bad_spec_is_safe(monkeypatch):
    _patch_httpx(monkeypatch, ["not", "a", "dict"])
    targets, urls = E.seed_targets_from_openapi("https://h.example/x.json", "")
    assert targets == [] and urls == []
