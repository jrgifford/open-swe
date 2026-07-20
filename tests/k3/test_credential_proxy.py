from __future__ import annotations

import base64
import importlib.util
import sys
import types
from pathlib import Path


def load_addon(monkeypatch):  # noqa: ANN001, ANN201
    fake_http = types.SimpleNamespace(
        HTTPFlow=object,
        Response=types.SimpleNamespace(make=lambda *args, **kwargs: (args, kwargs)),
    )
    monkeypatch.setitem(sys.modules, "mitmproxy", types.SimpleNamespace(http=fake_http))
    monkeypatch.setenv("PROXY_ADMIN_TOKEN", "admin-test-secret")
    path = Path(__file__).parents[2] / "deploy/k3/proxy/addon.py"
    spec = importlib.util.spec_from_file_location("k3_proxy_addon_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_injects_only_for_registered_source_and_scoped_repository(monkeypatch) -> None:  # noqa: ANN001
    addon = load_addon(monkeypatch)
    addon.CREDENTIALS["10.42.0.10"] = (
        "real-token",
        frozenset({"owner/repo"}),
        float("inf"),
    )

    allowed = addon.authorize("10.42.0.10", "api.github.com", "/repos/owner/repo/issues")
    assert allowed == "Bearer real-token"
    assert addon.authorize("10.42.0.10", "api.github.com", "/repos/owner/other") is None
    assert addon.authorize("10.42.0.11", "api.github.com", "/repos/owner/repo") is None


def test_git_smart_http_uses_basic_upstream_without_client_secret(monkeypatch) -> None:  # noqa: ANN001
    addon = load_addon(monkeypatch)
    addon.CREDENTIALS["10.42.0.10"] = (
        "real-token",
        frozenset({"owner/repo"}),
        float("inf"),
    )

    authorization = addon.authorize("10.42.0.10", "github.com", "/owner/repo.git/info/refs")

    assert authorization and authorization.startswith("Basic ")
    assert base64.b64decode(authorization.removeprefix("Basic ")).decode() == (
        "x-access-token:real-token"
    )
