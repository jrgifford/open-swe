from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from kubernetes import client

from agent.integrations.k3 import K3Sandbox, _safe_path, _status_exit_code
from agent.utils.sandbox import SANDBOX_FACTORIES, validate_sandbox_startup_config


def test_k3_provider_registered() -> None:
    assert SANDBOX_FACTORIES["k3"] == ("agent.integrations.k3", "create_k3_sandbox")


def test_startup_validation_requires_image(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SANDBOX_TYPE", "k3")
    monkeypatch.delenv("K3_SANDBOX_IMAGE", raising=False)
    with pytest.raises(ValueError, match="K3_SANDBOX_IMAGE"):
        validate_sandbox_startup_config()


def test_startup_validation_rejects_invalid_capacity(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("K3_SANDBOX_IMAGE", "sandbox:test")
    monkeypatch.setenv("K3_SANDBOX_CAPACITY", "0")
    with pytest.raises(ValueError, match="> 0"):
        K3Sandbox.validate_startup_config()


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/workspace/file", "/workspace/file"),
        ("relative", None),
        ("/workspace/../etc/passwd", None),
        ("/workspace//file", None),
        ("/workspace/file\x00suffix", None),
    ],
)
def test_safe_path(path: str, expected: str | None) -> None:
    assert _safe_path(path) == expected


def test_exec_status_extracts_exit_code() -> None:
    status = {
        "status": "Failure",
        "details": {"causes": [{"reason": "ExitCode", "message": "127"}]},
    }
    assert _status_exit_code(json.dumps(status).encode()) == 127
    assert _status_exit_code(b'{"status":"Success"}') == 0
    assert _status_exit_code(b"unparseable") == 1


def test_pod_security_and_secret_isolation() -> None:
    sandbox = K3Sandbox.__new__(K3Sandbox)
    sandbox._id = "openswe-0123456789abcdef01234567"
    sandbox.image = "sandbox:test"
    sandbox.namespace = "open-swe-sandboxes"
    sandbox.storage = "10Gi"
    sandbox.cpu_request = "250m"
    sandbox.cpu_limit = "2"
    sandbox.memory_request = "512Mi"
    sandbox.memory_limit = "4Gi"
    sandbox.proxy_url = "http://github-credential-proxy.open-swe-system.svc:8080"

    pod = sandbox._pod_body()
    assert pod.spec is not None
    container = pod.spec.containers[0]
    assert container.env is not None
    assert container.security_context is not None
    assert container.security_context.capabilities is not None
    assert container.security_context.seccomp_profile is not None
    env = {item.name: item.value for item in container.env}

    assert pod.spec.automount_service_account_token is False
    assert pod.spec.host_network is None
    assert container.security_context.allow_privilege_escalation is False
    assert container.security_context.capabilities.drop == ["ALL"]
    assert container.security_context.seccomp_profile.type == "RuntimeDefault"
    assert "GITHUB_TOKEN" not in env
    assert env["GH_TOKEN"] == "dummy"
    assert env["HTTPS_PROXY"] == sandbox.proxy_url
    assert "@" not in env["HTTPS_PROXY"]
    assert all("secret" not in (value or "").lower() for value in env.values())


def test_configure_proxy_binds_token_to_pod_ip(monkeypatch) -> None:  # noqa: ANN001
    sandbox = K3Sandbox.__new__(K3Sandbox)
    sandbox._pod = lambda: client.V1Pod(status=client.V1PodStatus(pod_ip="10.42.0.9"))  # type: ignore[method-assign]
    monkeypatch.setenv("K3_GITHUB_PROXY_ADMIN_TOKEN", "admin-secret")
    response = type("Response", (), {"raise_for_status": lambda self: None})()
    with patch("agent.integrations.k3.httpx.put", return_value=response) as request:
        sandbox.configure_github_proxy("github-secret", ["owner/repo"])

    args, kwargs = request.call_args
    assert args[0].endswith("/credentials/10.42.0.9")
    assert "github-secret" not in args[0]
    assert "github-secret" not in json.dumps(kwargs["json"])
    assert kwargs["json"]["encrypted_token"]
    assert kwargs["headers"]["Authorization"] == "Bearer admin-secret"
