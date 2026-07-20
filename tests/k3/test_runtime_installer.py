from __future__ import annotations

import base64
import json
import stat
from pathlib import Path

import pytest

from scripts import k3_runtime


def test_env_merge_preserves_unknown_and_uses_0600(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    env_file = tmp_path / ".env"
    env_file.write_text("# preserved\nUNKNOWN=value\nOPENAI_API_KEY=old\n")
    monkeypatch.setattr(k3_runtime, "ENV_FILE", env_file)

    lines, values = k3_runtime.load_env()
    values["OPENAI_API_KEY"] = "new"
    values["DASHBOARD_JWT_SECRET"] = "generated"
    k3_runtime.write_env(lines, values, {"OPENAI_API_KEY", "DASHBOARD_JWT_SECRET"})

    content = env_file.read_text()
    assert "# preserved" in content
    assert "UNKNOWN=value" in content
    assert "OPENAI_API_KEY=new" in content
    assert "DASHBOARD_JWT_SECRET=generated" in content
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_non_tty_reports_all_missing_before_write(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    env_file = tmp_path / ".env"
    monkeypatch.setattr(k3_runtime, "ENV_FILE", env_file)
    monkeypatch.setattr(k3_runtime.sys.stdin, "isatty", lambda: False)
    for name in (*k3_runtime.REQUIRED, *k3_runtime.GENERATED):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(k3_runtime.Failure) as exc_info:
        k3_runtime.ensure_credentials(3000, skip_checks=True)

    message = str(exc_info.value)
    assert all(name in message for name in k3_runtime.REQUIRED)
    assert not env_file.exists()


def test_generated_encryption_key_is_fernet_compatible(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(k3_runtime, "ENV_FILE", tmp_path / ".env")
    for name in k3_runtime.GENERATED:
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "OPENAI_API_KEY": "sk-fixture",
        "GITHUB_APP_CLIENT_ID": "Iv1.fixture",
        "GITHUB_APP_CLIENT_SECRET": "fixture-secret-at-least-twenty",
    }.items():
        monkeypatch.setenv(name, value)

    values = k3_runtime.ensure_credentials(3000, skip_checks=True)

    assert len(base64.urlsafe_b64decode(values["TOKEN_ENCRYPTION_KEY"])) == 32
    assert values["DASHBOARD_JWT_SECRET"]
    assert values["K3_GITHUB_PROXY_ADMIN_TOKEN"]
    persisted = (tmp_path / ".env").read_text()
    assert "OPENAI_API_KEY=sk-fixture" in persisted
    assert "GITHUB_APP_CLIENT_ID=Iv1.fixture" in persisted
    assert "GITHUB_APP_CLIENT_SECRET=fixture-secret-at-least-twenty" in persisted


def test_secret_manifest_uses_stdin_not_command_arguments(monkeypatch) -> None:  # noqa: ANN001
    calls: list[tuple[list[str], bytes | None]] = []

    def fake_run(command, *, input_data=None, **_kwargs):  # noqa: ANN001, ANN202
        calls.append((command, input_data))

        class Result:
            returncode = 0
            stdout = b""
            stderr = b""

        return Result()

    monkeypatch.setattr(k3_runtime, "run", fake_run)
    values = {"OPENAI_API_KEY": "super-secret"}
    k3_runtime.apply_secret(values, "http://localhost:3000")

    apply_command, manifest_bytes = calls[-1]
    assert apply_command == ["kubectl", "apply", "-f", "-"]
    assert "super-secret" not in " ".join(apply_command)
    assert manifest_bytes is not None
    manifest = json.loads(manifest_bytes)
    assert base64.b64decode(manifest["data"]["OPENAI_API_KEY"]) == b"super-secret"


def test_source_hash_changes_with_input(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(k3_runtime, "ROOT", tmp_path)
    item = tmp_path / "input"
    item.write_text("one")
    first = k3_runtime.hash_paths([item])
    item.write_text("two")
    assert k3_runtime.hash_paths([item]) != first
