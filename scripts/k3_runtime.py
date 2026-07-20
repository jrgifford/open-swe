#!/usr/bin/env python3
"""Idempotent lifecycle manager for the development-only local k3d runtime."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / ".open-swe"
CONFIG_FILE = STATE_DIR / "k3.json"
ENV_FILE = ROOT / ".env"
CLUSTER = "open-swe"
CONTEXT = f"k3d-{CLUSTER}"
K3S_IMAGE = "rancher/k3s:v1.32.3-k3s1"
REQUIRED = ("OPENAI_API_KEY", "GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET")
GENERATED = ("DASHBOARD_JWT_SECRET", "TOKEN_ENCRYPTION_KEY", "K3_GITHUB_PROXY_ADMIN_TOKEN")


class Failure(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    input_data: bytes | None = None,
    capture: bool = False,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    shown = " ".join(command)
    print(f"+ {shown}")
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=input_data,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
        env=env,
    )
    if check and result.returncode:
        detail = (result.stderr or result.stdout or b"").decode(errors="replace").strip()
        raise Failure(f"Command failed ({result.returncode}): {shown}\n{detail[-2000:]}")
    return result


def output(command: list[str], *, check: bool = True) -> str:
    return run(command, capture=True, check=check).stdout.decode().strip()


def load_env() -> tuple[list[str], dict[str, str]]:
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    values: dict[str, str] = {}
    for line in lines:
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    for name in (*REQUIRED, *GENERATED):
        if os.getenv(name):
            values[name] = os.environ[name]
    return lines, values


def write_env(lines: list[str], values: dict[str, str], changed: set[str]) -> None:
    if not changed:
        return
    rendered: list[str] = []
    seen: set[str] = set()
    for line in lines:
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if match and match.group(1) in changed:
            name = match.group(1)
            rendered.append(f"{name}={values[name]}")
            seen.add(name)
        else:
            rendered.append(line)
    if rendered and rendered[-1]:
        rendered.append("")
    for name in (*REQUIRED, *GENERATED):
        if name in changed and name not in seen:
            rendered.append(f"{name}={values[name]}")
    content = "\n".join(rendered).rstrip() + "\n"
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".env.", dir=ENV_FILE.parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, ENV_FILE)
        ENV_FILE.chmod(0o600)
    finally:
        Path(temporary).unlink(missing_ok=True)


def github_guidance(port: int) -> None:
    print(
        "\nGitHub App setup (manual, localhost-only):\n"
        f"  Homepage URL: http://localhost:{port}\n"
        f"  OAuth callback: http://localhost:{port}/dashboard/api/auth/callback\n"
        "  Repository permissions: Contents read/write, Pull requests read/write, "
        "Issues read/write, Metadata read-only\n"
        "  Account permission: Email addresses read-only\n"
        "  Install the App on the repositories Open SWE may access.\n"
        "  Webhook URL and webhook secret are intentionally unused for this localhost runtime.\n"
    )


def ensure_credentials(port: int, skip_checks: bool) -> dict[str, str]:
    lines, values = load_env()
    persisted = {
        match.group(1)
        for line in lines
        if (match := re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line))
    }
    missing = [name for name in REQUIRED if not values.get(name)]
    if missing and not sys.stdin.isatty():
        raise Failure("Missing required variables (no cluster changes made): " + ", ".join(missing))
    if missing:
        github_guidance(port)
        for name in missing:
            values[name] = getpass.getpass(f"{name}: ").strip()
            if not values[name]:
                raise Failure(f"{name} cannot be empty")
    changed = set(missing) | {
        name for name in REQUIRED if name not in persisted and values.get(name)
    }
    if not values.get("DASHBOARD_JWT_SECRET"):
        values["DASHBOARD_JWT_SECRET"] = secrets.token_urlsafe(48)
        changed.add("DASHBOARD_JWT_SECRET")
    if not values.get("TOKEN_ENCRYPTION_KEY"):
        values["TOKEN_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        changed.add("TOKEN_ENCRYPTION_KEY")
    if not values.get("K3_GITHUB_PROXY_ADMIN_TOKEN"):
        values["K3_GITHUB_PROXY_ADMIN_TOKEN"] = secrets.token_urlsafe(48)
        changed.add("K3_GITHUB_PROXY_ADMIN_TOKEN")
    if not skip_checks:
        validate_credentials(values)
    write_env(lines, values, changed)
    return values


def validate_credentials(values: dict[str, str]) -> None:
    if not values["OPENAI_API_KEY"].startswith("sk-"):
        raise Failure("OPENAI_API_KEY does not have the expected shape")
    request = urllib.request.Request(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {values['OPENAI_API_KEY']}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise Failure("OpenAI credential validation failed")
    except urllib.error.HTTPError as exc:
        raise Failure(f"OpenAI credential validation failed (HTTP {exc.code})") from exc
    except urllib.error.URLError as exc:
        raise Failure(f"OpenAI credential validation could not reach OpenAI: {exc.reason}") from exc
    if len(values["GITHUB_APP_CLIENT_ID"]) < 8:
        raise Failure("GITHUB_APP_CLIENT_ID does not have the expected shape")
    if len(values["GITHUB_APP_CLIENT_SECRET"]) < 20:
        raise Failure("GITHUB_APP_CLIENT_SECRET does not have the expected shape")


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        value = json.loads(CONFIG_FILE.read_text())
    except json.JSONDecodeError as exc:
        raise Failure(f"Invalid {CONFIG_FILE}: {exc}") from exc
    if not isinstance(value, dict):
        raise Failure(f"Invalid {CONFIG_FILE}: expected an object")
    return value


def save_config(value: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(CONFIG_FILE)


def port_available(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def select_config() -> dict[str, Any]:
    current = load_config()
    if current:
        port = int(current["port"])
        if cluster_exists():
            return current
        if not port_available(port):
            raise Failure(f"Persisted port {port} is occupied. Free it or edit {CONFIG_FILE}.")
        return current
    port = 3000
    if not port_available(port):
        if not sys.stdin.isatty():
            raise Failure(
                "Port 3000 is occupied; run interactively once to choose an alternate port"
            )
        entered = input("Port 3000 is occupied. Alternate localhost port: ").strip()
        try:
            port = int(entered)
        except ValueError as exc:
            raise Failure("Port must be an integer") from exc
        if not 1 <= port <= 65535 or not port_available(port):
            raise Failure(f"Port {port} is unavailable")
    value = {"cluster": CLUSTER, "port": port, "k3sImage": K3S_IMAGE, "sandboxCapacity": 2}
    save_config(value)
    return value


def cluster_exists() -> bool:
    result = run(["k3d", "cluster", "get", CLUSTER], capture=True, check=False)
    return result.returncode == 0


def preflight() -> None:
    if platform.system() not in {"Linux", "Darwin"}:
        raise Failure("Only Linux and macOS are supported")
    if platform.machine().lower() not in {"x86_64", "amd64", "arm64", "aarch64"}:
        raise Failure(f"Unsupported architecture: {platform.machine()}")
    for tool in ("docker", "mise", "k3d", "kubectl", "helm"):
        if shutil.which(tool) is None:
            raise Failure(f"Required tool not found after mise install: {tool}")
    run(["docker", "info"], capture=True)
    free = shutil.disk_usage(ROOT).free
    if free < 8 * 1024**3:
        raise Failure("At least 8 GiB free disk space is required")


def hash_paths(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    excluded = {".git", ".venv", "node_modules", ".output", "__pycache__", ".open-swe"}
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.exists():
            files.extend(
                item
                for item in path.rglob("*")
                if item.is_file() and not excluded.intersection(item.parts)
            )
    for path in sorted(set(files)):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def build_images() -> dict[str, str]:
    definitions = {
        "control": (
            "deploy/k3/images/control-plane.Dockerfile",
            [
                ROOT / "agent",
                ROOT / "pyproject.toml",
                ROOT / "uv.lock",
                ROOT / "langgraph.json",
                ROOT / "deploy/k3/images/control-plane.Dockerfile",
            ],
        ),
        "ui": (
            "deploy/k3/images/ui.Dockerfile",
            [ROOT / "ui", ROOT / "deploy/k3/images/ui.Dockerfile"],
        ),
        "sandbox": ("Dockerfile", [ROOT / "Dockerfile"]),
        "proxy": (
            "deploy/k3/images/proxy.Dockerfile",
            [ROOT / "deploy/k3/proxy", ROOT / "deploy/k3/images/proxy.Dockerfile"],
        ),
    }
    images: dict[str, str] = {}
    for name, (dockerfile, inputs) in definitions.items():
        tag = f"open-swe-{name}:k3-{hash_paths(inputs)}"
        images[name] = tag
        exists = run(["docker", "image", "inspect", tag], capture=True, check=False).returncode == 0
        if exists:
            print(f"Reusing unchanged image {tag}")
        else:
            run(["docker", "build", "--pull", "-f", dockerfile, "-t", tag, "."])
    return images


def ensure_cluster(port: int) -> None:
    if cluster_exists():
        image = output(
            ["docker", "inspect", "k3d-open-swe-server-0", "--format", "{{.Config.Image}}"],
            check=False,
        )
        if image and image != K3S_IMAGE:
            raise Failure(
                f"Existing cluster uses {image}, expected {K3S_IMAGE}. Export data then run make destroy-k3."
            )
        run(["k3d", "cluster", "start", CLUSTER], check=False)
        run(["kubectl", "config", "use-context", CONTEXT])
        return
    env = os.environ.copy()
    env["K3_HOST_PORT"] = str(port)
    run(["k3d", "cluster", "create", "--config", "deploy/k3/k3d.yaml"], env=env)


def apply_secret(values: dict[str, str], public_url: str) -> None:
    runtime = dict(values)
    runtime["DASHBOARD_BASE_URL"] = public_url
    runtime["DASHBOARD_API_BASE_URL"] = public_url
    runtime["DASHBOARD_ALLOWED_ORIGINS"] = public_url
    runtime["LANGSMITH_TRACING"] = "false"
    data = {key: base64.b64encode(value.encode()).decode() for key, value in runtime.items()}
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "open-swe-env", "namespace": "open-swe-system"},
        "type": "Opaque",
        "data": data,
    }
    for namespace in ("open-swe-system", "open-swe-sandboxes"):
        namespace_manifest = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {
                    "app.kubernetes.io/part-of": "open-swe",
                    "app.kubernetes.io/managed-by": "Helm",
                },
                "annotations": {
                    "meta.helm.sh/release-name": "open-swe",
                    "meta.helm.sh/release-namespace": "open-swe-system",
                },
            },
        }
        run(
            ["kubectl", "apply", "-f", "-"],
            input_data=json.dumps(namespace_manifest).encode(),
        )
    run(["kubectl", "apply", "-f", "-"], input_data=json.dumps(manifest).encode())


def install_release(
    images: dict[str, str], settings: dict[str, Any], values: dict[str, str]
) -> None:
    public_url = f"http://localhost:{settings['port']}"
    apply_secret(values, public_url)
    run(["k3d", "image", "import", "-c", CLUSTER, *images.values()])
    run(
        [
            "helm",
            "upgrade",
            "--install",
            "open-swe",
            "deploy/k3/chart",
            "--namespace",
            "open-swe-system",
            "--atomic",
            "--wait",
            "--timeout",
            "10m",
            "--set-string",
            f"images.controlPlane={images['control']}",
            "--set-string",
            f"images.ui={images['ui']}",
            "--set-string",
            f"images.sandbox={images['sandbox']}",
            "--set-string",
            f"images.proxy={images['proxy']}",
            "--set-string",
            f"config.publicUrl={public_url}",
            "--set",
            f"config.sandboxCapacity={settings['sandboxCapacity']}",
        ]
    )
    sync_proxy_ca()


def sync_proxy_ca() -> None:
    pod = output(
        [
            "kubectl",
            "get",
            "pod",
            "-n",
            "open-swe-system",
            "-l",
            "app=github-credential-proxy",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ]
    )
    cert = run(
        [
            "kubectl",
            "exec",
            "-n",
            "open-swe-system",
            pod,
            "--",
            "cat",
            "/root/.mitmproxy/mitmproxy-ca-cert.pem",
        ],
        capture=True,
    ).stdout
    manifest = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "github-proxy-ca", "namespace": "open-swe-sandboxes"},
        "data": {"ca.crt": cert.decode()},
    }
    run(["kubectl", "apply", "-f", "-"], input_data=json.dumps(manifest).encode())


def http_get(url: str, timeout: int = 10) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                raise Failure(f"GET {url} returned {response.status}")
            return response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise Failure(f"GET {url} failed: {exc}") from exc


def wait_http(url: str, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            http_get(url, timeout=5)
            return
        except Failure:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def http_json(url: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        raise Failure(f"{method} {url} failed: {exc}") from exc


def smoke(settings: dict[str, Any], values: dict[str, str]) -> None:
    base = f"http://localhost:{settings['port']}"
    ui = http_get(base + "/")
    if b"<title>open-swe</title>" not in ui or b"/assets/" not in ui:
        raise Failure("UI did not return the expected production shell")
    if b"ok" not in http_get(base + "/ok").lower():
        raise Failure("LangGraph /ok did not report healthy")
    info = http_json(base + "/info")
    if not info.get("version"):
        raise Failure("LangGraph metadata endpoint did not report a version")
    assistants = http_json(base + "/assistants/search", method="POST", payload={})
    graph_ids = {item.get("graph_id") for item in assistants}
    expected_graphs = {"agent", "reviewer", "analyzer", "chat", "scheduler"}
    if not expected_graphs.issubset(graph_ids):
        raise Failure(
            f"LangGraph metadata is missing graphs: {sorted(expected_graphs - graph_ids)}"
        )

    thread = http_json(
        base + "/threads",
        method="POST",
        payload={"metadata": {"k3_smoke": secrets.token_hex(8)}},
    )
    thread_id = thread.get("thread_id")
    if not thread_id or http_json(base + f"/threads/{thread_id}").get("thread_id") != thread_id:
        raise Failure("LangGraph thread state could not be written and read")

    control = output(
        [
            "kubectl",
            "get",
            "pod",
            "-n",
            "open-swe-system",
            "-l",
            "app=open-swe-control-plane",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ]
    )
    sentinel = f"k3-smoke-{secrets.token_hex(8)}"
    run(
        [
            "kubectl",
            "exec",
            "-n",
            "open-swe-system",
            control,
            "--",
            "sh",
            "-lc",
            f"printf %s {sentinel} > .langgraph_api/.k3-smoke",
        ]
    )
    run(["kubectl", "rollout", "restart", "deployment/control-plane", "-n", "open-swe-system"])
    run(
        [
            "kubectl",
            "rollout",
            "status",
            "deployment/control-plane",
            "-n",
            "open-swe-system",
            "--timeout=5m",
        ]
    )
    control = output(
        [
            "kubectl",
            "get",
            "pod",
            "-n",
            "open-swe-system",
            "-l",
            "app=open-swe-control-plane",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ]
    )
    persisted = output(
        [
            "kubectl",
            "exec",
            "-n",
            "open-swe-system",
            control,
            "--",
            "cat",
            "/app/.langgraph_api/.k3-smoke",
        ]
    )
    if persisted != sentinel:
        raise Failure("Graph-state PVC did not persist across control-plane restart")
    wait_http(base + "/ok")
    if http_json(base + f"/threads/{thread_id}").get("thread_id") != thread_id:
        raise Failure("LangGraph thread state did not persist across control-plane restart")

    proxy_test = (
        "import os,httpx; r=httpx.get('http://github-credential-proxy:8081/self-test',"
        "headers={'Authorization':'Bearer '+os.environ['K3_GITHUB_PROXY_ADMIN_TOKEN']});"
        "r.raise_for_status(); print(r.json()['status'])"
    )
    if (
        output(
            ["kubectl", "exec", "-n", "open-swe-system", control, "--", "python", "-c", proxy_test]
        )
        != "ok"
    ):
        raise Failure("Credential proxy isolation self-test failed")

    cleanup_job = f"sandbox-cleanup-smoke-{secrets.token_hex(4)}"
    run(
        [
            "kubectl",
            "create",
            "job",
            "-n",
            "open-swe-system",
            "--from=cronjob/sandbox-cleanup",
            cleanup_job,
        ]
    )
    try:
        run(
            [
                "kubectl",
                "wait",
                "-n",
                "open-swe-system",
                "--for=condition=complete",
                f"job/{cleanup_job}",
                "--timeout=2m",
            ]
        )
    finally:
        run(
            ["kubectl", "delete", "job", "-n", "open-swe-system", cleanup_job, "--wait=true"],
            check=False,
        )

    run(
        [
            "kubectl",
            "delete",
            "pod,pvc",
            "-n",
            "open-swe-sandboxes",
            "-l",
            "open-swe.dev/smoke=true",
            "--ignore-not-found",
            "--wait=true",
        ]
    )
    sandbox_test = r"""
import concurrent.futures, json, os, time
from deepagents.backends.protocol import ExecuteResponse, FileDownloadResponse, FileUploadResponse
from kubernetes import client, config
from agent.integrations.k3 import K3Sandbox
config.load_incluster_config(); api=client.CoreV1Api()
def mark(item):
 api.patch_namespaced_pod(item.id,item.namespace,{'metadata':{'labels':{'open-swe.dev/smoke':'true'}}})
 api.patch_namespaced_persistent_volume_claim(item._pvc_name,item.namespace,{'metadata':{'labels':{'open-swe.dev/smoke':'true'}}})
os.environ['K3_SANDBOX_QUEUE_TIMEOUT_SECONDS']='2'
first = K3Sandbox(); mark(first)
upload = first.upload_files([('/workspace/empty', b''),('/workspace/data.bin', bytes(range(256))*4096)])
assert all(isinstance(item, FileUploadResponse) and item.error is None for item in upload)
channels = first._exec_channels("printf stdout; printf stderr >&2; exit 7")
assert channels.stdout == b'stdout' and channels.stderr == b'stderr' and channels.exit_code == 7
assert first.execute("true").exit_code == 0
assert first.execute("command-that-does-not-exist").exit_code == 127
assert first.execute("bash -c 'kill -TERM $$'").exit_code == 143
assert first.execute("bash -c 'exec -a k3-timeout-probe sleep 30'", timeout=1).exit_code == 124
assert first.execute("pgrep -f '[k]3-timeout-probe'").exit_code != 0
empty, data = first.download_files(['/workspace/empty','/workspace/data.bin'])
assert isinstance(empty, FileDownloadResponse) and empty.content == b''
assert data.content == bytes(range(256))*4096
assert first.download_files(['/workspace/../etc/passwd'])[0].error == 'invalid_path'
first.execute("mkdir -p /workspace/tree && printf x >/workspace/tree/item && chmod 600 /workspace/tree/item")
assert first.download_files(['/workspace/tree'])[0].error == 'is_directory'
assert first.execute("test $(stat -c %a /workspace/tree/item) = 600").exit_code == 0
second = K3Sandbox(); mark(second)
started=time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
 results=list(pool.map(lambda item: item.execute("sleep 1; echo ok"), [first,first,second]))
assert all(isinstance(item, ExecuteResponse) and item.exit_code == 0 for item in results)
assert time.monotonic()-started < 4
first.execute("nohup python3 -m http.server 8787 --bind 0.0.0.0 >/tmp/k3-http.log 2>&1 &")
first_ip=api.read_namespaced_pod(first.id,first.namespace).status.pod_ip
assert second.execute(f"curl -fsS --connect-timeout 3 http://{first_ip}:8787").exit_code != 0
assert first.execute("getent hosts github-credential-proxy.open-swe-system.svc >/dev/null").exit_code == 0
assert first.execute("curl -fsS --connect-timeout 3 http://control-plane.open-swe-system.svc:2024/ok").exit_code != 0
assert first.execute("curl -fsS --max-time 15 https://example.com >/dev/null").exit_code == 0
bounded=False
try: K3Sandbox()
except TimeoutError: bounded=True
assert bounded
sid=first.id
api.delete_namespaced_pod(sid, first.namespace, grace_period_seconds=0)
import time
for _ in range(60):
 try: api.read_namespaced_pod(sid, first.namespace)
 except client.ApiException as exc:
  if exc.status == 404: break
 time.sleep(1)
reconnected=K3Sandbox(sid)
assert reconnected.download_files(['/workspace/data.bin'])[0].content == bytes(range(256))*4096
api.delete_namespaced_pod(second.id,second.namespace,grace_period_seconds=0)
api.delete_namespaced_persistent_volume_claim(second._pvc_name,second.namespace)
print(json.dumps({'status':'ok','sandbox':sid}))
"""
    result = output(
        ["kubectl", "exec", "-n", "open-swe-system", control, "--", "python", "-c", sandbox_test]
    )
    if '"status": "ok"' not in result:
        raise Failure("Sandbox lifecycle smoke failed")
    sandbox_id = json.loads(result)["sandbox"]
    run(["kubectl", "rollout", "restart", "deployment/control-plane", "-n", "open-swe-system"])
    run(
        [
            "kubectl",
            "rollout",
            "status",
            "deployment/control-plane",
            "-n",
            "open-swe-system",
            "--timeout=5m",
        ]
    )
    control = output(
        [
            "kubectl",
            "get",
            "pod",
            "-n",
            "open-swe-system",
            "-l",
            "app=open-swe-control-plane",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ]
    )
    reconnect_test = f"""
from kubernetes import client, config
from agent.integrations.k3 import K3Sandbox
item=K3Sandbox({sandbox_id!r})
assert item.download_files(['/workspace/data.bin'])[0].content == bytes(range(256))*4096
config.load_incluster_config(); api=client.CoreV1Api()
api.delete_namespaced_pod(item.id,item.namespace,grace_period_seconds=0)
api.delete_namespaced_persistent_volume_claim(item._pvc_name,item.namespace)
print('ok')
"""
    if (
        output(
            [
                "kubectl",
                "exec",
                "-n",
                "open-swe-system",
                control,
                "--",
                "python",
                "-c",
                reconnect_test,
            ]
        )
        != "ok"
    ):
        raise Failure("Sandbox did not reconnect after control-plane restart")

    logs = ""
    for deployment in ("control-plane", "github-credential-proxy", "ui"):
        logs += output(["kubectl", "logs", "-n", "open-swe-system", f"deployment/{deployment}"])
    logs += output(
        ["kubectl", "get", "events", "-A", "-o", "json"],
        check=False,
    )
    leaked = [name for name in (*REQUIRED, *GENERATED) if values.get(name) and values[name] in logs]
    if leaked:
        raise Failure("Configured secrets appeared in logs: " + ", ".join(leaked))
    print(
        "Smoke gates passed: UI/API, graph-state restart, sandbox transport/PVC/capacity/network, proxy isolation, log redaction"
    )


def start(args: argparse.Namespace) -> None:
    preflight()
    settings = select_config()
    values = ensure_credentials(int(settings["port"]), args.skip_credential_checks)
    images = build_images()
    ensure_cluster(int(settings["port"]))
    install_release(images, settings, values)
    smoke(settings, values)
    url = f"http://localhost:{settings['port']}"
    print(f"\nOpen SWE is ready: {url}")
    print("Next: sign in with GitHub and install/authorize the configured GitHub App.")
    print("Lifecycle: make status-k3 | make logs-k3 | make stop-k3 | make destroy-k3")


def status(_args: argparse.Namespace) -> None:
    settings = load_config()
    print(f"cluster: {CLUSTER}")
    run(["k3d", "cluster", "list"], check=False)
    run(["helm", "status", "open-swe", "-n", "open-swe-system"], check=False)
    run(
        ["kubectl", "get", "pods,pvc,ingress", "-A", "-l", "app.kubernetes.io/part-of=open-swe"],
        check=False,
    )
    run(["kubectl", "get", "pods,pvc", "-n", "open-swe-sandboxes"], check=False)
    if settings.get("port"):
        print(f"url: http://localhost:{settings['port']}")


def logs(_args: argparse.Namespace) -> None:
    run(
        ["kubectl", "logs", "-n", "open-swe-system", "deployment/control-plane", "--tail=200"],
        check=False,
    )
    run(["kubectl", "logs", "-n", "open-swe-system", "deployment/ui", "--tail=100"], check=False)
    run(
        [
            "kubectl",
            "logs",
            "-n",
            "open-swe-system",
            "deployment/github-credential-proxy",
            "--tail=100",
        ],
        check=False,
    )
    run(
        ["kubectl", "get", "events", "-n", "open-swe-sandboxes", "--sort-by=.lastTimestamp"],
        check=False,
    )


def stop(_args: argparse.Namespace) -> None:
    run(["k3d", "cluster", "stop", CLUSTER])
    print(
        "Cluster stopped; Docker volumes, PVCs, credentials, and local configuration were retained."
    )


def destroy(args: argparse.Namespace) -> None:
    if not args.yes:
        if not sys.stdin.isatty():
            raise Failure("Destruction requires a TTY confirmation or --yes")
        answer = input("Delete the k3d cluster and all in-cluster state/PVCs? Type 'destroy': ")
        if answer != "destroy":
            raise Failure("Destruction cancelled")
    run(["k3d", "cluster", "delete", CLUSTER], check=False)
    print(f"Cluster deleted. {ENV_FILE} and {CONFIG_FILE} were retained.")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    start_parser = sub.add_parser("start")
    start_parser.add_argument("--skip-credential-checks", action="store_true")
    start_parser.set_defaults(handler=start)
    for name, handler in (("status", status), ("logs", logs), ("stop", stop)):
        item = sub.add_parser(name)
        item.set_defaults(handler=handler)
    destroy_parser = sub.add_parser("destroy")
    destroy_parser.add_argument("--yes", action="store_true")
    destroy_parser.set_defaults(handler=destroy)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        args.handler(args)
    except Failure as exc:
        print(f"error: {exc}", file=sys.stderr)
        if args.command == "start" and cluster_exists():
            print("diagnostics: make status-k3; make logs-k3", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
