"""Kubernetes-backed persistent sandboxes for the local k3d runtime."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import posixpath
import re
import secrets
import shlex
import tarfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import httpx
from cryptography.fernet import Fernet
from deepagents.backends.protocol import ExecuteResponse, FileDownloadResponse, FileUploadResponse
from deepagents.backends.sandbox import BaseSandbox
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.stream import stream
from kubernetes.stream.ws_client import ERROR_CHANNEL, STDERR_CHANNEL, STDOUT_CHANNEL
from langsmith.sandbox import SandboxClientError

_NAME_RE = re.compile(r"^openswe-[a-z0-9]{24}$")
_PROVISION_LOCK = threading.Lock()


@dataclass(frozen=True)
class ExecChannels:
    stdout: bytes
    stderr: bytes
    exit_code: int


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_path(path: str) -> str | None:
    if not path.startswith("/") or "\x00" in path:
        return None
    normalized = posixpath.normpath(path)
    if normalized != path.rstrip("/") or any(part == ".." for part in path.split("/")):
        return None
    return normalized


def _status_exit_code(raw: bytes) -> int:
    if not raw:
        return 0
    try:
        status = json.loads(raw.decode())
        if status.get("status") == "Success":
            return 0
        for cause in status.get("details", {}).get("causes", []):
            if cause.get("reason") == "ExitCode":
                return int(cause["message"])
    except (UnicodeDecodeError, ValueError, TypeError, KeyError):
        pass
    return 1


class K3Sandbox(BaseSandbox):
    """One hardened Pod and persistent PVC in the sandbox namespace."""

    def __init__(self, sandbox_id: str | None = None) -> None:
        self.namespace = os.getenv("K3_SANDBOX_NAMESPACE", "open-swe-sandboxes")
        self.image = os.environ["K3_SANDBOX_IMAGE"]
        self.capacity = int(os.getenv("K3_SANDBOX_CAPACITY", "2"))
        self.queue_timeout = int(os.getenv("K3_SANDBOX_QUEUE_TIMEOUT_SECONDS", "120"))
        self.ready_timeout = int(os.getenv("K3_SANDBOX_READY_TIMEOUT_SECONDS", "180"))
        self.storage = os.getenv("K3_SANDBOX_STORAGE", "10Gi")
        self.cpu_request = os.getenv("K3_SANDBOX_CPU_REQUEST", "250m")
        self.cpu_limit = os.getenv("K3_SANDBOX_CPU_LIMIT", "2")
        self.memory_request = os.getenv("K3_SANDBOX_MEMORY_REQUEST", "512Mi")
        self.memory_limit = os.getenv("K3_SANDBOX_MEMORY_LIMIT", "4Gi")
        self.proxy_url = os.getenv(
            "K3_GITHUB_PROXY_URL", "http://github-credential-proxy.open-swe-system.svc:8080"
        )
        self._operation_lock = threading.Lock()
        self._active_operations = 0
        self._api = self._make_api()
        if sandbox_id is not None and not _NAME_RE.fullmatch(sandbox_id):
            raise ValueError("Invalid k3 sandbox id")
        self._id = sandbox_id or f"openswe-{secrets.token_hex(12)}"
        self._ensure_workspace()

    @staticmethod
    def validate_startup_config() -> None:
        required = ["K3_SANDBOX_IMAGE"]
        missing = [name for name in required if not os.getenv(name)]
        if missing:
            raise ValueError(f"Missing k3 sandbox configuration: {', '.join(missing)}")
        for name in (
            "K3_SANDBOX_CAPACITY",
            "K3_SANDBOX_QUEUE_TIMEOUT_SECONDS",
            "K3_SANDBOX_READY_TIMEOUT_SECONDS",
        ):
            try:
                value = int(os.environ.get(name, "2" if name.endswith("CAPACITY") else "120"))
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if value <= 0:
                raise ValueError(f"{name} must be > 0")

    @staticmethod
    def _make_api() -> client.CoreV1Api:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config(context=os.getenv("K3_KUBE_CONTEXT") or None)
        return client.CoreV1Api()

    @property
    def id(self) -> str:
        return self._id

    @property
    def _pvc_name(self) -> str:
        return f"{self._id}-data"

    def _pod(self) -> client.V1Pod | None:
        try:
            return cast(client.V1Pod, self._api.read_namespaced_pod(self._id, self.namespace))
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def _pvc_exists(self) -> bool:
        try:
            self._api.read_namespaced_persistent_volume_claim(self._pvc_name, self.namespace)
            return True
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise

    def _wait_for_capacity(self) -> None:
        deadline = time.monotonic() + self.queue_timeout
        while True:
            pods = self._api.list_namespaced_pod(
                self.namespace, label_selector="app.kubernetes.io/component=sandbox"
            ).items
            active = sum(p.metadata.deletion_timestamp is None for p in pods)
            if active < self.capacity:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Sandbox capacity {self.capacity} reached; queue timed out after "
                    f"{self.queue_timeout}s"
                )
            time.sleep(2)

    def _create_pvc(self) -> None:
        if self._pvc_exists():
            return
        body = client.V1PersistentVolumeClaim(
            metadata=client.V1ObjectMeta(
                name=self._pvc_name,
                labels={
                    "app.kubernetes.io/managed-by": "open-swe",
                    "app.kubernetes.io/component": "sandbox-data",
                    "open-swe.dev/sandbox-id": self._id,
                },
                annotations={"open-swe.dev/last-used": _now()},
            ),
            spec=client.V1PersistentVolumeClaimSpec(
                access_modes=["ReadWriteOnce"],
                resources=client.V1ResourceRequirements(requests={"storage": self.storage}),
            ),
        )
        try:
            self._api.create_namespaced_persistent_volume_claim(self.namespace, body)
        except ApiException as exc:
            if exc.status != 409:
                raise

    def _pod_body(self) -> client.V1Pod:
        labels = {
            "app.kubernetes.io/managed-by": "open-swe",
            "app.kubernetes.io/component": "sandbox",
            "open-swe.dev/sandbox-id": self._id,
        }
        annotations = {"open-swe.dev/last-used": _now(), "open-swe.dev/operation-lease": "0"}
        security = client.V1SecurityContext(
            allow_privilege_escalation=False,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            run_as_user=0,
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )
        volume_mounts = [
            client.V1VolumeMount(name="data", mount_path="/workspace", sub_path="workspace"),
            client.V1VolumeMount(name="data", mount_path="/root", sub_path="root"),
            client.V1VolumeMount(
                name="proxy-ca",
                mount_path="/usr/local/share/ca-certificates/open-swe-proxy.crt",
                sub_path="ca.crt",
                read_only=True,
            ),
        ]
        container = client.V1Container(
            name="sandbox",
            image=self.image,
            image_pull_policy="IfNotPresent",
            command=["/bin/sh", "-lc"],
            args=["update-ca-certificates >/dev/null 2>&1; exec sleep infinity"],
            env=[
                client.V1EnvVar(name="HTTP_PROXY", value=self.proxy_url),
                client.V1EnvVar(name="HTTPS_PROXY", value=self.proxy_url),
                client.V1EnvVar(name="http_proxy", value=self.proxy_url),
                client.V1EnvVar(name="https_proxy", value=self.proxy_url),
                client.V1EnvVar(name="GH_TOKEN", value="dummy"),
                client.V1EnvVar(name="NO_PROXY", value=".cluster.local,127.0.0.1,localhost"),
            ],
            resources=client.V1ResourceRequirements(
                requests={"cpu": self.cpu_request, "memory": self.memory_request},
                limits={"cpu": self.cpu_limit, "memory": self.memory_limit},
            ),
            security_context=security,
            volume_mounts=volume_mounts,
        )
        init = client.V1Container(
            name="initialize-data",
            image=self.image,
            command=["/bin/sh", "-lc"],
            args=["mkdir -p /persist/workspace /persist/root; cp -an /root/. /persist/root/"],
            security_context=security,
            volume_mounts=[client.V1VolumeMount(name="data", mount_path="/persist")],
        )
        return client.V1Pod(
            metadata=client.V1ObjectMeta(name=self._id, labels=labels, annotations=annotations),
            spec=client.V1PodSpec(
                automount_service_account_token=False,
                restart_policy="Never",
                enable_service_links=False,
                security_context=client.V1PodSecurityContext(
                    run_as_user=0,
                    run_as_group=0,
                    fs_group=0,
                    seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
                ),
                init_containers=[init],
                containers=[container],
                volumes=[
                    client.V1Volume(
                        name="data",
                        persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                            claim_name=self._pvc_name
                        ),
                    ),
                    client.V1Volume(
                        name="proxy-ca",
                        config_map=client.V1ConfigMapVolumeSource(name="github-proxy-ca"),
                    ),
                ],
            ),
        )

    def _ensure_workspace(self) -> None:
        with _PROVISION_LOCK:
            pod = self._pod()
            if pod is None:
                self._wait_for_capacity()
                self._create_pvc()
                try:
                    self._api.create_namespaced_pod(self.namespace, self._pod_body())
                except ApiException as exc:
                    if exc.status != 409:
                        raise
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            pod = self._pod()
            status = pod.status if pod else None
            if status and status.phase == "Running":
                container_statuses = status.container_statuses or []
                if container_statuses and all(item.ready for item in container_statuses):
                    return
            if status and status.phase in {"Failed", "Succeeded"}:
                raise SandboxClientError(f"Sandbox pod entered {status.phase}")
            time.sleep(1)
        raise TimeoutError(f"Sandbox pod {self._id} was not Ready after {self.ready_timeout}s")

    def _patch_annotations(self, **annotations: str) -> None:
        try:
            self._api.patch_namespaced_pod(
                self._id, self.namespace, {"metadata": {"annotations": annotations}}
            )
            self._api.patch_namespaced_persistent_volume_claim(
                self._pvc_name,
                self.namespace,
                {
                    "metadata": {
                        "annotations": {
                            "open-swe.dev/last-used": annotations["open-swe.dev/last-used"]
                        }
                    }
                },
            )
        except ApiException as exc:
            raise SandboxClientError(str(exc)) from exc

    def _heartbeat_lease(self, stopped: threading.Event) -> None:
        while not stopped.wait(30):
            with self._operation_lock:
                if self._active_operations == 0:
                    return
                try:
                    self._patch_annotations(
                        **{
                            "open-swe.dev/last-used": _now(),
                            "open-swe.dev/operation-lease": str(self._active_operations),
                        }
                    )
                except SandboxClientError:
                    return

    @contextmanager
    def _lease(self) -> Iterator[None]:
        with self._operation_lock:
            self._active_operations += 1
            self._patch_annotations(
                **{
                    "open-swe.dev/last-used": _now(),
                    "open-swe.dev/operation-lease": str(self._active_operations),
                }
            )
        stopped = threading.Event()
        heartbeat = threading.Thread(target=self._heartbeat_lease, args=(stopped,), daemon=True)
        heartbeat.start()
        try:
            yield
        finally:
            stopped.set()
            heartbeat.join(timeout=2)
            with self._operation_lock:
                self._active_operations -= 1
                self._patch_annotations(
                    **{
                        "open-swe.dev/last-used": _now(),
                        "open-swe.dev/operation-lease": str(self._active_operations),
                    }
                )

    def _exec_channels(
        self, command: str, *, timeout: int | None = None, stdin: bytes | None = None
    ) -> ExecChannels:
        remote_command = command
        if timeout is not None:
            remote_command = (
                f"timeout --signal=TERM --kill-after=5s {timeout}s "
                f"/bin/sh -lc {shlex.quote(command)}"
            )
        exec_api = client.CoreV1Api(
            client.ApiClient(configuration=self._api.api_client.configuration)
        )
        response = stream(
            exec_api.connect_get_namespaced_pod_exec,
            self._id,
            self.namespace,
            command=["/bin/sh", "-lc", remote_command],
            container="sandbox",
            stderr=True,
            stdin=stdin is not None,
            stdout=True,
            tty=False,
            _preload_content=False,
        )
        stdout = bytearray()
        stderr = bytearray()
        error = bytearray()
        deadline = time.monotonic() + timeout + 10 if timeout else None
        try:
            if stdin is not None:
                response.write_stdin(stdin)
            while response.is_open():
                if deadline and time.monotonic() >= deadline:
                    response.close()
                    raise TimeoutError(f"Command timed out after {timeout}s")
                response.update(timeout=1)
                for channel, target in (
                    (STDOUT_CHANNEL, stdout),
                    (STDERR_CHANNEL, stderr),
                    (ERROR_CHANNEL, error),
                ):
                    while response.peek_channel(channel):
                        value = response.read_channel(channel)
                        target.extend(value.encode() if isinstance(value, str) else value)
        except Exception:
            response.close()
            raise
        finally:
            response.close()
            exec_api.api_client.close()
        return ExecChannels(bytes(stdout), bytes(stderr), _status_exit_code(bytes(error)))

    def execute(self, command: str, *, timeout: int | None = None) -> ExecuteResponse:
        with self._lease():
            try:
                result = self._exec_channels(command, timeout=timeout)
            except (ApiException, OSError) as exc:
                raise SandboxClientError(str(exc)) from exc
        output = result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
        return ExecuteResponse(output=output, exit_code=result.exit_code)

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        responses: list[FileUploadResponse] = []
        valid: list[tuple[str, bytes]] = []
        for path, content in files:
            safe = _safe_path(path)
            if safe is None:
                responses.append(FileUploadResponse(path=path, error="invalid_path"))
            else:
                responses.append(FileUploadResponse(path=path))
                valid.append((safe, content))
        if not valid:
            return responses
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            directories: set[str] = set()
            for path, content in valid:
                relative = path.lstrip("/")
                parent = posixpath.dirname(relative)
                pending: list[str] = []
                while parent and parent not in directories:
                    pending.append(parent)
                    parent = posixpath.dirname(parent)
                for directory in reversed(pending):
                    info = tarfile.TarInfo(directory)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    tar.addfile(info)
                    directories.add(directory)
                info = tarfile.TarInfo(relative)
                info.size = len(content)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(content))
        payload = archive.getvalue()
        with self._lease():
            result = self._exec_channels(
                f"head -c {len(payload)} | tar -xpf - -C /",
                timeout=max(30, self.ready_timeout),
                stdin=payload,
            )
        if result.exit_code:
            error = result.stderr.decode(errors="replace") or "upload failed"
            return [
                FileUploadResponse(path=item.path, error=error) if item.error is None else item
                for item in responses
            ]
        return responses

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        responses: list[FileDownloadResponse] = []
        for path in paths:
            safe = _safe_path(path)
            if safe is None:
                responses.append(FileDownloadResponse(path=path, error="invalid_path"))
                continue
            quoted = shlex.quote(safe)
            with self._lease():
                kind = self._exec_channels(f"test -f {quoted}")
                if kind.exit_code:
                    exists = self._exec_channels(f"test -d {quoted}")
                    error = "is_directory" if exists.exit_code == 0 else "file_not_found"
                    responses.append(FileDownloadResponse(path=path, error=error))
                    continue
                result = self._exec_channels(f"tar -cpf - -P {quoted} | base64")
            if result.exit_code:
                responses.append(FileDownloadResponse(path=path, error="permission_denied"))
                continue
            try:
                raw = base64.b64decode(result.stdout, validate=False)
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
                    member = tar.next()
                    extracted = tar.extractfile(member) if member else None
                    content = extracted.read() if extracted else None
                responses.append(FileDownloadResponse(path=path, content=content))
            except (tarfile.TarError, ValueError):
                responses.append(FileDownloadResponse(path=path, error="download failed"))
        return responses

    def discard(self) -> None:
        pod = self._pod()
        pod_ip = pod.status.pod_ip if pod and pod.status else None
        admin_token = os.getenv("K3_GITHUB_PROXY_ADMIN_TOKEN")
        endpoint = os.getenv(
            "K3_GITHUB_PROXY_ADMIN_URL",
            "http://github-credential-proxy.open-swe-system.svc:8081",
        )
        if pod_ip and admin_token:
            try:
                httpx.delete(
                    f"{endpoint}/credentials/{pod_ip}",
                    headers={"Authorization": f"Bearer {admin_token}"},
                    timeout=5,
                )
            except httpx.HTTPError:
                pass
        errors: list[ApiException] = []
        for delete in (
            lambda: self._api.delete_namespaced_pod(
                self._id, self.namespace, grace_period_seconds=0
            ),
            lambda: self._api.delete_namespaced_persistent_volume_claim(
                self._pvc_name, self.namespace
            ),
        ):
            try:
                delete()
            except ApiException as exc:
                if exc.status != 404:
                    errors.append(exc)
        if errors:
            raise SandboxClientError("; ".join(str(error) for error in errors))

    def configure_github_proxy(self, token: str, repositories: list[str] | None = None) -> None:
        pod = self._pod()
        pod_ip = pod.status.pod_ip if pod and pod.status else None
        if not pod_ip:
            raise SandboxClientError("Sandbox Pod has no network identity")
        admin_token = os.environ["K3_GITHUB_PROXY_ADMIN_TOKEN"]
        endpoint = os.getenv(
            "K3_GITHUB_PROXY_ADMIN_URL",
            "http://github-credential-proxy.open-swe-system.svc:8081",
        )
        encryption_key = base64.urlsafe_b64encode(hashlib.sha256(admin_token.encode()).digest())
        encrypted_token = Fernet(encryption_key).encrypt(token.encode()).decode()
        response = httpx.put(
            f"{endpoint}/credentials/{pod_ip}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"encrypted_token": encrypted_token, "repositories": repositories or []},
            timeout=10,
        )
        response.raise_for_status()


def create_k3_sandbox(sandbox_id: str | None = None) -> K3Sandbox:
    return K3Sandbox(sandbox_id)
