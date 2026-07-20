"""Garbage collection entrypoint for k3 sandbox compute and storage."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException


def _age_seconds(value: str | None) -> float:
    if not value:
        return 0
    return (datetime.now(UTC) - datetime.fromisoformat(value)).total_seconds()


def main() -> None:
    config.load_incluster_config()
    api = client.CoreV1Api()
    namespace = os.getenv("K3_SANDBOX_NAMESPACE", "open-swe-sandboxes")
    idle = int(os.getenv("K3_SANDBOX_IDLE_SECONDS", "3600"))
    retention = int(os.getenv("K3_SANDBOX_RETENTION_SECONDS", "2592000"))
    pods = api.list_namespaced_pod(
        namespace, label_selector="app.kubernetes.io/component=sandbox"
    ).items
    for pod in pods:
        annotations = pod.metadata.annotations or {}
        age = _age_seconds(annotations.get("open-swe.dev/last-used"))
        if annotations.get("open-swe.dev/operation-lease", "0") != "0" and age < idle:
            continue
        if age >= idle:
            try:
                api.delete_namespaced_pod(
                    pod.metadata.name,
                    namespace,
                    body=client.V1DeleteOptions(
                        grace_period_seconds=10,
                        preconditions=client.V1Preconditions(
                            uid=pod.metadata.uid,
                            resource_version=pod.metadata.resource_version,
                        ),
                    ),
                )
            except ApiException as exc:
                if exc.status not in {404, 409}:
                    raise
    claims = api.list_namespaced_persistent_volume_claim(
        namespace, label_selector="app.kubernetes.io/component=sandbox-data"
    ).items
    active_ids = {
        pod.metadata.labels.get("open-swe.dev/sandbox-id")
        for pod in api.list_namespaced_pod(namespace).items
        if pod.metadata.deletion_timestamp is None
    }
    for claim in claims:
        annotations = claim.metadata.annotations or {}
        sandbox_id = (claim.metadata.labels or {}).get("open-swe.dev/sandbox-id")
        if (
            sandbox_id not in active_ids
            and _age_seconds(annotations.get("open-swe.dev/last-used")) >= retention
        ):
            try:
                api.delete_namespaced_persistent_volume_claim(
                    claim.metadata.name,
                    namespace,
                    body=client.V1DeleteOptions(
                        preconditions=client.V1Preconditions(
                            uid=claim.metadata.uid,
                            resource_version=claim.metadata.resource_version,
                        )
                    ),
                )
            except ApiException as exc:
                if exc.status not in {404, 409}:
                    raise


if __name__ == "__main__":
    main()
