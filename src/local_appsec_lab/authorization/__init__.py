from __future__ import annotations

import getpass
import hashlib
import time
from pathlib import Path
from typing import Literal

from pydantic import Field

from local_appsec_lab.configuration import Config
from local_appsec_lab.errors import AuthorizationError
from local_appsec_lab.models import Mode, Model, digest
from local_appsec_lab.utilities.files import files, read_text


def fingerprint(root: Path) -> str:
    parts = []
    for path in files(root):
        parts.append((path, hashlib.sha256(read_text(root, path).encode()).hexdigest()))
    return digest([str(root.resolve()), parts])


class Approval(Model):
    version: Literal[1] = 1
    repository: str
    repository_fingerprint: str
    plan_digest: str
    user: str
    acknowledgment: Literal["I authorize local execution and bounded testing"]
    mode: Mode
    service_identities: list[str]
    addresses: list[str] = Field(default_factory=lambda: ["127.0.0.1"])
    ports: list[int]
    categories: list[str]
    limits: dict
    expires_at: float
    run_id: str
    existing_manifest_digest: str | None = None

    def validate_scope(self, root: Path, config: Config, mode: Mode, run_id: str) -> None:
        if time.time() >= self.expires_at:
            raise AuthorizationError("Authorization expired; authorize a new run")
        if self.repository != str(root.resolve()) or self.repository_fingerprint != fingerprint(
            root
        ):
            raise AuthorizationError("Repository changed since authorization")
        if (
            self.plan_digest != digest(config.model_dump())
            or self.run_id != run_id
            or self.mode != mode
        ):
            raise AuthorizationError("Approval does not match this plan, mode, or run")
        if config.execution.port not in self.ports:
            raise AuthorizationError("Port is outside the approval")


def authorize(
    root: Path,
    workspace: Path,
    config: Config,
    mode: Mode,
    run_id: str,
    acknowledged: bool,
    existing_digest: str | None = None,
) -> Approval | None:
    root, workspace = root.resolve(strict=True), workspace.resolve(strict=True)
    if not root.is_dir() or not root.is_relative_to(workspace):
        raise AuthorizationError("Repository is outside the CLI-authorized workspace")
    if mode == "review":
        return None
    if not acknowledged:
        raise AuthorizationError(
            "Local execution/testing requires --authorize; inspect 'plan' first"
        )
    if config.execution.existing_url and existing_digest != digest(
        {
            "url": config.execution.existing_url,
            "identity": config.execution.existing_identity,
            "repository": str(root),
        }
    ):
        raise AuthorizationError(
            "Existing service requires --existing-manifest-digest from the reviewed plan"
        )
    return Approval(
        repository=str(root),
        repository_fingerprint=fingerprint(root),
        plan_digest=digest(config.model_dump()),
        user=getpass.getuser(),
        acknowledgment="I authorize local execution and bounded testing",
        mode=mode,
        service_identities=[config.execution.service or "app"],
        ports=[config.execution.port],
        categories=config.categories
        or [
            "headers",
            "session",
            "cors",
            "authentication",
            "authorization",
            "validation",
            "business_logic",
            "tenant_isolation",
        ],
        limits=config.limits.model_dump(),
        expires_at=time.time() + config.limits.duration_seconds,
        run_id=run_id,
        existing_manifest_digest=existing_digest,
    )
