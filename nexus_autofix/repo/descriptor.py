from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml


@dataclass
class SecurityFixDescriptor:
    nexus_app_id: str
    build: str | None = None
    test: str | None = None
    smoke: str | None = None
    gate: str = "pre-pr"
    auto_merge: str = "never"
    suppress: list[dict] = field(default_factory=list)


def read_descriptor(path: Path) -> SecurityFixDescriptor | None:
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return SecurityFixDescriptor(
        nexus_app_id=data["nexus_app_id"],
        build=data.get("build"),
        test=data.get("test"),
        smoke=data.get("smoke"),
        gate=data.get("gate", "pre-pr"),
        auto_merge=data.get("auto_merge", "never"),
        suppress=data.get("suppress", []),
    )


def write_descriptor(path: Path, descriptor: SecurityFixDescriptor) -> None:
    data: dict = {
        "nexus_app_id": descriptor.nexus_app_id,
        "gate": descriptor.gate,
        "auto_merge": descriptor.auto_merge,
    }
    if descriptor.build:
        data["build"] = descriptor.build
    if descriptor.test:
        data["test"] = descriptor.test
    if descriptor.smoke:
        data["smoke"] = descriptor.smoke
    if descriptor.suppress:
        data["suppress"] = descriptor.suppress
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def unexpired_suppressions(descriptor: SecurityFixDescriptor | None, today: date) -> set[str]:
    if not descriptor:
        return set()
    result = set()
    for entry in descriptor.suppress:
        expires = entry.get("expires")
        if expires is None or date.fromisoformat(str(expires)) >= today:
            result.add(entry["component"])
    return result
