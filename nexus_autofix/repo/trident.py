from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

KNOWN_ECOSYSTEMS = {"gradle", "maven", "npm", "yarn", "pnpm"}


@dataclass(frozen=True)
class TridentStrategy:
    ecosystem: str
    toolchain: dict[str, str]  # e.g. {"java": "17.0.1"} or {"node": "20.11.0"}


def _strip_version_suffix(uses: str) -> str:
    return uses.split("@", 1)[0]


def _normalise_ecosystem(uses: str) -> str:
    """Reduce a `strategy.uses` value to a KNOWN_ECOSYSTEMS key.

    Case-insensitive and whitespace-tolerant: "Gradle", "GRADLE" and " gradle " are the same
    build system as "gradle", and a repo owner writing it naturally should not have a run
    refuse to start. Also drops an `@version` suffix, so "gradle@v1" resolves too.
    """
    return _strip_version_suffix(str(uses).strip()).strip().lower()


def _extract_toolchain(block: dict) -> dict[str, str]:
    toolchain: dict[str, str] = {}
    for key, value in (block or {}).items():
        # Keys are lowercased for the same reason as strategy.uses: "Java-Version" is the
        # same declaration as "java-version".
        key = str(key).strip().lower()
        if key.endswith("-version"):
            name = key[: -len("-version")]
            toolchain[name] = str(value)
    return toolchain


def _parse_strategy_entry(entry: dict) -> TridentStrategy:
    uses = entry.get("uses")
    if not uses:
        raise ValueError(f"strategy entry missing 'uses': {entry}")
    ecosystem = _normalise_ecosystem(uses)
    if ecosystem not in KNOWN_ECOSYSTEMS:
        raise ValueError(
            f"unrecognized .trident/build.yaml strategy.uses value: {uses!r}. "
            f"Known values (matched case-insensitively): {sorted(KNOWN_ECOSYSTEMS)}"
        )
    toolchain = _extract_toolchain(entry.get("with") or {})
    # Tolerate *-version keys at the top level too — the doc flags this nesting as unconfirmed.
    top_level_version_keys = {k: v for k, v in entry.items() if k.endswith("-version")}
    for name, value in _extract_toolchain(top_level_version_keys).items():
        toolchain.setdefault(name, value)
    return TridentStrategy(ecosystem=ecosystem, toolchain=toolchain)


def parse_trident_build_yaml(path: Path) -> list[TridentStrategy]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    strategy = data.get("strategy")
    if strategy is None:
        raise ValueError(f"{path} has no top-level 'strategy' key")
    entries = strategy if isinstance(strategy, list) else [strategy]
    return [_parse_strategy_entry(entry) for entry in entries]
