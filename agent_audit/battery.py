"""Battery loading + validation.

The battery is *data, not code*: a manifest plus a set of case files under a battery
directory. The battery_sha256 is computed over the canonical JSON of the manifest and
every case, and is stamped into every sealed result — a report is meaningless without
the exact battery that produced it.

Fail-closed: an unknown checker type, a missing required field, or a duplicate case id
aborts the load. We never silently skip a malformed case.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The set of checker types a case may declare. Adding a checker means adding code in
# checks.py AND this allowlist — keeping the two in lockstep is the point.
KNOWN_CHECKS = frozenset(
    {
        "canary_leak",
        "must_not_contain",
        "must_contain",
        "field_trace",
        "groundedness",
        "refusal",
        "consistency",
    }
)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    check: str
    user_prompt: str
    params: dict[str, Any] = field(default_factory=dict)
    source_text: str = ""
    repeat: int = 1

    def messages(self, system_prompt: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": self.user_prompt},
        ]


@dataclass(frozen=True)
class Battery:
    version: str
    canaries: dict[str, str]
    categories: list[str]
    cases: list[Case]
    battery_sha256: str

    def by_id(self, case_id: str) -> Case | None:
        for c in self.cases:
            if c.case_id == case_id:
                return c
        return None


def _validate_case(raw: dict[str, Any], path: Path) -> Case:
    for key in ("case_id", "category", "check", "user_prompt"):
        if key not in raw or raw[key] in (None, ""):
            raise ValueError(f"{path.name}: case missing required field '{key}': {raw}")
    check = raw["check"]
    if check not in KNOWN_CHECKS:
        raise ValueError(
            f"{path.name}: unknown checker '{check}' for case '{raw['case_id']}'. "
            f"Known: {sorted(KNOWN_CHECKS)}"
        )
    repeat = int(raw.get("repeat", 1))
    if repeat < 1:
        raise ValueError(f"{path.name}: case '{raw['case_id']}' repeat must be >= 1")
    # checker-specific required params, validated at load time (fail-closed)
    params = raw.get("params", {})
    if check in ("must_not_contain", "must_contain") and not params.get("patterns"):
        raise ValueError(
            f"{path.name}: case '{raw['case_id']}' ({check}) needs params.patterns"
        )
    if check in ("field_trace", "groundedness") and not raw.get("source_text"):
        raise ValueError(
            f"{path.name}: case '{raw['case_id']}' ({check}) needs source_text"
        )
    return Case(
        case_id=str(raw["case_id"]),
        category=str(raw["category"]),
        check=str(check),
        user_prompt=str(raw["user_prompt"]),
        params=dict(params),
        source_text=str(raw.get("source_text", "")),
        repeat=repeat,
    )


def load_battery(battery_dir: str | Path) -> Battery:
    battery_dir = Path(battery_dir)
    manifest_path = battery_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"battery manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text())

    version = manifest.get("version")
    if not version:
        raise ValueError("manifest.json missing 'version'")
    canaries = dict(manifest.get("canaries", {}))
    categories = list(manifest.get("categories", []))

    # collect case files deterministically (sorted) for a stable battery hash
    case_files = sorted(
        p for p in battery_dir.glob("*.json") if p.name != "manifest.json"
    )
    cases: list[Case] = []
    seen: set[str] = set()
    hash_payload: list[Any] = [{"manifest": manifest}]
    for path in case_files:
        doc = json.loads(path.read_text())
        raw_cases = doc if isinstance(doc, list) else doc.get("cases", [])
        for raw in raw_cases:
            case = _validate_case(raw, path)
            if case.case_id in seen:
                raise ValueError(f"duplicate case_id across battery: {case.case_id}")
            seen.add(case.case_id)
            cases.append(case)
            hash_payload.append(raw)

    if not cases:
        raise ValueError(f"battery {battery_dir} has no cases")

    battery_sha256 = _sha256_hex(canonical_json(hash_payload))
    return Battery(
        version=str(version),
        canaries=canaries,
        categories=categories,
        cases=cases,
        battery_sha256=battery_sha256,
    )
