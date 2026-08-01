"""Drift attestation — the product differentiator.

Compares the most recent sealed audit for a target against the previous one for the
SAME battery_sha256 (comparing across battery versions would be apples to oranges).
Classifies each case as regression (pass->fail), improvement (fail->pass), newly-erroring,
unchanged, or new/removed. Cites the sealed row hashes on both sides so the attestation
is itself verifiable.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from . import store


@dataclass
class DriftReport:
    target_id: str
    prev_date: str | None
    curr_date: str | None
    battery_sha256: str | None
    regressions: list[dict[str, Any]] = field(default_factory=list)
    improvements: list[dict[str, Any]] = field(default_factory=list)
    new_errors: list[dict[str, Any]] = field(default_factory=list)
    new_cases: list[dict[str, Any]] = field(default_factory=list)
    removed_cases: list[dict[str, Any]] = field(default_factory=list)
    unchanged_count: int = 0
    comparable: bool = False
    note: str = ""

    @property
    def has_regression(self) -> bool:
        return bool(self.regressions) or bool(self.new_errors)


def _index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {r["case_id"]: r for r in rows}


def compute_drift(conn: sqlite3.Connection, target_id: str) -> DriftReport:
    dates = store.list_audit_dates(conn, target_id)
    if len(dates) < 2:
        return DriftReport(
            target_id, None, dates[-1] if dates else None, None,
            comparable=False, note="need at least two sealed audit dates to attest drift",
        )
    curr_date, prev_date = dates[-1], dates[-2]
    curr = store.get_results(conn, target_id, curr_date)
    prev = store.get_results(conn, target_id, prev_date)

    curr_battery = {r["battery_sha256"] for r in curr}
    prev_battery = {r["battery_sha256"] for r in prev}
    shared = curr_battery & prev_battery
    if not shared:
        return DriftReport(
            target_id, prev_date, curr_date, None, comparable=False,
            note="battery changed between the two dates; drift is not comparable",
        )
    battery_sha = sorted(shared)[0]
    curr = [r for r in curr if r["battery_sha256"] == battery_sha]
    prev = [r for r in prev if r["battery_sha256"] == battery_sha]

    ci, pi = _index(curr), _index(prev)
    report = DriftReport(target_id, prev_date, curr_date, battery_sha, comparable=True)

    for case_id, c in ci.items():
        p = pi.get(case_id)
        if p is None:
            report.new_cases.append({"case_id": case_id, "outcome": c["outcome"]})
            continue
        pair = {
            "case_id": case_id,
            "category": c["category"],
            "prev_outcome": p["outcome"],
            "curr_outcome": c["outcome"],
            "prev_row_sha256": p["row_sha256"],
            "curr_row_sha256": c["row_sha256"],
        }
        if p["outcome"] == "pass" and c["outcome"] == "fail":
            report.regressions.append(pair)
        elif p["outcome"] == "fail" and c["outcome"] == "pass":
            report.improvements.append(pair)
        elif c["outcome"] == "error" and p["outcome"] != "error":
            report.new_errors.append(pair)
        else:
            report.unchanged_count += 1

    for case_id in pi:
        if case_id not in ci:
            report.removed_cases.append(
                {"case_id": case_id, "outcome": pi[case_id]["outcome"]}
            )
    return report
