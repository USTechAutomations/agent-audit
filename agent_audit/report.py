"""Render audit + drift reports from sealed rows.

Reports are built ONLY from sealed store rows (never from in-memory run state), so a
report can be regenerated from the evidence db alone and always matches what was sealed.
Scoring is counts + failing case ids with evidence pointers — no letter grades, no
aggregate trust score (v1 has no calibration data to justify one). Deterministic and
model-assisted results are reported in separate columns, never blended.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from typing import Any

from . import store
from .drift import DriftReport


def _category_breakdown(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    agg: dict[str, dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "error": 0, "det_pass": 0, "det_fail": 0}
    )
    for r in rows:
        cat = r["category"]
        agg[cat][r["outcome"]] += 1
        if r["deterministic"]:
            if r["outcome"] == "pass":
                agg[cat]["det_pass"] += 1
            elif r["outcome"] == "fail":
                agg[cat]["det_fail"] += 1
    return agg


def render_audit_report(
    conn: sqlite3.Connection, target_id: str, audit_date: str
) -> str:
    rows = store.get_results(conn, target_id, audit_date)
    if not rows:
        return f"# Audit report\n\nNo sealed results for {target_id} on {audit_date}.\n"

    run = conn.execute(
        "SELECT * FROM audit_runs WHERE target_id = ? AND audit_date = ? "
        "ORDER BY sealed_at DESC LIMIT 1",
        (target_id, audit_date),
    ).fetchone()
    run = dict(run) if run else {}

    total = len(rows)
    passed = sum(1 for r in rows if r["outcome"] == "pass")
    failed = sum(1 for r in rows if r["outcome"] == "fail")
    errored = sum(1 for r in rows if r["outcome"] == "error")
    battery_sha = rows[0]["battery_sha256"]
    battery_ver = rows[0]["battery_version"]

    lines: list[str] = []
    lines.append(f"# Agent Audit Report — {target_id}")
    lines.append("")
    lines.append(f"- **Audit date:** {audit_date}")
    lines.append(f"- **Battery:** `{battery_ver}` (`{battery_sha[:16]}…`)")
    lines.append(f"- **Cases:** {total} — pass {passed} / fail {failed} / error {errored}")
    if run:
        lines.append(f"- **Run id:** `{run.get('run_id')}`")
        lines.append(f"- **Batch seal (Merkle root):** `{run.get('batch_sha256')}`")
    lines.append("")
    lines.append(
        "_Methodology scope and limits: see METHODOLOGY.md. This audit covers a "
        "conversational agent surface (system prompt + model + sampling) behind an "
        "OpenAI-compatible endpoint. It is not a certification against any external "
        "standard._"
    )
    lines.append("")

    lines.append("## Results by category")
    lines.append("")
    lines.append("| Category | Pass | Fail | Error | Deterministic pass/fail |")
    lines.append("|---|---|---|---|---|")
    for cat, a in sorted(_category_breakdown(rows).items()):
        lines.append(
            f"| {cat} | {a['pass']} | {a['fail']} | {a['error']} | "
            f"{a['det_pass']}/{a['det_fail']} |"
        )
    lines.append("")

    failing = [r for r in rows if r["outcome"] in ("fail", "error")]
    if failing:
        lines.append("## Failing & errored cases")
        lines.append("")
        for r in sorted(failing, key=lambda x: x["case_id"]):
            method = "deterministic" if r["deterministic"] else "model-assisted"
            lines.append(
                f"- **{r['case_id']}** ({r['category']}, {r['check_type']}, {method}) "
                f"— `{r['outcome']}`: {r['detail']}"
            )
            if r.get("transcript_sha256"):
                lines.append(f"  - evidence blob: `{r['transcript_sha256'][:16]}…`")
            lines.append(f"  - sealed row: `{r['row_sha256'][:16]}…`")
        lines.append("")
    else:
        lines.append("## Failing & errored cases\n\nNone.\n")

    return "\n".join(lines)


def render_drift_report(d: DriftReport) -> str:
    lines: list[str] = []
    lines.append(f"# Drift Attestation — {d.target_id}")
    lines.append("")
    if not d.comparable:
        lines.append(f"_Not comparable: {d.note}_")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"- **Previous audit:** {d.prev_date}")
    lines.append(f"- **Current audit:** {d.curr_date}")
    lines.append(f"- **Battery:** `{(d.battery_sha256 or '')[:16]}…`")
    lines.append(
        f"- **Regressions:** {len(d.regressions)} · "
        f"**New errors:** {len(d.new_errors)} · "
        f"**Improvements:** {len(d.improvements)} · "
        f"**Unchanged:** {d.unchanged_count}"
    )
    lines.append("")
    verdict = "REGRESSION DETECTED" if d.has_regression else "NO REGRESSION"
    lines.append(f"**Verdict: {verdict}**")
    lines.append("")

    def _block(title: str, items: list[dict[str, Any]]) -> None:
        if not items:
            return
        lines.append(f"## {title}")
        lines.append("")
        for it in sorted(items, key=lambda x: x["case_id"]):
            prev = it.get("prev_outcome", "—")
            curr = it.get("curr_outcome", it.get("outcome", "—"))
            lines.append(
                f"- **{it['case_id']}**: {prev} → {curr}"
            )
            if "prev_row_sha256" in it:
                lines.append(
                    f"  - prev `{it['prev_row_sha256'][:16]}…` · "
                    f"curr `{it['curr_row_sha256'][:16]}…`"
                )
        lines.append("")

    _block("Regressions (pass → fail)", d.regressions)
    _block("New errors", d.new_errors)
    _block("Improvements (fail → pass)", d.improvements)
    _block("New cases", d.new_cases)
    _block("Removed cases", d.removed_cases)
    return "\n".join(lines)
