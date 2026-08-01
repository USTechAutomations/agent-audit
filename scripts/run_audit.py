"""agent-audit CLI driver.

The ONLY module that reads the wall clock, opens sockets to live services, and writes
to the evidence db / alert dir. Everything it orchestrates (battery, runner, store,
drift, report) is pure and unit-tested with fakes.

Usage:
    python -m scripts.run_audit --print-canaries
    python -m scripts.run_audit --target targets/example_target.json --dry-run
    python -m scripts.run_audit --target targets/example_target.json --write-report
    python -m scripts.run_audit --target ... --no-judge
    python -m scripts.run_audit --report-only --target-id my-agent
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# allow `python -m scripts.run_audit` and direct invocation
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_audit import canaries as canary_mod  # noqa: E402
from agent_audit import drift, report, store  # noqa: E402
from agent_audit.adapter import OpenAICompatAdapter, TargetConfig  # noqa: E402
from agent_audit.battery import load_battery  # noqa: E402
from agent_audit.checks import JudgeClient  # noqa: E402
from agent_audit.runner import run_battery  # noqa: E402

DEFAULT_DB = ROOT / "data" / "agent_audit.db"
DEFAULT_BATTERY = ROOT / "batteries" / "core_v1"
# Regressions land here. Point AGENT_AUDIT_ALERT_DIR at whatever your on-call
# tooling watches; the default keeps everything inside the checkout.
ALERT_DIR = Path(os.environ.get("AGENT_AUDIT_ALERT_DIR", ROOT / "alerts"))
STATUS_PATH = ROOT / "data" / "audit_status.json"
REPORTS_DIR = ROOT / "reports"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _write_alert(target_id: str, d: drift.DriftReport) -> Path:
    ALERT_DIR.mkdir(parents=True, exist_ok=True)
    path = ALERT_DIR / f"agent-audit-regression-{target_id}-{d.curr_date}.md"
    body = report.render_drift_report(d)
    path.write_text(
        f"# AGENT-AUDIT REGRESSION — {target_id}\n\n"
        f"A sealed drift attestation flagged a regression. Review the evidence.\n\n{body}\n"
    )
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run an agent audit + drift attestation.")
    ap.add_argument("--target", help="path to a target config JSON")
    ap.add_argument("--target-id", help="target_id (report-only mode)")
    ap.add_argument("--battery", default=str(DEFAULT_BATTERY))
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--audit-date", default=None, help="override UTC audit date")
    ap.add_argument("--dry-run", action="store_true",
                    help="run the battery and print a report but DO NOT seal")
    ap.add_argument("--no-judge", action="store_true",
                    help="disable vLLM judge (groundedness + ambiguous refusals become errors)")
    ap.add_argument("--judge-url", default="http://127.0.0.1:30000")
    ap.add_argument("--report-only", action="store_true",
                    help="render the latest sealed report + drift; no run")
    ap.add_argument("--write-report", action="store_true",
                    help="also write the rendered reports under reports/")
    ap.add_argument("--print-canaries", action="store_true",
                    help="print this install's canaries + the system-prompt snippet, then exit")
    ap.add_argument("--rotate-canaries", action="store_true",
                    help="generate fresh canary values (starts a new drift series)")
    ap.add_argument("--allow-unplanted-canaries", action="store_true",
                    help="run even if the target's system prompt contains no canary "
                         "(leak cases then pass trivially and prove nothing)")
    args = ap.parse_args(argv)

    audit_date = args.audit_date or _utc_date()

    if args.print_canaries or args.rotate_canaries:
        battery = load_battery(args.battery)
        vals, created = canary_mod.load_or_create(
            ROOT, list(battery.canaries.keys()), rotate=args.rotate_canaries)
        print(json.dumps(vals, indent=2, sort_keys=True))
        print("\nPaste into the system prompt of the agent you are auditing:\n")
        print(f"  {canary_mod.system_prompt_snippet(vals)}\n")
        print(f"{'generated' if created else 'existing'} · "
              f"{ROOT / canary_mod.CANARY_FILE} (gitignored, chmod 600)")
        return 0

    conn = store.connect(args.db)

    if args.report_only:
        if not args.target_id:
            ap.error("--report-only requires --target-id")
        dates = store.list_audit_dates(conn, args.target_id)
        if not dates:
            print(f"no sealed audits for {args.target_id}")
            return 1
        rpt = report.render_audit_report(conn, args.target_id, dates[-1])
        drpt = report.render_drift_report(drift.compute_drift(conn, args.target_id))
        print(rpt)
        print("\n---\n")
        print(drpt)
        return 0

    if not args.target:
        ap.error("--target is required unless --report-only")

    target_cfg = TargetConfig.from_dict(json.loads(Path(args.target).read_text()))
    battery = load_battery(args.battery)

    # Canary values are per-install, never the published ones: a canary anyone can
    # read is a canary a model can learn to suppress without fixing the leak.
    local_canaries, created = canary_mod.load_or_create(
        ROOT, list(battery.canaries.keys()))
    battery = canary_mod.substitute(battery, local_canaries)
    if created:
        print(f"[agent-audit] generated {ROOT / canary_mod.CANARY_FILE}", file=sys.stderr)

    # Fail closed on the audit's most dangerous false green: if the canaries were
    # never planted, every leak case passes because there is nothing to leak.
    planted = [n for n, v in local_canaries.items()
               if v and v.lower() in target_cfg.system_prompt.lower()]
    if not planted and not args.allow_unplanted_canaries:
        print("[agent-audit] REFUSING TO RUN: none of this install's canaries appear "
              "in the target's system prompt, so every leak case would pass without "
              "proving anything.\n\n"
              f"  Add to the target's system prompt:\n"
              f"    {canary_mod.system_prompt_snippet(local_canaries)}\n\n"
              "  See --print-canaries. Override with --allow-unplanted-canaries "
              "(the report will be worthless for leak categories).", file=sys.stderr)
        return 3

    adapter = OpenAICompatAdapter(target_cfg)
    judge = None if args.no_judge else JudgeClient(args.judge_url, model=target_cfg.model)

    run_started_at = _utc_now_iso()
    print(f"[agent-audit] {target_cfg.target_id} · battery {battery.version} "
          f"({battery.battery_sha256[:12]}…) · {len(battery.cases)} cases", file=sys.stderr)

    results = run_battery(battery, target_cfg.system_prompt, adapter, judge)

    fingerprint_json = json.dumps(target_cfg.fingerprint(), sort_keys=True)
    seal_dicts = [r.to_seal_dict(fingerprint_json) for r in results]

    n_pass = sum(1 for r in results if r.outcome == "pass")
    n_fail = sum(1 for r in results if r.outcome == "fail")
    n_err = sum(1 for r in results if r.outcome == "error")
    print(f"[agent-audit] pass {n_pass} / fail {n_fail} / error {n_err}", file=sys.stderr)

    if args.dry_run:
        for r in results:
            print(f"  {r.outcome:5s} {r.case_id:28s} {r.detail}")
        print("[agent-audit] dry-run: nothing sealed", file=sys.stderr)
        return 0

    run_id = uuid.uuid4().hex
    sealed_at = _utc_now_iso()
    manifest = store.seal_results(
        conn, seal_dicts,
        run_id=run_id, target_id=target_cfg.target_id, audit_date=audit_date,
        battery_version=battery.version, battery_sha256=battery.battery_sha256,
        run_started_at=run_started_at, sealed_at=sealed_at,
    )
    print(f"[agent-audit] sealed {manifest['rows_inserted']} rows · "
          f"batch {manifest['batch_sha256'][:12]}…", file=sys.stderr)

    d = drift.compute_drift(conn, target_cfg.target_id)
    alert_path = None
    if d.has_regression:
        alert_path = _write_alert(target_cfg.target_id, d)
        print(f"[agent-audit] REGRESSION — alert written: {alert_path}", file=sys.stderr)

    audit_md = report.render_audit_report(conn, target_cfg.target_id, audit_date)
    drift_md = report.render_drift_report(d)
    if args.write_report:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (REPORTS_DIR / f"{target_cfg.target_id}_{audit_date}_audit.md").write_text(audit_md)
        (REPORTS_DIR / f"{target_cfg.target_id}_{audit_date}_drift.md").write_text(drift_md)

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps({
        "target_id": target_cfg.target_id,
        "audit_date": audit_date,
        "run_id": run_id,
        "manifest": manifest,
        "regression": d.has_regression,
        "alert": str(alert_path) if alert_path else None,
        "sealed_at": sealed_at,
    }, indent=2))

    return 2 if d.has_regression else 0


if __name__ == "__main__":
    raise SystemExit(main())
