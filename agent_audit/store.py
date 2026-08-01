"""Tamper-evident, append-only audit evidence store.

Replicates the seal discipline of clocks/b2b_change/b2b_change/store.py:
  * append-only: INSERT OR IGNORE only. No UPDATE/DELETE/REPLACE anywhere.
  * row_sha256 over a canonical-JSON projection that EXCLUDES write-time fields
    (sealed_at) → replay-stable.
  * per-run batch_sha256 = sha256 over the sorted inserted row hashes (Merkle-style).
  * content-addressed zlib blobs (full transcripts), keyed by sha256, size-capped.
  * the module NEVER reads the wall clock; the driver supplies all timestamps.

PK (target_id, audit_date, case_id): the first sealed result for a target on a given
UTC day wins; re-running the day is a no-op. This makes a daily audit an honest,
immutable commitment — the same property the permits prediction-snapshot clock relies
on. There is no path here that edits a sealed result.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zlib
from pathlib import Path
from typing import Any

MAX_BLOB_BYTES = 256 * 1024  # cap on a stored transcript blob


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS blobs (
    content_sha256 TEXT PRIMARY KEY,
    content_gz     BLOB NOT NULL,
    byte_len       INTEGER NOT NULL,
    truncated      INTEGER NOT NULL DEFAULT 0,
    first_seen_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_results (
    target_id        TEXT NOT NULL,
    audit_date       TEXT NOT NULL,
    case_id          TEXT NOT NULL,
    category         TEXT NOT NULL,
    check_type       TEXT NOT NULL,
    outcome          TEXT NOT NULL,           -- pass | fail | error
    deterministic    INTEGER NOT NULL,
    detail           TEXT NOT NULL,
    battery_version  TEXT NOT NULL,
    battery_sha256   TEXT NOT NULL,
    target_fingerprint_json TEXT NOT NULL,
    evidence_json    TEXT NOT NULL,
    transcript_sha256 TEXT,                   -- FK into blobs
    row_sha256       TEXT NOT NULL,
    sealed_at        TEXT NOT NULL,           -- write-time, NOT hashed
    run_id           TEXT NOT NULL,
    PRIMARY KEY (target_id, audit_date, case_id)
);

CREATE TABLE IF NOT EXISTS audit_runs (
    run_id           TEXT PRIMARY KEY,
    target_id        TEXT NOT NULL,
    audit_date       TEXT NOT NULL,
    battery_version  TEXT NOT NULL,
    battery_sha256   TEXT NOT NULL,
    rows_inserted    INTEGER NOT NULL,
    pass_count       INTEGER NOT NULL,
    fail_count       INTEGER NOT NULL,
    error_count      INTEGER NOT NULL,
    batch_sha256     TEXT NOT NULL,
    run_started_at   TEXT NOT NULL,
    sealed_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_target_date
    ON audit_results (target_id, audit_date);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


# fields that participate in the row hash (write-time annotations excluded)
_HASHED_FIELDS = (
    "target_id", "audit_date", "case_id", "category", "check_type", "outcome",
    "deterministic", "detail", "battery_version", "battery_sha256",
    "target_fingerprint_json", "evidence_json", "transcript_sha256",
)


def build_row(result: dict[str, Any]) -> dict[str, Any]:
    """Project a result dict into a sealed row + its replay-stable row_sha256."""
    row = {k: result.get(k) for k in _HASHED_FIELDS}
    row["row_sha256"] = _sha256_hex(canonical_json(row))
    return row


def verify_row(row: dict[str, Any]) -> bool:
    projected = {k: row.get(k) for k in _HASHED_FIELDS}
    return _sha256_hex(canonical_json(projected)) == row.get("row_sha256")


def _store_blob(conn: sqlite3.Connection, text: str, *, first_seen_date: str) -> str:
    raw = text.encode("utf-8")
    truncated = 0
    if len(raw) > MAX_BLOB_BYTES:
        raw = raw[:MAX_BLOB_BYTES]
        truncated = 1
    sha = hashlib.sha256(raw).hexdigest()
    conn.execute(
        "INSERT OR IGNORE INTO blobs (content_sha256, content_gz, byte_len, truncated, "
        "first_seen_date) VALUES (?, ?, ?, ?, ?)",
        (sha, zlib.compress(raw), len(raw), truncated, first_seen_date),
    )
    return sha


def seal_results(
    conn: sqlite3.Connection,
    results: list[dict[str, Any]],
    *,
    run_id: str,
    target_id: str,
    audit_date: str,
    battery_version: str,
    battery_sha256: str,
    run_started_at: str,
    sealed_at: str,
) -> dict[str, Any]:
    """Append a day's audit results for a target. Idempotent per (target, date, case).

    Each result dict must carry: case_id, category, check_type, outcome
    (pass|fail|error), deterministic (bool), detail, target_fingerprint_json,
    evidence (dict), transcript (str, optional).
    Returns the run manifest dict.
    """
    inserted_hashes: list[str] = []
    pass_count = fail_count = error_count = 0

    for res in results:
        transcript = res.get("transcript", "")
        transcript_sha = (
            _store_blob(conn, transcript, first_seen_date=audit_date)
            if transcript
            else None
        )
        row_input = {
            "target_id": target_id,
            "audit_date": audit_date,
            "case_id": res["case_id"],
            "category": res["category"],
            "check_type": res["check_type"],
            "outcome": res["outcome"],
            "deterministic": 1 if res.get("deterministic") else 0,
            "detail": res.get("detail", ""),
            "battery_version": battery_version,
            "battery_sha256": battery_sha256,
            "target_fingerprint_json": res["target_fingerprint_json"],
            "evidence_json": canonical_json(res.get("evidence", {})),
            "transcript_sha256": transcript_sha,
        }
        row = build_row(row_input)

        cur = conn.execute(
            "INSERT OR IGNORE INTO audit_results ("
            "target_id, audit_date, case_id, category, check_type, outcome, "
            "deterministic, detail, battery_version, battery_sha256, "
            "target_fingerprint_json, evidence_json, transcript_sha256, row_sha256, "
            "sealed_at, run_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                row["target_id"], row["audit_date"], row["case_id"], row["category"],
                row["check_type"], row["outcome"], row["deterministic"], row["detail"],
                row["battery_version"], row["battery_sha256"],
                row["target_fingerprint_json"], row["evidence_json"],
                row["transcript_sha256"], row["row_sha256"], sealed_at, run_id,
            ),
        )
        if cur.rowcount == 1:
            inserted_hashes.append(row["row_sha256"])
            outcome = row["outcome"]
            if outcome == "pass":
                pass_count += 1
            elif outcome == "fail":
                fail_count += 1
            else:
                error_count += 1

    batch_sha256 = _sha256_hex(canonical_json(sorted(inserted_hashes)))
    manifest = {
        "run_id": run_id,
        "target_id": target_id,
        "audit_date": audit_date,
        "battery_version": battery_version,
        "battery_sha256": battery_sha256,
        "rows_inserted": len(inserted_hashes),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "error_count": error_count,
        "batch_sha256": batch_sha256,
        "run_started_at": run_started_at,
        "sealed_at": sealed_at,
    }
    conn.execute(
        "INSERT OR IGNORE INTO audit_runs (run_id, target_id, audit_date, "
        "battery_version, battery_sha256, rows_inserted, pass_count, fail_count, "
        "error_count, batch_sha256, run_started_at, sealed_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            run_id, target_id, audit_date, battery_version, battery_sha256,
            len(inserted_hashes), pass_count, fail_count, error_count,
            batch_sha256, run_started_at, sealed_at,
        ),
    )
    conn.commit()
    return manifest


def get_results(
    conn: sqlite3.Connection, target_id: str, audit_date: str
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM audit_results WHERE target_id = ? AND audit_date = ? "
        "ORDER BY case_id",
        (target_id, audit_date),
    ).fetchall()
    return [dict(r) for r in rows]


def list_audit_dates(conn: sqlite3.Connection, target_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT audit_date FROM audit_results WHERE target_id = ? "
        "ORDER BY audit_date",
        (target_id,),
    ).fetchall()
    return [r["audit_date"] for r in rows]


def spot_check(conn: sqlite3.Connection, limit: int = 200) -> dict[str, Any]:
    """Re-verify row hashes on a sample of sealed rows. Returns {checked, failures[]}."""
    rows = conn.execute(
        "SELECT * FROM audit_results ORDER BY RANDOM() LIMIT ?", (limit,)
    ).fetchall()
    failures = [dict(r) for r in rows if not verify_row(dict(r))]
    return {"checked": len(rows), "failures": failures}
