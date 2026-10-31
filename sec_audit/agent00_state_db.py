#!/usr/bin/env python3
"""
Agent-00: Deterministic SQLite WAL State Database & SubAgentFindingEnvelope Validator
for the 6-Stage Node.js (npm) & PHP (Packagist) Supply-Chain & Taint Audit Pipeline.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import sqlite3
import sys
from typing import Any, Dict, List, Optional

VALID_MILESTONES = ("M1", "M2", "M3", "M4")
VALID_STAGES = ("Stage-1", "Stage-2", "Stage-3", "Stage-4", "Stage-5", "Stage-6")
VALID_AGENTS = ("Agent-00", "Agent-01", "Agent-02", "Agent-03", "Agent-04", "Agent-05", "Agent-06")
VALID_STATUSES = (
    "QUEUED",
    "INDEXED",
    "CANDIDATE",
    "STATICALLY_CONFIRMED",
    "FALSE_POSITIVE_PRUNED",
    "SANDBOX_REPRODUCED",
    "PATCH_GENERATED",
)

SQL_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS package_targets (
    package_id TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL CHECK (ecosystem IN ('npm', 'packagist')),
    package_name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    priority INTEGER NOT NULL,
    latest_version TEXT DEFAULT '',
    current_milestone TEXT NOT NULL DEFAULT 'M1',
    current_stage TEXT NOT NULL DEFAULT 'Stage-1',
    status TEXT NOT NULL DEFAULT 'QUEUED',
    tarball_sha256 TEXT DEFAULT '',
    git_tag_commit TEXT DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stage_transitions (
    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL REFERENCES package_targets(package_id),
    milestone TEXT NOT NULL,
    stage TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_envelopes (
    envelope_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES package_targets(package_id),
    version TEXT NOT NULL,
    milestone TEXT NOT NULL,
    stage TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    cvss_v4_vector TEXT NOT NULL,
    summary TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS native_artifacts (
    artifact_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES package_targets(package_id),
    relative_path TEXT NOT NULL,
    artifact_type TEXT NOT NULL CHECK (artifact_type IN ('node_addon', 'php_ext')),
    sha256 TEXT NOT NULL,
    ghidra_mcp_dispatched INTEGER NOT NULL DEFAULT 0,
    discovered_at TEXT NOT NULL
);
"""


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_finding_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Strictly validate a SubAgentFindingEnvelope payload between stages."""
    required_fields = (
        "schema_version",
        "envelope_id",
        "milestone",
        "stage",
        "agent_id",
        "package_id",
        "ecosystem",
        "package_name",
        "version",
        "status",
        "supply_chain_diff",
        "findings",
        "native_binaries",
        "timestamp",
    )
    missing = [field for field in required_fields if field not in envelope]
    if missing:
        raise ValueError(f"SubAgentFindingEnvelope missing required fields: {missing}")

    if envelope["milestone"] not in VALID_MILESTONES:
        raise ValueError(f"Invalid milestone: {envelope['milestone']}")
    if envelope["stage"] not in VALID_STAGES:
        raise ValueError(f"Invalid stage: {envelope['stage']}")
    if envelope["agent_id"] not in VALID_AGENTS:
        raise ValueError(f"Invalid agent_id: {envelope['agent_id']}")
    if envelope["status"] not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {envelope['status']}")
    if envelope["ecosystem"] not in ("npm", "packagist"):
        raise ValueError(f"Invalid ecosystem: {envelope['ecosystem']}")
    if not isinstance(envelope["findings"], list):
        raise ValueError("findings must be a list")
    if not isinstance(envelope["native_binaries"], list):
        raise ValueError("native_binaries must be a list")

    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope_With_hash = dict(envelope)
    envelope_With_hash["envelope_sha256"] = hashlib.sha256(canonical).hexdigest()
    return envelope_With_hash


class SecAuditStateDB:
    def __init__(self, db_path: pathlib.Path) -> None:
        self.db_path = pathlib.Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_schema_and_manifest(self, manifest_path: pathlib.Path) -> Dict[str, Any]:
        manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
        packages = manifest.get("packages", [])
        now = utc_now_iso()

        with self.connect() as conn:
            conn.executescript(SQL_SCHEMA)
            for pkg in packages:
                conn.execute(
                    """
                    INSERT INTO package_targets (
                        package_id, ecosystem, package_name, repo_url, priority,
                        current_milestone, current_stage, status, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'M1', 'Stage-1', 'QUEUED', ?)
                    ON CONFLICT(package_id) DO UPDATE SET
                        repo_url = excluded.repo_url,
                        priority = excluded.priority,
                        updated_at = excluded.updated_at
                    """,
                    (
                        pkg["id"],
                        pkg["ecosystem"],
                        pkg["name"],
                        pkg["repo_url"],
                        int(pkg["priority"]),
                        now,
                    ),
                )
            conn.commit()
            counts = {
                row["ecosystem"]: row["cnt"]
                for row in conn.execute(
                    "SELECT ecosystem, COUNT(*) AS cnt FROM package_targets GROUP BY ecosystem"
                ).fetchall()
            }

        return {
            "db_path": str(self.db_path),
            "schema_initialized": True,
            "total_packages": len(packages),
            "ecosystem_counts": counts,
            "timestamp": now,
        }

    def record_envelope(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        validated = validate_finding_envelope(envelope)
        envelope_sha256 = validated["envelope_sha256"]
        now = utc_now_iso()
        pkg_id = validated["package_id"]
        diff_info = validated.get("supply_chain_diff", {})

        with self.connect() as conn:
            row = conn.execute(
                "SELECT status FROM package_targets WHERE package_id = ?", (pkg_id,)
            ).fetchone()
            prev_status = row["status"] if row else "QUEUED"

            conn.execute(
                """
                UPDATE package_targets
                SET latest_version = ?,
                    current_milestone = ?,
                    current_stage = ?,
                    status = ?,
                    tarball_sha256 = ?,
                    git_tag_commit = ?,
                    updated_at = ?
                WHERE package_id = ?
                """,
                (
                    validated["version"],
                    validated["milestone"],
                    validated["stage"],
                    validated["status"],
                    diff_info.get("tarball_tree_sha256", ""),
                    diff_info.get("git_tree_sha256", ""),
                    now,
                    pkg_id,
                ),
            )

            conn.execute(
                """
                INSERT INTO stage_transitions (
                    package_id, milestone, stage, agent_id,
                    from_status, to_status, envelope_sha256, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pkg_id,
                    validated["milestone"],
                    validated["stage"],
                    validated["agent_id"],
                    prev_status,
                    validated["status"],
                    envelope_sha256,
                    now,
                ),
            )

            findings: List[Dict[str, Any]] = validated.get("findings", [])
            primary_cwe = findings[0].get("cwe_id", "CWE-NONE") if findings else "CWE-NONE"
            primary_cvss = (
                findings[0].get("cvss_v4_vector", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
                if findings
                else "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
            )
            summary = (
                findings[0].get("message", "Clean stage envelope")
                if findings
                else "Tarball-vs-Git supply chain tree comparison completed."
            )

            conn.execute(
                """
                INSERT OR REPLACE INTO finding_envelopes (
                    envelope_id, package_id, version, milestone, stage, agent_id,
                    status, cwe_id, cvss_v4_vector, summary, envelope_json,
                    envelope_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    validated["envelope_id"],
                    pkg_id,
                    validated["version"],
                    validated["milestone"],
                    validated["stage"],
                    validated["agent_id"],
                    validated["status"],
                    primary_cwe,
                    primary_cvss,
                    summary,
                    json.dumps(validated, sort_keys=True),
                    envelope_sha256,
                    now,
                ),
            )

            for nat in validated.get("native_binaries", []):
                artifact_id = f"{pkg_id}:{nat['relative_path']}"
                conn.execute(
                    """
                    INSERT OR REPLACE INTO native_artifacts (
                        artifact_id, package_id, relative_path, artifact_type,
                        sha256, ghidra_mcp_dispatched, discovered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact_id,
                        pkg_id,
                        nat["relative_path"],
                        nat["artifact_type"],
                        nat["sha256"],
                        1 if nat.get("ghidra_mcp_dispatched") else 0,
                        now,
                    ),
                )
            conn.commit()

        return validated

    def summary(self) -> Dict[str, Any]:
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM package_targets").fetchone()["c"]
            by_status = {
                r["status"]: r["c"]
                for r in conn.execute(
                    "SELECT status, COUNT(*) AS c FROM package_targets GROUP BY status"
                ).fetchall()
            }
            envelopes = conn.execute("SELECT COUNT(*) AS c FROM finding_envelopes").fetchone()["c"]
            natives = conn.execute("SELECT COUNT(*) AS c FROM native_artifacts").fetchone()["c"]
        return {
            "db_path": str(self.db_path),
            "total_packages": total,
            "status_breakdown": by_status,
            "recorded_envelopes": envelopes,
            "native_artifacts": natives,
        }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-00 SQLite WAL State DB Manager")
    parser.add_argument(
        "--db",
        default="/tmp/sec-audit/state/sec_audit_state.sqlite3",
        help="Path to SQLite state database",
    )
    parser.add_argument(
        "--manifest",
        default=str(pathlib.Path(__file__).with_name("target_manifest.json")),
        help="Path to target_manifest.json",
    )
    parser.add_argument("--init", action="store_true", help="Initialize schema and seed 40 targets")
    parser.add_argument("--status", action="store_true", help="Print state DB summary JSON")
    args = parser.parse_args(argv)

    db = SecAuditStateDB(pathlib.Path(args.db))
    if args.init:
        res = db.initialize_schema_and_manifest(pathlib.Path(args.manifest))
        print(json.dumps(res, indent=2))
    if args.status:
        print(json.dumps(db.summary(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
