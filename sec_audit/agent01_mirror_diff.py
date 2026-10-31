#!/usr/bin/env python3
"""
Agent-01: Local Repository Indexing & Supply Chain Tarball-vs-Git Diffing (Stage-1 / M1).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from sec_audit.agent00_state_db import SecAuditStateDB, utc_now_iso, validate_finding_envelope

NPM_HOOK_KEYS = ("preinstall", "install", "postinstall", "prepublish", "prepare")
COMPOSER_HOOK_KEYS = (
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "post-autoload-dump",
    "post-package-install",
)
IGNORED_GIT_ONLY_PREFIXES = (".git/", ".github/", ".gitlab/", "tests/", "test/", "docs/")


def normalize_source_bytes(path: pathlib.Path, raw: bytes) -> bytes:
    """Normalize comments/whitespace for deterministic AST-equivalent source comparison."""
    suffix = path.suffix.lower()
    if suffix not in (".js", ".cjs", ".mjs", ".ts", ".php", ".json"):
        return raw
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    # Strip block and single-line comments while preserving string literals heuristically
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue
        lines.append(re.sub(r"\s+", " ", stripped))
    return "\n".join(lines).encode("utf-8")


def hash_tree(root: pathlib.Path) -> Tuple[str, Dict[str, Dict[str, str]], List[Dict[str, Any]]]:
    """Compute both raw and normalized SHA-256 hashes for every file under root, plus native binaries."""
    root = pathlib.Path(root)
    files_map: Dict[str, Dict[str, str]] = {}
    native_binaries: List[Dict[str, Any]] = []
    overall = hashlib.sha256()

    if not root.exists():
        return overall.hexdigest(), files_map, native_binaries

    for file_path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = file_path.relative_to(root).as_posix()
        if rel.startswith(".git/"):
            continue
        raw = file_path.read_bytes()
        raw_sha = hashlib.sha256(raw).hexdigest()
        norm_sha = hashlib.sha256(normalize_source_bytes(file_path, raw)).hexdigest()
        files_map[rel] = {"raw_sha256": raw_sha, "norm_sha256": norm_sha}
        overall.update(f"{rel}:{norm_sha}\n".encode("utf-8"))

        suffix = file_path.suffix.lower()
        if suffix in (".node", ".so"):
            native_binaries.append(
                {
                    "relative_path": rel,
                    "artifact_type": "node_addon" if suffix == ".node" else "php_ext",
                    "sha256": raw_sha,
                    "ghidra_mcp_endpoint": "http://10.200.0.2:9403/mcp",
                    "ghidra_mcp_dispatched": False,
                }
            )

    return overall.hexdigest(), files_map, native_binaries


def extract_lifecycle_hooks(root: pathlib.Path, ecosystem: str) -> Dict[str, str]:
    """Extract lifecycle install/autoload hooks from package.json or composer.json."""
    hooks: Dict[str, str] = {}
    if ecosystem == "npm":
        pkg_json = root / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                scripts = data.get("scripts", {})
                if isinstance(scripts, dict):
                    for k in NPM_HOOK_KEYS:
                        if k in scripts and isinstance(scripts[k], str):
                            hooks[k] = scripts[k]
            except Exception:
                pass
    elif ecosystem == "packagist":
        comp_json = root / "composer.json"
        if comp_json.is_file():
            try:
                data = json.loads(comp_json.read_text(encoding="utf-8"))
                scripts = data.get("scripts", {})
                if isinstance(scripts, dict):
                    for k in COMPOSER_HOOK_KEYS:
                        if k in scripts:
                            val = scripts[k]
                            hooks[k] = json.dumps(val, sort_keys=True) if not isinstance(val, str) else val
            except Exception:
                pass
    return hooks


def compare_tarball_vs_git(
    package_id: str,
    ecosystem: str,
    package_name: str,
    version: str,
    tarball_dir: pathlib.Path,
    git_dir: pathlib.Path,
) -> Dict[str, Any]:
    """Run Stage-1 tarball-vs-Git comparison and emit a validated SubAgentFindingEnvelope."""
    tar_tree_sha, tar_files, tar_natives = hash_tree(tarball_dir)
    git_tree_sha, git_files, _ = hash_tree(git_dir)

    tar_only: List[str] = []
    norm_diverged: List[str] = []

    for rel, hashes in tar_files.items():
        if rel not in git_files:
            tar_only.append(rel)
        elif hashes["norm_sha256"] != git_files[rel]["norm_sha256"]:
            norm_diverged.append(rel)

    tar_hooks = extract_lifecycle_hooks(tarball_dir, ecosystem)
    git_hooks = extract_lifecycle_hooks(git_dir, ecosystem)
    unauthorized_hooks: Dict[str, Dict[str, Optional[str]]] = {}
    for hook_name, cmd in tar_hooks.items():
        if git_hooks.get(hook_name) != cmd:
            unauthorized_hooks[hook_name] = {
                "tarball_cmd": cmd,
                "git_cmd": git_hooks.get(hook_name),
            }

    findings: List[Dict[str, Any]] = []
    if unauthorized_hooks:
        findings.append(
            {
                "finding_id": f"{package_id}:{version}:unauthorized-lifecycle-hook",
                "rule_id": "sec-audit.supply-chain.unauthorized-lifecycle-hook",
                "cwe_id": "CWE-506",
                "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                "severity": "CRITICAL",
                "message": f"Tarball defines lifecycle hooks absent or modified from Git tag: {list(unauthorized_hooks.keys())}",
                "evidence": unauthorized_hooks,
            }
        )

    if tar_only:
        findings.append(
            {
                "finding_id": f"{package_id}:{version}:tarball-only-artifacts",
                "rule_id": "sec-audit.supply-chain.tarball-only-artifact",
                "cwe_id": "CWE-829",
                "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
                "severity": "HIGH",
                "message": f"Published registry tarball contains {len(tar_only)} file(s) absent from upstream Git tag.",
                "evidence": {"tarball_only_files": tar_only},
            }
        )

    if norm_diverged:
        findings.append(
            {
                "finding_id": f"{package_id}:{version}:ast-normalized-divergence",
                "rule_id": "sec-audit.supply-chain.ast-normalized-divergence",
                "cwe_id": "CWE-494",
                "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
                "severity": "HIGH",
                "message": f"{len(norm_diverged)} file(s) differ between published tarball and Git tag after AST/comment normalization.",
                "evidence": {"diverged_files": norm_diverged},
            }
        )

    status = "CANDIDATE" if findings else "INDEXED"
    envelope_seed = f"M1:Stage-1:Agent-01:{package_id}:{version}:{tar_tree_sha}:{git_tree_sha}"
    envelope_id = "env-" + hashlib.sha256(envelope_seed.encode("utf-8")).hexdigest()[:16]

    raw_envelope: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "envelope_id": envelope_id,
        "milestone": "M1",
        "stage": "Stage-1",
        "agent_id": "Agent-01",
        "package_id": package_id,
        "ecosystem": ecosystem,
        "package_name": package_name,
        "version": version,
        "status": status,
        "supply_chain_diff": {
            "tarball_tree_sha256": tar_tree_sha,
            "git_tree_sha256": git_tree_sha,
            "tarball_file_count": len(tar_files),
            "git_file_count": len(git_files),
            "tarball_only_files": tar_only,
            "ast_normalized_diverged_files": norm_diverged,
            "unauthorized_lifecycle_hooks": unauthorized_hooks,
        },
        "findings": findings,
        "native_binaries": tar_natives,
        "timestamp": utc_now_iso(),
    }
    return validate_finding_envelope(raw_envelope)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Agent-01 Tarball-vs-Git Supply Chain Diff")
    parser.add_argument("--db", default="/tmp/sec-audit/state/sec_audit_state.sqlite3")
    parser.add_argument("--package-id", required=True, help="e.g. npm:lodash")
    parser.add_argument("--ecosystem", required=True, choices=["npm", "packagist"])
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tarball-dir", required=True)
    parser.add_argument("--git-dir", required=True)
    args = parser.parse_args(argv)

    db = SecAuditStateDB(pathlib.Path(args.db))
    envelope = compare_tarball_vs_git(
        package_id=args.package_id,
        ecosystem=args.ecosystem,
        package_name=args.package_name,
        version=args.version,
        tarball_dir=pathlib.Path(args.tarball_dir),
        git_dir=pathlib.Path(args.git_dir),
    )
    recorded = db.record_envelope(envelope)
    print(json.dumps(recorded, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
