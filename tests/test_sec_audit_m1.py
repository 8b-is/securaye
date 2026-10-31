import json
import pathlib
import tempfile
import unittest

from sec_audit.agent00_state_db import SecAuditStateDB, validate_finding_envelope
from sec_audit.agent01_mirror_diff import compare_tarball_vs_git
from sec_audit.ultrafoldpop_orchestrator import (
    CorpusRuleIndexer,
    run_ultrafoldpop_package_pipeline,
)


class TestSecAuditMilestone1(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest_path = (
            pathlib.Path(__file__).resolve().parents[1] / "sec_audit" / "target_manifest.json"
        )
        self.rules_path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "sec_audit"
            / "semgrep_nodejs_php_rules.yaml"
        )

    def test_manifest_has_40_packages_and_semgrep_rules_exist(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        pkgs = manifest["packages"]
        self.assertEqual(len(pkgs), 40)
        npm_pkgs = [p for p in pkgs if p["ecosystem"] == "npm"]
        php_pkgs = [p for p in pkgs if p["ecosystem"] == "packagist"]
        self.assertEqual(len(npm_pkgs), 20)
        self.assertEqual(len(php_pkgs), 20)
        self.assertTrue(self.rules_path.is_file())
        rules_text = self.rules_path.read_text(encoding="utf-8")
        self.assertIn("sec-audit.nodejs.prototype-pollution-to-exec-or-vm", rules_text)
        self.assertIn("sec-audit.php.pop-chain-magic-to-sink", rules_text)

    def test_agent00_state_db_and_agent01_tarball_diff_detects_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            db_path = tmp_path / "sec_audit_state.sqlite3"
            db = SecAuditStateDB(db_path)
            init_res = db.initialize_schema_and_manifest(self.manifest_path)
            self.assertEqual(init_res["total_packages"], 40)
            self.assertEqual(init_res["ecosystem_counts"], {"npm": 20, "packagist": 20})

            git_dir = tmp_path / "git_ws"
            tar_dir = tmp_path / "tar_ws"
            git_dir.mkdir()
            tar_dir.mkdir()

            # Upstream Git tag has clean package.json and index.js
            (git_dir / "package.json").write_text(
                json.dumps({"name": "ws", "version": "8.18.0", "scripts": {"test": "mocha"}}),
                encoding="utf-8",
            )
            (git_dir / "index.js").write_text(
                "// upstream comment\nmodule.exports = function connect() { return true; };\n",
                encoding="utf-8",
            )

            # Published tarball has unauthorized postinstall hook, injected file, and .node addon
            (tar_dir / "package.json").write_text(
                json.dumps(
                    {
                        "name": "ws",
                        "version": "8.18.0",
                        "scripts": {
                            "test": "mocha",
                            "postinstall": "node ./scripts/telemetry_canary.js",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (tar_dir / "index.js").write_text(
                "module.exports = function connect() { return true; };\n",
                encoding="utf-8",
            )
            (tar_dir / "bufferutil.node").write_bytes(b"\x7fELF\x02\x01\x01\x00bufferutil")

            envelope = compare_tarball_vs_git(
                package_id="npm:ws",
                ecosystem="npm",
                package_name="ws",
                version="8.18.0",
                tarball_dir=tar_dir,
                git_dir=git_dir,
            )
            validated = validate_finding_envelope(envelope)
            self.assertEqual(validated["status"], "CANDIDATE")
            self.assertEqual(len(validated["native_binaries"]), 1)
            self.assertEqual(
                validated["native_binaries"][0]["relative_path"], "bufferutil.node"
            )
            rule_ids = {f["rule_id"] for f in validated["findings"]}
            self.assertIn("sec-audit.supply-chain.unauthorized-lifecycle-hook", rule_ids)
            self.assertIn("sec-audit.supply-chain.tarball-only-artifact", rule_ids)

            recorded = db.record_envelope(validated)
            self.assertIn("envelope_sha256", recorded)
            summary = db.summary()
            self.assertEqual(summary["recorded_envelopes"], 1)
            self.assertEqual(summary["native_artifacts"], 1)
            self.assertEqual(summary["status_breakdown"].get("CANDIDATE"), 1)

    def test_ultrafoldpop_e2e_bilingual_jpcert_advisory_and_pass3_pruning(self) -> None:
        indexer = CorpusRuleIndexer()
        cinfo = indexer.index_corpora()
        self.assertGreater(cinfo["indexed_repositories"], 0)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            db = SecAuditStateDB(tmp_path / "sec_audit.sqlite3")
            db.initialize_schema_and_manifest(self.manifest_path)

            git_dir = tmp_path / "git_php"
            tar_dir = tmp_path / "tar_php"
            git_dir.mkdir()
            tar_dir.mkdir()

            vuln_php = (
                "<?php\n"
                "class Gadget {\n"
                "  public function __wakeup() {\n"
                "    $data = unserialize($this->payload);\n"
                "    proc_open($this->cmd, [], $pipes);\n"
                "  }\n"
                "}\n"
            )
            sanitized_php = (
                "<?php\n"
                "class SafeGadget {\n"
                "  public function __wakeup() {\n"
                "    $data = unserialize($this->payload, ['allowed_classes' => false]);\n"
                "    proc_open(escapeshellarg($this->cmd), [], $pipes);\n"
                "  }\n"
                "}\n"
            )
            (git_dir / "Gadget.php").write_text(vuln_php, encoding="utf-8")
            (tar_dir / "Gadget.php").write_text(vuln_php, encoding="utf-8")
            (git_dir / "SafeGadget.php").write_text(sanitized_php, encoding="utf-8")
            (tar_dir / "SafeGadget.php").write_text(sanitized_php, encoding="utf-8")

            res = run_ultrafoldpop_package_pipeline(
                db=db,
                package_id="packagist:monolog/monolog",
                ecosystem="packagist",
                package_name="monolog/monolog",
                version="3.8.0",
                tarball_dir=tar_dir,
                git_dir=git_dir,
            )
            self.assertEqual(res["active_folded_chains"], 1)
            self.assertEqual(res["pruned_folded_chains"], 1)
            self.assertEqual(res["envelope"]["status"], "STATICALLY_CONFIRMED")
            self.assertEqual(len(res["jpcert_ipa_advisories"]), 1)
            adv = res["jpcert_ipa_advisories"][0]
            self.assertEqual(adv["cwe_id"], "CWE-502")
            self.assertIn("早期警戒セキュリティ勧告", adv["bilingual_bulletin_markdown"])
            self.assertIn("--network=none", res["podman_canary_cmd"])


if __name__ == "__main__":
    unittest.main()
