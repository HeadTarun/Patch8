from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess

from analysis_ir import AnalysisType, Fact, FactState, IRRecord, Language, SourceLocation
from analysis_pipeline import run_analysis, validate_analysis_mode
from ir_adapters import normalize_report
from taxonomy import get_weakness
from scanner import _cppcheck, _semgrep


def legacy_finding(root: Path, *, file: str = "main.c", line: int = 4, tool: str = "Clang Static Analyzer", cwe_id: str = "CWE-476") -> dict:
    source = root / file
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    return {
        "id": "finding-1", "file": file, "line": line, "rule_id": "core.NullDereference",
        "message": "Possible null pointer dereference", "source_tool": tool, "source_tools": [tool],
        "classification": "STATIC_ANALYSIS_FINDING", "cwe": get_weakness(cwe_id),
        "mapping_confidence": "direct", "analyzer_confidence": "not assessed", "severity": "warning",
        "risk_context": "not_assessed", "mapping_rationale": "Analyzer diagnostic.",
        "evidence": "Actual analyzer diagnostic with its source location.",
    }


def report(finding: dict) -> dict:
    return {
        "scan_status": "COMPLETED", "findings": [finding], "source_files": 1,
        "analyzer_status": {"Clang Static Analyzer": {"status": "completed", "error": None}},
        "analyzers": ["Clang Static Analyzer"], "summary": {"total": 1},
    }


class IRModelTests(unittest.TestCase):
    def test_unknown_facts_are_valid_and_known_facts_require_values(self):
        self.assertEqual(Fact[int]().state, FactState.UNKNOWN)
        with self.assertRaises(ValueError):
            Fact[int](state=FactState.KNOWN)

    def test_ir_source_locations_are_relative_and_one_based(self):
        self.assertEqual(SourceLocation(file_path="src/main.c", line=1).line, 1)
        with self.assertRaises(ValueError):
            SourceLocation(file_path="../main.c", line=1)
        with self.assertRaises(ValueError):
            SourceLocation(file_path=r"C:\\src\\main.c", line=1)
        with self.assertRaises(ValueError):
            SourceLocation(file_path=r"..\\main.c", line=1)
        with self.assertRaises(ValueError):
            SourceLocation(file_path="main.c", line=0)
        with self.assertRaises(ValueError):
            SourceLocation(file_path="main.c", line=1, column=Fact[int](state=FactState.KNOWN, value=0))

    def test_adapter_preserves_evidence_and_marks_header_language_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            finding = legacy_finding(root, file="include/api.h")
            ir = normalize_report(report(finding), root, "unified")
            record = ir.records[0]
            self.assertEqual(record.language, Language.UNKNOWN)
            self.assertEqual(record.source.line, 4)
            self.assertEqual(record.evidence.raw_evidence, finding["evidence"])
            self.assertEqual(record.operation.type, "REFERENCE_ACCESS")
            self.assertEqual(record.properties.nullability, "POSSIBLY_NULL")
            self.assertEqual(record.evidence.analysis_type, AnalysisType.PATH_SENSITIVE)
            self.assertEqual(record.properties.buffer_capacity.state, FactState.UNKNOWN)

    def test_semgrep_candidate_remains_pattern_based_and_uncertain(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            finding = legacy_finding(root, tool="Semgrep", cwe_id="CWE-121")
            finding.update(classification="SUSPICIOUS_CANDIDATE", rule_id="buffer-unchecked-strcpy")
            finding["cwe"] = get_weakness("CWE-121")
            record = normalize_report(report(finding), root, "shadow").records[0]
            self.assertEqual(record.family, "BUFFER_BOUNDARY_VIOLATION")
            self.assertEqual(record.evidence.analysis_type, AnalysisType.PATTERN_BASED)
            self.assertEqual(record.classification, "SUSPICIOUS_CANDIDATE")
            self.assertTrue(record.limitations)

    def test_analyzer_timeout_and_malformed_output_are_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "main.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            with patch("scanner.shutil.which", return_value="semgrep"), patch("scanner.subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 1)):
                self.assertEqual(_semgrep(root, [source])["status"], "failed")
            result = type("Result", (), {"returncode": 0, "stderr": "not xml", "stdout": ""})()
            with patch("scanner.shutil.which", return_value="cppcheck"), patch("scanner.subprocess.run", return_value=result):
                self.assertEqual(_cppcheck(root, [source])["status"], "failed")


class ModeTests(unittest.TestCase):
    def test_mode_validation_defaults_to_legacy_and_rejects_invalid_values(self):
        self.assertEqual(validate_analysis_mode(None), "legacy")
        self.assertEqual(validate_analysis_mode("shadow"), "shadow")
        with self.assertRaises(ValueError):
            validate_analysis_mode("experimental")

    def test_legacy_mode_returns_existing_report_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            finding = legacy_finding(source)
            old_report = report(finding)
            with patch("analysis_pipeline.analyze_legacy", return_value=old_report) as analyze:
                actual = run_analysis(source, "legacy")
            self.assertIs(actual, old_report)
            self.assertEqual(analyze.call_count, 1)

    def test_shadow_mode_keeps_legacy_findings_and_runs_pipeline_independently(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            finding = legacy_finding(source)
            old_report = report(finding)
            with patch("analysis_pipeline.analyze_legacy", side_effect=[old_report, old_report]) as analyze:
                actual = run_analysis(source, "shadow")
            self.assertEqual(actual["findings"], old_report["findings"])
            self.assertEqual(analyze.call_count, 2)
            self.assertEqual(actual["shadow_analysis"]["product"], "PatchGuard")
            self.assertEqual(actual["shadow_analysis"]["comparison"]["counts"]["matched"], 1)
            self.assertEqual(actual["shadow_analysis"]["records"][0]["ir_version"], "1.0")

    def test_unified_mode_converts_back_to_existing_finding_shape(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            finding = legacy_finding(source)
            old_report = report(finding)
            with patch("analysis_pipeline.analyze_legacy", return_value=old_report):
                actual = run_analysis(source, "unified")
            self.assertEqual(actual["findings"][0], finding)
            self.assertEqual(set(actual["findings"][0]), set(finding))
            self.assertEqual(actual["analysis"]["mode"], "unified")

    def test_shadow_comparison_surfaces_pipeline_disagreement(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            legacy = legacy_finding(source)
            other = dict(legacy, line=9, id="finding-2")
            with patch("analysis_pipeline.analyze_legacy", side_effect=[report(legacy), report(other)]):
                actual = run_analysis(source, "shadow")
            counts = actual["shadow_analysis"]["comparison"]["counts"]
            self.assertEqual((counts["matched"], counts["legacy_only"], counts["ir_only"]), (0, 1, 1))

    def test_shadow_pipeline_error_does_not_change_legacy_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            finding = legacy_finding(source)
            old_report = report(finding)
            with patch("analysis_pipeline.analyze_legacy", side_effect=[old_report, RuntimeError("IR adapter failure")]):
                actual = run_analysis(source, "shadow")
            self.assertEqual(actual["findings"], old_report["findings"])
            self.assertEqual(actual["shadow_analysis"]["status"], "FAILED")
            self.assertEqual(actual["shadow_analysis"]["comparison"]["counts"]["legacy_only"], 1)

    def test_unified_ir_error_falls_back_to_legacy_and_reports_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            finding = legacy_finding(source)
            old_report = report(finding)
            with patch("analysis_pipeline.analyze_legacy", return_value=old_report), patch("analysis_pipeline.normalize_report", side_effect=RuntimeError("bad IR")):
                actual = run_analysis(source, "unified")
            self.assertEqual(actual["findings"], old_report["findings"])
            self.assertEqual(actual["scan_status"], "PARTIAL")
            self.assertEqual(actual["analysis"]["fallback"], "legacy")


if __name__ == "__main__":
    unittest.main()
