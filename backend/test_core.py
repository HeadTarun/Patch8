from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
import app
import scanner
from scanner import analyze, parse_cppcheck_output, sarif_report
from taxonomy import catalog, get_weakness, supported_weaknesses
from worker import safe_extract


class TaxonomyTests(unittest.TestCase):
    def test_only_requested_cwes_are_supported(self):
        self.assertEqual({item["id"] for item in supported_weaknesses()}, {"CWE-120", "CWE-121", "CWE-122", "CWE-476"})
        self.assertEqual((catalog()["version"], catalog()["schema"]), ("5.0", "8.0"))

    def test_cppcheck_only_normalizes_in_scope_null_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "main.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            xml = f'''<results><errors>
              <error id="nullPointer" severity="warning" msg="Possible null pointer dereference"><location file="{source}" line="3"/></error>
              <error id="useAfterFree" severity="error" msg="Use after free"><location file="{source}" line="4"/></error>
              <error id="bufferAccessOutOfBounds" severity="error" msg="Writing past buffer"><location file="{source}" line="5"/></error>
            </errors></results>'''
            findings = parse_cppcheck_output(root, xml)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["cwe"]["id"], "CWE-476")
            self.assertEqual(findings[0]["source_tool"], "Cppcheck")


class AnalyzerTests(unittest.TestCase):
    def test_semgrep_result_is_candidate_with_evidence_and_storage_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "main.c"
            source.write_text('void copy(const char *src) { char dst[8]; strcpy(dst, src); }\n', encoding="utf-8")
            output = {"results": [{"check_id": "buffer-unchecked-strcpy", "path": "main.c", "start": {"line": 1},
                "extra": {"message": "Unbounded copy", "lines": "strcpy(dst, src);", "metavars": {"$DEST": {"abstract_content": "dst"}}}}]}
            with patch.object(scanner.shutil, "which", return_value="semgrep"), patch.object(scanner.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr="")):
                result = scanner._semgrep(root, [source])
            finding = result["findings"][0]
            self.assertEqual(result["status"], "completed")
            self.assertEqual(finding["classification"], "SUSPICIOUS_CANDIDATE")
            self.assertEqual(finding["cwe"]["id"], "CWE-121")
            self.assertEqual(finding["evidence"], "strcpy(dst, src);")

    def test_all_unavailable_analyzers_make_scan_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            with patch.object(scanner.shutil, "which", return_value=None):
                report = analyze(root)
            self.assertEqual(report["scan_status"], "FAILED")
            self.assertEqual(report["summary"]["total"], 0)
            self.assertTrue(all(item["status"] == "failed" for item in report["analyzer_status"].values()))

    def test_analyzer_failure_with_a_successful_tool_is_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            ok = {"status": "completed", "error": None, "findings": []}
            failed = {"status": "failed", "error": "tool unavailable", "findings": []}
            with patch.object(scanner, "_clang", return_value=ok), patch.object(scanner, "_cppcheck", return_value=failed), patch.object(scanner, "_semgrep", return_value=ok):
                report = analyze(root)
            self.assertEqual(report["scan_status"], "PARTIAL")
            self.assertEqual(report["analyzer_status"]["Cppcheck"]["error"], "tool unavailable")

    def test_duplicate_null_findings_keep_both_analyzer_references(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "main.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            finding = scanner._finding(root, source, 1, "nullPointer", "Possible null dereference", "Clang Static Analyzer",
                "CWE-476", "STATIC_ANALYSIS_FINDING", "high", "null pointer", "warning")
            duplicate = {**finding, "source_tool": "Cppcheck", "source_tools": ["Cppcheck"], "rule_id": "nullPointer"}
            ok = {"status": "completed", "error": None, "findings": []}
            with patch.object(scanner, "_clang", return_value={**ok, "findings": [finding]}), patch.object(scanner, "_cppcheck", return_value={**ok, "findings": [duplicate]}), patch.object(scanner, "_semgrep", return_value=ok):
                report = analyze(root)
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(set(report["findings"][0]["source_tools"]), {"Clang Static Analyzer", "Cppcheck"})

    def test_sarif_keeps_candidate_without_asserting_taxonomy(self):
        finding = {
            "id": "candidate", "file": "main.c", "line": 1, "rule_id": "buffer-unchecked-strcpy", "message": "Risky copy",
            "source_tool": "Semgrep", "source_tools": ["Semgrep"], "classification": "SUSPICIOUS_CANDIDATE", "cwe": None,
        }
        report = sarif_report("job", [finding])
        result = report["runs"][0]["results"][0]
        self.assertNotIn("taxa", result)
        self.assertEqual(result["properties"]["classification"], "SUSPICIOUS_CANDIDATE")


class ApiTests(unittest.TestCase):
    def test_health_exposes_only_selected_cwes(self):
        client = TestClient(app.app)
        self.assertEqual(client.get("/api/health").json()["analyzers"], ["Clang Static Analyzer", "Cppcheck", "Semgrep"])
        self.assertEqual({item["id"] for item in client.get("/api/weaknesses").json()["items"]}, {"CWE-120", "CWE-121", "CWE-122", "CWE-476"})

    def post_file(self, filename: str, body: bytes):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with patch.object(app, "JOBS_ROOT", Path(temporary.name)), patch.object(app, "_save_job"):
            return TestClient(app.app).post("/api/jobs", files={"file": (filename, body)}, data={})

    def test_upload_accepts_standalone_c_cpp_and_defaults_to_scan_only(self):
        for filename in ("main.c", "main.cpp"):
            with self.subTest(filename=filename):
                response = self.post_file(filename, b"int main(void) { return 0; }\n")
                self.assertEqual(response.status_code, 202, response.text)

    def test_upload_rejects_header_empty_invalid_encoding_and_oversize(self):
        self.assertEqual(self.post_file("main.h", b"int x;\n").status_code, 415)
        self.assertEqual(self.post_file("main.c", b"").status_code, 400)
        self.assertEqual(self.post_file("main.c", b"\xff\xfe").status_code, 400)
        self.assertEqual(self.post_file("main.cpp", b"x" * 200_001).status_code, 413)

    def test_zip_accepts_header_files(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("firmware/main.h", "int read_sensor(void);\n")
        response = self.post_file("project.zip", stream.getvalue())
        self.assertEqual(response.status_code, 202, response.text)

    def test_zip_rejects_corrupt_archive_and_path_traversal(self):
        self.assertEqual(self.post_file("project.zip", b"not a zip").status_code, 400)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../main.c", "int main(void) { return 0; }\n")
        self.assertEqual(self.post_file("project.zip", stream.getvalue()).status_code, 400)

    def test_zip_upload_and_expansion_limits(self):
        with patch.object(app, "MAX_UPLOAD", 10):
            self.assertEqual(self.post_file("project.zip", b"x" * 11).status_code, 413)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("main.c", "int main(void) { return 0; }\n")
        with patch.object(app, "MAX_EXTRACTED", 10):
            self.assertEqual(self.post_file("project.zip", stream.getvalue()).status_code, 413)


class ArchiveTests(unittest.TestCase):
    def test_zip_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source_zip = base / "source.zip"
            with zipfile.ZipFile(source_zip, "w") as archive:
                archive.writestr("../outside.c", "bad")
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                safe_extract(source_zip, base / "output")

    def test_safe_extract_supports_header_only_project(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source_zip = base / "source.zip"
            with zipfile.ZipFile(source_zip, "w") as archive:
                archive.writestr("firmware/main.h", "int read_sensor(void);\n")
            target = base / "output"
            safe_extract(source_zip, target)
            self.assertTrue((target / "firmware" / "main.h").is_file())


if __name__ == "__main__":
    unittest.main()
