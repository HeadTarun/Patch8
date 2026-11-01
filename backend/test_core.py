from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import auth
import providers

from fastapi.testclient import TestClient
import app
import scanner
import worker
from scanner import analyze, parse_cppcheck_output, sarif_report
from taxonomy import catalog, get_weakness, supported_weaknesses
from worker import safe_extract


class AuthTests(unittest.TestCase):
    def test_signed_session(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64}):
            token = auth.issue_session("user-id", "dev@example.com")
            self.assertEqual(auth.read_session(token)["id"], "user-id")
            self.assertIsNone(auth.read_session(token + "tampered"))

    def test_job_api_requires_a_session(self):
        self.assertEqual(TestClient(app.app).get("/api/jobs").status_code, 401)

    def test_registration_sets_session_and_me_returns_user(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64, "AUTH_COOKIE_SECURE": "false"}), patch.object(app, "supabase_auth", return_value={"user": {"id": "auth-user-1", "email": "dev@example.com"}, "access_token": "ignored"}):
            client = TestClient(app.app)
            registered = client.post("/api/auth/register", json={"email": "Dev@Example.com", "password": "correct horse battery"})
            self.assertEqual(registered.status_code, 201, registered.text)
            self.assertIn("httponly", registered.headers.get("set-cookie", "").lower())
            self.assertEqual(client.get("/api/auth/me").json()["email"], "dev@example.com")

    def test_registration_reports_email_confirmation_without_session(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64, "FRONTEND_URL": "http://localhost:8000/"}), patch.object(app, "supabase_auth", return_value={"user": {"id": "auth-user-1", "email": "dev@example.com"}}) as sign_up:
            response = TestClient(app.app).post("/api/auth/register", json={"email": "dev@example.com", "password": "correct horse battery"})
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json()["requires_email_confirmation"])
        self.assertNotIn("set-cookie", response.headers)
        sign_up.assert_called_once_with("signup?redirect_to=http%3A%2F%2Flocalhost%3A8000%2Fauth%2Fcallback", {"email": "dev@example.com", "password": "correct horse battery"})

    def test_auth_callback_validates_supabase_user_and_sets_session(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64, "AUTH_COOKIE_SECURE": "false"}), patch.object(app, "supabase_user", return_value={"id": "auth-user-3", "email": "dev@example.com"}) as verify:
            client = TestClient(app.app)
            response = client.post("/api/auth/callback", json={"access_token": "x" * 32})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn("httponly", response.headers.get("set-cookie", "").lower())
            self.assertEqual(client.get("/api/auth/me").json(), {"id": "auth-user-3", "email": "dev@example.com"})
        verify.assert_called_once_with("x" * 32)

    def test_login_uses_supabase_auth_and_issues_local_session(self):
        auth_result = {"user": {"id": "auth-user-2", "email": "dev@example.com"}, "access_token": "not-forwarded"}
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64, "AUTH_COOKIE_SECURE": "false"}), patch.object(app, "supabase_auth", return_value=auth_result) as sign_in:
            client = TestClient(app.app)
            response = client.post("/api/auth/login", json={"email": "Dev@Example.com", "password": "correct horse battery"})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn("httponly", response.headers.get("set-cookie", "").lower())
            self.assertEqual(client.get("/api/auth/me").json(), {"id": "auth-user-2", "email": "dev@example.com"})
        sign_in.assert_called_once_with("token?grant_type=password", {"email": "dev@example.com", "password": "correct horse battery"})

    def test_demo_login_uses_server_configured_supabase_account(self):
        result = {"user": {"id": "demo-user", "email": "demo@example.com"}, "access_token": "not-forwarded"}
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64, "AUTH_COOKIE_SECURE": "false", "DEMO_EMAIL": "demo@example.com", "DEMO_PASSWORD": "a demo password kept server-side"}), patch.object(app, "supabase_auth", return_value=result) as sign_in:
            client = TestClient(app.app)
            self.assertEqual(client.get("/api/auth/demo/status").json(), {"enabled": True})
            response = client.post("/api/auth/demo")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(client.get("/api/auth/me").json(), {"id": "demo-user", "email": "demo@example.com"})
        sign_in.assert_called_once_with("token?grant_type=password", {"email": "demo@example.com", "password": "a demo password kept server-side"})

    def test_demo_login_is_disabled_without_credentials(self):
        with patch.dict(os.environ, {"DEMO_EMAIL": "", "DEMO_PASSWORD": ""}):
            client = TestClient(app.app)
            self.assertEqual(client.get("/api/auth/demo/status").json(), {"enabled": False})
            self.assertEqual(client.post("/api/auth/demo").status_code, 404)

    def test_github_sign_in_redirects_through_supabase_to_port_8000(self):
        with patch.dict(os.environ, {"SUPABASE_URL": "https://project.supabase.co", "FRONTEND_URL": "http://localhost:8000/"}):
            response = TestClient(app.app).get("/api/auth/github", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "https://project.supabase.co/auth/v1/authorize?provider=github&redirect_to=http%3A%2F%2Flocalhost%3A8000%2Fauth%2Fcallback")

    def test_session_cannot_read_another_owners_job(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64}), patch.object(app, "get_job", return_value={"id": "00000000-0000-0000-0000-000000000001", "owner_id": "owner-b"}):
            client = TestClient(app.app)
            client.cookies.set("patchguard_session", auth.issue_session("owner-a", "a@example.com"))
            response = client.get("/api/jobs/00000000-0000-0000-0000-000000000001")
        self.assertEqual(response.status_code, 404)


class ProviderTests(unittest.TestCase):
    def test_auto_falls_back_to_groq_and_reports_provider(self):
        proposal = providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=1, end_line=1, original="bad", replacement="good", reason="fix")], explanation="fixed", security_improvement="safe")
        with patch.object(providers, "_ollama", side_effect=RuntimeError("offline")), patch.object(providers, "_groq", return_value=proposal):
            result, actual = providers.generate_with_provider("auto", {"file": "main.c"})
        self.assertIs(result, proposal)
        self.assertEqual(actual, "groq")

    def test_explicit_ollama_does_not_fall_back(self):
        with patch.object(providers, "_ollama", side_effect=RuntimeError("offline")), patch.object(providers, "_groq") as groq:
            with self.assertRaises(RuntimeError):
                providers.generate_with_provider("ollama", {"file": "main.c"})
        groq.assert_not_called()

    def test_explanations_fall_back_and_report_the_provider(self):
        result = providers.FindingExplanation(summary="A write may exceed the buffer.", impact="Nearby memory may be corrupted.", recommended_action="Validate the input length.")
        with patch.object(providers, "_ollama_explanation", side_effect=RuntimeError("offline")), patch.object(providers, "_groq_explanation", return_value=result):
            explanation, actual = providers.explain_with_provider("auto", {"finding": "overflow"})
        self.assertIs(explanation, result)
        self.assertEqual(actual, "groq")

    def test_explicit_ollama_explanation_does_not_fall_back(self):
        with patch.object(providers, "_ollama_explanation", side_effect=RuntimeError("offline")), patch.object(providers, "_groq_explanation") as groq:
            with self.assertRaises(RuntimeError):
                providers.explain_with_provider("ollama", {})
        groq.assert_not_called()



class TargetedRepairTests(unittest.TestCase):
    def test_mismatch_attempt_keeps_actual_expected_and_suggestion(self):
        proposal = providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=2, end_line=2, original="wrong", replacement="fixed", reason="reason")], explanation="fix", security_improvement="safe")
        result = app._rejected_attempt(ValueError("text_mismatch: Edit 1 does not match lines 2-2."), proposal, "first\nactual\n", 2)
        self.assertEqual(result["code"], "text_mismatch")
        self.assertEqual(result["edits"][0]["actual"], "actual\n")
        self.assertEqual(result["edits"][0]["expected"], "wrong")
        self.assertEqual(result["edits"][0]["replacement"], "fixed")
        self.assertIn("verification have not started", result["message"])

    def test_source_preview_is_owner_scoped_and_available_without_repair(self):
        job_id = "00000000-0000-0000-0000-000000000004"
        job = {"id": job_id, "owner_id": "owner-a", "findings": [{"id": "f", "file": "main.c", "line": 1}]}
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / job_id / "source"
            source.mkdir(parents=True)
            (source / "main.c").write_text("int x;\n")
            with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", Path(temp)), patch.object(app, "get_job", return_value=job):
                client = TestClient(app.app)
                client.cookies.set("patchguard_session", auth.issue_session("owner-a", "a@example.com"))
                self.assertEqual(client.get(f"/api/jobs/{job_id}/findings/f/source").json()["original"], "int x;\n")
                client.cookies.set("patchguard_session", auth.issue_session("owner-b", "b@example.com"))
                self.assertEqual(client.get(f"/api/jobs/{job_id}/findings/f/source").status_code, 404)

    def test_local_edit_preserves_crlf_and_unrelated_source(self):
        before = "int helper(void) { return 1; }\r\nint f(int *p) { return *p; }\r\n"
        edit = {"start_line":2, "end_line":2, "original": "return *p;", "replacement": "return p ? *p : 0;", "reason": "check pointer", "kind": "code"}
        after, edits, added, deleted = app._validate_edits(before, [edit], 0, len(before))
        self.assertEqual(after, before.replace(edit["original"], edit["replacement"]))
        self.assertEqual((added, deleted), (1, 1))
        self.assertEqual(edits[0]["line"], 2)

    def test_ambiguous_overlapping_and_out_of_scope_edits_fail(self):
        before = "int x;\nint x;\nint value = 1;\n"
        for edits, start, end in [
            ([{"start_line":1, "end_line":2, "original":"int x;", "replacement":"int y;", "reason":"x"}], 0, len(before)),
            ([{"start_line":3, "end_line":3, "original":"int value", "replacement":"long value", "reason":"x"}, {"start_line":3, "end_line":3, "original":"value = 1", "replacement":"value = 2", "reason":"y"}], 0, len(before)),
            ([{"start_line":3, "end_line":3, "original":"int value", "replacement":"long value", "reason":"x"}], 0, 2),
        ]:
            with self.assertRaises(ValueError):
                app._validate_edits(before, edits, start, end)

    def test_repeated_text_outside_selected_range_and_newlines(self):
        before = "int a(){return 0;}\r\nint b(){return 0;}\r\n"
        edit = {"start_line":2, "end_line":2, "original":"int b(){return 0;}\n", "replacement":"int b(){return 1;}\n", "reason":"fix", "kind":"code"}
        after, _, _, _ = app._validate_edits(before, [edit], 0, len(before))
        self.assertEqual(after, "int a(){return 0;}\r\nint b(){return 1;}\r\n")
        edit["start_line"] = 1
        edit["end_line"] = 1
        with self.assertRaisesRegex(ValueError, "text_mismatch"):
            app._validate_edits(before, [edit], 0, len(before))

    def test_mixed_line_endings_and_indent_mismatch_rejected(self):
        source = "int a;\r\n int b;\n"
        edit = {"start_line":2, "end_line":2, "original":"int b;", "replacement":"int c;", "reason":"fix"}
        with self.assertRaisesRegex(ValueError, "mixed_line_endings"):
            app._validate_edits(source, [edit], 0, len(source))
        source = "int a;\n int b;\n"
        edit["original"] = "  int b;"
        with self.assertRaisesRegex(ValueError, "text_mismatch"):
            app._validate_edits(source, [edit], 0, len(source))

    def test_verification_uses_fresh_copy_after_build_mutates_files(self):
        job_id = "00000000-0000-0000-0000-000000000004"
        repair_id = "00000000-0000-0000-0000-000000000005"
        job = {"id": job_id, "repair": {"id": repair_id, "finding_id": "f"}, "repair_operation": {"id": "op"}, "findings": []}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / job_id / "candidates" / repair_id
            candidate.mkdir(parents=True)
            (candidate / "main.c").write_text("original\n")
            def build(directory, source, on_check=None):
                (source / "main.c").write_text("modified by build\n")
                return {"build":"passed", "tests":"not_available", "sanitizers":"not_available", "performance":"not_measured"}
            def security(source, current):
                self.assertEqual((source / "main.c").read_text(), "original\n")
                return {"status":"passed", "details":"checked"}
            with patch.object(worker, "JOBS_ROOT", root), patch.object(worker, "validate_build", side_effect=build), patch.object(worker, "verify_repair_security", side_effect=security), patch.object(worker, "run_benchmark", return_value=None), patch.object(worker, "update_repair_operation", return_value=True), patch.object(worker, "get_job", return_value=job), patch.object(worker, "finish_repair") as finish:
                worker.validate_repair(job_id, job)
            self.assertEqual((candidate / "main.c").read_text(), "original\n")
            self.assertEqual(finish.call_args.args[3]["verification_outcome"], "partially_verified")

    def test_include_edit_only_adds_standard_include(self):
        before = '#include <stdio.h>\nint f(void) { return 0; }\n'
        edit = {"start_line":1, "end_line":1, "original":"#include <stdio.h>\n", "replacement":"#include <stdio.h>\n#include <stdlib.h>\n", "reason":"header", "kind":"include"}
        self.assertIn("#include <stdlib.h>", app._validate_edits(before, [edit], 19, len(before))[0])
        edit["replacement"] += "int injected;\n"
        with self.assertRaises(ValueError):
            app._validate_edits(before, [edit], 19, len(before))

    def test_retry_apply_and_preserve_existing_copy(self):
        job_id = "00000000-0000-0000-0000-000000000003"
        finding_id = "finding-3"
        source = "int read_value(int *p) { return *p; }\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_dir = root / job_id / "source"
            source_dir.mkdir(parents=True)
            (source_dir / "main.c").write_bytes(source.encode())
            finding = {"id": finding_id, "file":"main.c", "line":1, "message":"null dereference", "mapping_confidence":"high", "cwe":{"id":"CWE-476"}}
            job = {"id":job_id, "owner_id":"owner-a", "state":"complete", "provider":"auto", "findings":[finding]}
            def proposal(original):
                return providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=1, end_line=1, original=original, replacement="return p ? *p : 0;", reason="check pointer")], explanation="Check pointer", security_improvement="Avoid null dereference")
            with patch.dict(os.environ, {"AUTH_SECRET":"a" * 64}), patch.object(app, "JOBS_ROOT", root), patch.object(app, "get_job", return_value=job), patch.object(app, "_save_job"), patch.object(app, "begin_repair", return_value=True), patch.object(app, "update_repair_operation", return_value=True), patch.object(app, "enqueue_repair", side_effect=lambda jid, opid, repair, proposal: job.update(repair=repair, proposals=[proposal]) or True), patch.object(app, "generate_with_provider", side_effect=[(proposal("missing"), "ollama"), (proposal("return *p;"), "ollama")]) as generate:
                client = TestClient(app.app)
                client.cookies.set("patchguard_session", auth.issue_session("owner-a", "a@example.com"))
                response = client.post(f"/api/jobs/{job_id}/repair/{finding_id}")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(generate.call_count, 2)
                self.assertEqual(generate.call_args_list[1].args[0], "ollama")
                repair_id = response.json()["id"]
                job["repair"]["state"] = "review_ready"
                job["repair"]["checks"]["verification_outcome"] = "verified"
                (source_dir / "main.c").write_text("changed")
                self.assertEqual(client.post(f"/api/jobs/{job_id}/apply/{repair_id}").status_code, 409)
                (source_dir / "main.c").write_bytes(source.encode())
                job["repair"]["checks"]["verification_outcome"] = "failed"
                self.assertEqual(client.post(f"/api/jobs/{job_id}/apply/{repair_id}").status_code, 409)
                job["repair"]["checks"]["verification_outcome"] = "partially_verified"
                self.assertEqual(client.post(f"/api/jobs/{job_id}/apply/{repair_id}").status_code, 409)
                job["repair"]["checks"]["verification_outcome"] = "verified"
                applied = client.post(f"/api/jobs/{job_id}/apply/{repair_id}")
                self.assertEqual(applied.status_code, 200, applied.text)
                self.assertEqual((source_dir / "main.c").read_bytes(), source.encode())
                patched = root / job_id / "patched" / "main.c"
                self.assertIn("p ? *p : 0", patched.read_text())
                self.assertEqual(client.post(f"/api/jobs/{job_id}/apply/{repair_id}").status_code, 409)
                self.assertTrue(patched.exists())

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

    def test_explanation_is_authenticated_owner_scoped_and_cached(self):
        job_id = "00000000-0000-0000-0000-000000000001"
        finding_id = "finding-1"
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / job_id / "source"
        source.mkdir(parents=True)
        (source / "main.c").write_text("char output[4];\nvoid copy(const char *input) { strcpy(output, input); }\n")
        job = {"id": job_id, "owner_id": "owner-a", "state": "complete", "provider": "ollama", "findings": [{"id": finding_id, "file": "main.c", "line": 2, "message": "Unbounded copy", "evidence": "strcpy", "severity": "high", "classification": "confirmed", "cwe": {"id": "CWE-120"}}]}
        generated = providers.FindingExplanation(summary="The copy has no size limit.", impact="Long input can overwrite adjacent memory.", recommended_action="Bound the copy by the destination capacity.")
        with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", root), patch.object(app, "get_job", return_value=job), patch.object(app, "_save_job") as save, patch.object(app, "explain_with_provider", return_value=(generated, "ollama")) as explain:
            client = TestClient(app.app)
            endpoint = f"/api/jobs/{job_id}/explain/{finding_id}"
            self.assertEqual(client.post(endpoint).status_code, 401)
            client.cookies.set("patchguard_session", auth.issue_session("owner-a", "a@example.com"))
            first = client.post(endpoint)
            second = client.post(endpoint)
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(second.json(), first.json())
            self.assertEqual(first.json()["provider_used"], "ollama")
            self.assertEqual(client.get(endpoint).json(), first.json())
            explain.assert_called_once()
            save.assert_called_once()
            self.assertEqual(client.get(f"/api/jobs/{job_id}/explain/missing").status_code, 404)
            client.cookies.set("patchguard_session", auth.issue_session("owner-b", "b@example.com"))
            self.assertEqual(client.post(endpoint).status_code, 404)

    def test_explanation_provider_failure_returns_actionable_gateway_error(self):
        job_id = "00000000-0000-0000-0000-000000000002"
        finding_id = "finding-2"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / job_id / "source"
            source.mkdir(parents=True)
            (source / "main.c").write_text("int main(void) { return 0; }\n")
            job = {"id": job_id, "owner_id": "owner-a", "state": "complete", "provider": "auto", "findings": [{"id": finding_id, "file": "main.c", "line": 1, "message": "Test finding"}]}
            with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", root), patch.object(app, "get_job", return_value=job), patch.object(app, "explain_with_provider", side_effect=RuntimeError("Ollama and Groq are unavailable.")):
                client = TestClient(app.app)
                client.cookies.set("patchguard_session", auth.issue_session("owner-a", "a@example.com"))
                response = client.post(f"/api/jobs/{job_id}/explain/{finding_id}")
            self.assertEqual(response.status_code, 502)
            self.assertIn("Ollama and Groq are unavailable", response.json()["detail"])

    def test_provider_status_reports_reachable_endpoint_with_missing_model(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self): return b'{"models":[{"name":"other-model:latest"}]}'
        with patch.dict(os.environ, {"OLLAMA_BASE_URL": "http://ollama:11434", "OLLAMA_MODEL": "qwen2.5:3b"}), patch.object(app.urllib.request, "urlopen", return_value=Response()):
            provider = TestClient(app.app).get("/api/providers").json()["providers"]["ollama"]
        self.assertTrue(provider["available"])
        self.assertFalse(provider["model_available"])

    def post_file(self, filename: str, body: bytes):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", Path(temporary.name)), patch.object(app, "_save_job"):
            client = TestClient(app.app)
            client.cookies.set("patchguard_session", auth.issue_session("test-user", "test@example.com"))
            return client.post("/api/jobs", files={"file": (filename, body)}, data={})

    def test_upload_defaults_to_automatic_provider(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", Path(temp)), patch.object(app, "_save_job") as save:
                client = TestClient(app.app)
                client.cookies.set("patchguard_session", auth.issue_session("test-user", "test@example.com"))
                response = client.post("/api/jobs", files={"file": ("main.c", b"int main(void) { return 0; }\n")})
                self.assertEqual(response.status_code, 202)
                self.assertEqual(save.call_args.args[0]["provider"], "auto")

    def test_upload_accepts_multiple_nested_source_files(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", Path(temporary.name)), patch.object(app, "_save_job") as save:
            client = TestClient(app.app)
            client.cookies.set("patchguard_session", auth.issue_session("test-user", "test@example.com"))
            response = client.post("/api/jobs", files=[("files", ("src/main.c", b"int main(void) { return 0; }\n")), ("files", ("include/main.h", b"int read(void);\n")), ("files", ("CMakeLists.txt", b"cmake_minimum_required(VERSION 3.20)\n")), ("files", ("node_modules/ignored.c", b"not included\n"))], data={"provider": "none"})
            self.assertEqual(response.status_code, 202, response.text)
            job = save.call_args.args[0]
            self.assertEqual(job["upload_kind"], "project")
            self.assertTrue((Path(temporary.name) / job["id"] / "upload-source" / "src" / "main.c").is_file())
            self.assertTrue((Path(temporary.name) / job["id"] / "upload-source" / "include" / "main.h").is_file())
            self.assertTrue((Path(temporary.name) / job["id"] / "upload-source" / "CMakeLists.txt").is_file())
            self.assertFalse((Path(temporary.name) / job["id"] / "upload-source" / "node_modules").exists())

    def test_single_file_from_folder_keeps_its_path(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", Path(temporary.name)), patch.object(app, "_save_job") as save:
            client = TestClient(app.app)
            client.cookies.set("patchguard_session", auth.issue_session("test-user", "test@example.com"))
            response = client.post("/api/jobs", files={"files": ("project/src/main.c", b"int main(void) { return 0; }\n")}, data={"provider": "none"})
            self.assertEqual(response.status_code, 202, response.text)
            job = save.call_args.args[0]
            self.assertEqual(job["upload_kind"], "project")
            self.assertTrue((Path(temporary.name) / job["id"] / "upload-source" / "project" / "src" / "main.c").is_file())

    def test_upload_accepts_standalone_c_cpp_and_defaults_to_scan_only(self):
        for filename in ("main.c", "main.cpp"):
            with self.subTest(filename=filename):
                response = self.post_file(filename, b"int main(void) { return 0; }\n")
                self.assertEqual(response.status_code, 202, response.text)

    def test_upload_accepts_header_and_rejects_empty_invalid_encoding_and_oversize(self):
        self.assertEqual(self.post_file("main.h", b"int x;\n").status_code, 202)
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


class RepairValidationTests(unittest.TestCase):
    def test_repair_context_rejects_source_over_limit(self):
        finding = {"message": "null dereference", "mapping_confidence": "high", "file": "main.c", "line": 1}
        cwe = {"id": "CWE-476", "name": "NULL Pointer Dereference", "description": "", "mapping_usage": "", "mitigations": []}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "main.c"
            with patch.object(app, "MAX_REPAIR_CONTEXT_CHARS", 3):
                with self.assertRaises(app.HTTPException) as raised:
                    app._build_repair_context("int x;", finding, cwe, root, target)
                self.assertIn("repair context limit", raised.exception.detail)

    def test_security_verifier_reports_target_remaining_as_failure(self):
        original = {"id": "finding", "file": "main.c", "rule_id": "nullPointer", "message": "null dereference", "cwe": {"id": "CWE-476"}}
        job = {"findings": [original], "repair": {"finding_id": "finding"}}
        with patch.object(worker, "analyze", return_value={"scan_status": "COMPLETED", "findings": [original]}):
            self.assertEqual(worker.verify_repair_security(Path("."), job)["status"], "failed")

    def test_security_verifier_never_passes_incomplete_scan(self):
        original = {"id": "finding", "file": "main.c", "rule_id": "nullPointer", "message": "null dereference", "cwe": {"id": "CWE-476"}}
        job = {"findings": [original], "repair": {"finding_id": "finding"}}
        with patch.object(worker, "analyze", return_value={"scan_status": "PARTIAL", "findings": []}):
            self.assertEqual(worker.verify_repair_security(Path("."), job)["status"], "unverified")

    def test_security_verifier_passes_only_complete_clean_scan(self):
        original = {"id": "finding", "file": "main.c", "rule_id": "nullPointer", "message": "null dereference", "cwe": {"id": "CWE-476"}}
        job = {"findings": [original], "repair": {"finding_id": "finding"}}
        with patch.object(worker, "analyze", return_value={"scan_status": "COMPLETED", "findings": []}):
            self.assertEqual(worker.verify_repair_security(Path("."), job)["status"], "passed")

    def test_security_verifier_rejects_new_findings(self):
        original = {"id": "finding", "file": "main.c", "rule_id": "nullPointer", "message": "null dereference", "cwe": {"id": "CWE-476"}}
        added = {"file": "other.c", "rule_id": "nullPointer", "message": "new null dereference", "cwe": {"id": "CWE-476"}}
        job = {"findings": [original], "repair": {"finding_id": "finding"}}
        with patch.object(worker, "analyze", return_value={"scan_status": "COMPLETED", "findings": [added]}):
            self.assertEqual(worker.verify_repair_security(Path("."), job)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
