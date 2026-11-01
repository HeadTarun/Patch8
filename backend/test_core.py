from __future__ import annotations

import io
import hashlib
import json
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import contextmanager
import auth
import providers

from fastapi.testclient import TestClient
from starlette.requests import Request
import app
import scanner
import worker
from scanner import analyze, parse_cppcheck_output, sarif_report
from taxonomy import catalog, get_weakness, supported_weaknesses
from worker import safe_extract


def request_for(user_id: str) -> Request:
    token = auth.issue_session(user_id, f"{user_id}@example.com")
    return Request({"type": "http", "method": "POST", "path": "/", "query_string": b"",
                    "headers": [(b"cookie", f"patchguard_session={token}".encode())],
                    "server": ("test", 80), "client": ("127.0.0.1", 1234), "scheme": "http"})


class JobTestCase(unittest.TestCase):
    """API unit tests use an in-memory job; PostgreSQL locking has separate checks."""
    def setUp(self):
        @contextmanager
        def memory_job(job_id, owner_id):
            job = app._read_job(job_id, owner_id)
            yield job
            app._save_job(job)
        self.job_lock = patch.object(app, "_locked_job", memory_job)
        self.job_lock.start()
        self.addCleanup(self.job_lock.stop)


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
        self.assertEqual(response.headers["location"], "https://project.supabase.co/auth/v1/authorize?provider=github&redirect_to=http%3A%2F%2Flocalhost%3A8000%2Fauth%2Fcallback%3Fsource%3Dgithub")

    def test_session_cannot_read_another_owners_job(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "s" * 64}), patch.object(app, "get_job", return_value={"id": "00000000-0000-0000-0000-000000000001", "owner_id": "owner-b"}):
            client = TestClient(app.app)
            client.cookies.set("patchguard_session", auth.issue_session("owner-a", "a@example.com"))
            response = client.get("/api/jobs/00000000-0000-0000-0000-000000000001")
        self.assertEqual(response.status_code, 404)


class GitHubTests(unittest.TestCase):
    def test_repository_list_requires_session_and_returns_only_public_fields(self):
        client = TestClient(app.app)
        response = client.post("/api/github/repositories", json={"provider_token": "provider-token"})
        self.assertEqual(response.status_code, 401)

        repositories = [
            {"full_name": "demo/firmware", "default_branch": "main", "description": "Firmware", "updated_at": "2026-10-31T12:00:00Z", "private": False},
            {"full_name": "demo/private", "default_branch": "main", "private": True},
        ]
        with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "_github_json", return_value=repositories) as github_json:
            client.cookies.set("patchguard_session", auth.issue_session("demo-user", "demo@example.com"))
            response = client.post("/api/github/repositories", json={"provider_token": "provider-token"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"next_page": None, "repositories": [{"full_name": "demo/firmware", "default_branch": "main", "description": "Firmware", "updated_at": "2026-10-31T12:00:00Z"}]})
        github_json.assert_called_once_with("/user/repos?visibility=public&sort=updated&per_page=100&page=1", "provider-token")

    def test_snapshot_resolves_branch_to_commit_and_rejects_private_repositories(self):
        sha = "a" * 40
        with patch.object(app, "_github_json", side_effect=[{"private": False, "default_branch": "release/v1"}, {"sha": sha}]) as github_json, patch.object(app, "_github_archive", return_value=b"zip") as download:
            archive, source = app._github_snapshot("provider-token", "demo/firmware")
        self.assertEqual(archive, b"zip")
        self.assertEqual(source, {"type": "github", "repository": "demo/firmware", "branch": "release/v1", "commit_sha": sha})
        self.assertEqual(github_json.call_args_list[1].args[0], "/repos/demo/firmware/commits/release%2Fv1")
        download.assert_called_once_with("demo", "firmware", sha)

        with patch.object(app, "_github_json", return_value={"private": True}) as github_json, patch.object(app, "_github_archive") as download:
            with self.assertRaises(app.HTTPException) as error:
                app._github_snapshot("provider-token", "demo/private")
        self.assertEqual(error.exception.status_code, 404)
        download.assert_not_called()

    def test_scan_uses_existing_zip_validation_and_does_not_persist_provider_token(self):
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("firmware-main/src/main.c", "int main(void) { return 0; }\n")
        source = {"type": "github", "repository": "demo/firmware", "branch": "main", "commit_sha": "b" * 40}
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", Path(temporary)), patch.object(app, "_github_snapshot", return_value=(archive_buffer.getvalue(), source)) as snapshot, patch.object(app, "_save_job") as save:
            client = TestClient(app.app)
            client.cookies.set("patchguard_session", auth.issue_session("demo-user", "demo@example.com"))
            response = client.post("/api/github/scan", json={"provider_token": "provider-token-secret", "full_name": "demo/firmware"})
            self.assertEqual(response.status_code, 202, response.text)
            job = save.call_args.args[0]
            self.assertEqual(job["name"], "demo/firmware")
            self.assertEqual(job["source"], source)
            self.assertEqual(job["upload_kind"], "zip")
            self.assertTrue((Path(temporary) / job["id"] / "upload.zip").is_file())
            self.assertNotIn("provider-token-secret", json.dumps(job))
        snapshot.assert_called_once_with("provider-token-secret", "demo/firmware")

    def test_scan_rejects_invalid_repository_names(self):
        with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}):
            client = TestClient(app.app)
            client.cookies.set("patchguard_session", auth.issue_session("demo-user", "demo@example.com"))
            response = client.post("/api/github/scan", json={"provider_token": "provider-token", "full_name": "https://example.com/archive.zip"})
        self.assertEqual(response.status_code, 400)

    def test_archive_limit_and_github_rate_limit_are_reported(self):
        class OversizedResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def geturl(self): return "https://codeload.github.com/demo/repo/zip/" + "a" * 40
            def read(self, size): return b"x" * size

        with patch.object(app, "MAX_UPLOAD", 4), patch.object(app.urllib.request, "urlopen", return_value=OversizedResponse()):
            with self.assertRaises(app.HTTPException) as too_large:
                app._github_archive("demo", "repo", "a" * 40)
        self.assertEqual(too_large.exception.status_code, 413)

        from email.message import Message
        headers = Message()
        headers["X-RateLimit-Remaining"] = "0"
        rate_limited = app.urllib.error.HTTPError("https://api.github.com/user/repos", 403, "rate limited", headers, None)
        with patch.object(app.urllib.request.OpenerDirector, "open", side_effect=rate_limited):
            with self.assertRaises(app.HTTPException) as rate_limit:
                app._github_request("/user/repos", "provider-token")
        self.assertEqual(rate_limit.exception.status_code, 429)


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

    def test_deep_repair_uses_configured_groq_model_and_high_reasoning(self):
        proposal = providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=1, end_line=1, original="bad", replacement="good", reason="fix")], explanation="fixed", security_improvement="safe")
        prompt = SimpleNamespace(invoke=lambda context: SimpleNamespace(to_string=lambda: "prompt"))
        response = {"choices": [{"message": {"content": proposal.model_dump_json()}}]}
        with patch.dict(os.environ, {"GROQ_API_KEY": "secret", "GROQ_DEEP_MODEL": "openai/gpt-oss-120b"}), patch.object(providers, "_prompt_template", return_value=prompt), patch.object(providers, "_post", return_value=response) as post:
            actual, provider = providers.generate_with_provider("deep", {})
        self.assertEqual(provider, "groq")
        self.assertEqual(actual.file, "main.c")
        payload = post.call_args.args[1]
        self.assertEqual(payload["model"], "openai/gpt-oss-120b")
        self.assertEqual(payload["reasoning_effort"], "high")


class InternalRepairTests(unittest.TestCase):
    def test_internal_generation_requires_shared_secret(self):
        proposal = providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=1, end_line=1, original="bad", replacement="good", reason="fix")], explanation="fixed", security_improvement="safe")
        with patch.dict(os.environ, {"REPAIR_INTERNAL_SECRET": "internal-secret", "GROQ_MODEL": "standard-model"}), patch.object(app, "generate_with_provider", return_value=(proposal, "groq")):
            payload = app.InternalRepairRequest(provider="groq", context={})
            with self.assertRaises(app.HTTPException) as denied:
                app.internal_repair_generate(payload, "")
            response = app.internal_repair_generate(payload, "internal-secret")
        self.assertEqual(denied.exception.status_code, 404)
        self.assertEqual(response["model"], "standard-model")

    def test_deep_repair_is_available_after_failure_and_shares_attempt_limit(self):
        job_id, finding_id = "00000000-0000-0000-0000-000000000003", "finding-3"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / job_id / "source"
            source.mkdir(parents=True)
            (source / "main.c").write_text("int value;\n")
            job = {"id": job_id, "owner_id": "owner-a", "state": "complete", "provider": "none",
                   "findings": [{"id": finding_id, "file": "main.c", "line": 1, "cwe": {"id": "CWE-120"}, "mapping_confidence": "high"}],
                   "repair_operation": {}, "repair_attempt_counts": {}}
            context = {"scope_start_line": 1, "scope_end_line": 1}
            with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64, "GROQ_API_KEY": "secret"}), patch.object(app, "JOBS_ROOT", root), patch.object(app, "recover_repairs"), patch.object(app, "_read_job", return_value=job), patch.object(app, "_build_repair_context", return_value=context), patch.object(app, "begin_repair", return_value=True) as begin:
                request = request_for("owner-a")
                response = app.create_repair(job_id, finding_id, request, mode="deep")
                self.assertEqual(response["state"], "queued")
                self.assertEqual(begin.call_args.args[2]["mode"], "deep")
                job["provider"] = "auto"
                job["repair_operation"] = {"finding_id": finding_id, "status": "failed"}
                job["repair_attempt_counts"][finding_id] = 1
                retry = app.create_repair(job_id, finding_id, request, mode="deep")
                self.assertEqual(retry["state"], "queued")
                job["repair_attempt_counts"][finding_id] = 3
                with self.assertRaises(app.HTTPException) as exhausted:
                    app.create_repair(job_id, finding_id, request, mode="deep")
        self.assertEqual(exhausted.exception.status_code, 409)


class RepairAcceptanceTests(JobTestCase):
    def test_acceptance_records_author_and_verification_outcome(self):
        job_id, repair_id = "00000000-0000-0000-0000-000000000004", "00000000-0000-0000-0000-000000000005"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / job_id / "source"
            source.mkdir(parents=True)
            original = source / "main.c"
            original.write_text("int value;\n")
            candidate = root / job_id / "candidates" / repair_id
            candidate.mkdir(parents=True)
            (candidate / "main.c").write_text("int value = 1;\n")
            repair = {"id": repair_id, "finding_id": "finding", "file": "main.c", "source_hash": hashlib.sha256(original.read_bytes()).hexdigest(),
                      "candidate_hash": app._tree_hash(candidate), "state": "review_ready", "checks": {"verification_outcome": "verified", "build":"passed", "tests":"passed", "sanitizers":"passed", "security":"passed"}}
            repairs = root / job_id / "repairs"
            repairs.mkdir()
            (repairs / f"{repair_id}.json").write_text(json.dumps(repair))
            job = {"id": job_id, "owner_id": "owner-a", "repair": dict(repair), "proposals": [], "repair_operation": {}}
            with patch.dict(os.environ, {"AUTH_SECRET": "a" * 64}), patch.object(app, "JOBS_ROOT", root), patch.object(app, "_read_job", return_value=job), patch.object(app, "_save_job"):
                response = app.apply_repair(job_id, repair_id, request_for("owner-a"), confirm_human_review=True)
            audit = response["review"]
            self.assertEqual(audit["reviewed_by"], "owner-a")
            self.assertEqual(audit["verification_outcome"], "verified")
            self.assertTrue(audit["reviewed_at"] > 0)


class RepairContextTests(unittest.TestCase):
    def test_deep_context_is_wider_and_carries_verification_feedback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "main.c"
            target.write_text("".join(f"int item_{line};\n" for line in range(1, 301)))
            finding = {"message": "Null dereference", "evidence": "pointer access", "mapping_confidence": "high", "file": "main.c", "line": 150}
            weakness = get_weakness("CWE-476")
            standard = app._build_repair_context(target.read_text(), finding, weakness, root, target)
            deep = app._build_repair_context(target.read_text(), finding, weakness, root, target, deep=True, verification_feedback="build failed")
        self.assertNotIn("int item_30;", standard["numbered_source"])
        self.assertIn("int item_30;", deep["numbered_source"])
        self.assertEqual(deep["verification_feedback"], "build failed")

    def test_invalid_standard_attempt_stops_with_retry_available(self):
        job_id, finding_id = "00000000-0000-0000-0000-000000000006", "finding-6"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / job_id / "source"
            source.mkdir(parents=True)
            (source / "main.c").write_text("int value;\n")
            proposal = providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=1, end_line=1, original="wrong", replacement="fixed", reason="repair")], explanation="repair", security_improvement="safe")
            job = {"repair_operation": {"id": "operation", "finding_id": finding_id, "mode": "standard", "deadline": time.time()+60},
                   "findings": [{"id": finding_id, "file": "main.c", "line": 1, "message": "finding", "cwe": {"id": "CWE-476"}, "mapping_confidence": "high"}], "provider": "auto"}
            context = {"scope_start": 0, "scope_end": 10, "scope_start_line": 1, "scope_end_line": 1}
            with patch.object(worker, "JOBS_ROOT", root), patch.object(worker, "_build_repair_context", return_value=context), patch.object(worker, "reserve_repair_attempt", return_value=1), patch.object(worker, "_generate_with_deadline", return_value=(proposal, "groq", "model")) as generate, patch.object(worker, "update_repair_operation", return_value=True) as update:
                worker.generate_repair(job_id, job)
        self.assertEqual(generate.call_count, 1)
        self.assertEqual(update.call_args.args[2]["status"], "failed")
        self.assertTrue(update.call_args.args[2]["attempts"][0]["retryable"])

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



class TargetedRepairTests(JobTestCase):
    def test_final_rejected_suggestion_requires_human_review(self):
        job_id = "00000000-0000-0000-0000-000000000010"
        finding = {"id":"f", "file":"main.c", "line":1, "message":"null dereference", "mapping_confidence":"high", "cwe":{"id":"CWE-476"}}
        job = {"id":job_id, "owner_id":"owner-a", "state":"complete", "provider":"ollama", "findings":[finding],
               "repair_operation":{"id":"op", "finding_id":"f", "deadline":time.time()+180}}
        proposal = providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=1, end_line=1, original="not present", replacement="fixed", reason="fix")], explanation="fix", security_improvement="safe")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / job_id / "source"
            source.mkdir(parents=True)
            (source / "main.c").write_bytes(b"int x;\n")
            with patch.object(worker, "JOBS_ROOT", root), patch.object(worker, "reserve_repair_attempt", return_value=3), patch.object(worker, "update_repair_operation") as update, patch.object(worker, "_generate_with_deadline", return_value=(proposal,"ollama","model")) as generate:
                worker.generate_repair(job_id, job)
            self.assertEqual(generate.call_count, 1)
            self.assertEqual(update.call_args.args[2]["status"], "human_review")
            self.assertEqual((source / "main.c").read_text(), "int x;\n")

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
            (source / "main.c").write_bytes(b"int x;\n")
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
        with self.assertRaisesRegex(ValueError, "missing_context"):
            app._validate_edits(before, [edit], 0, len(before))

    def test_mixed_line_endings_and_indent_mismatch_rejected(self):
        source = "int a;\r\n int b;\n"
        edit = {"start_line":2, "end_line":2, "original":"int b;", "replacement":"int c;", "reason":"fix"}
        with self.assertRaisesRegex(ValueError, "mixed_line_endings"):
            app._validate_edits(source, [edit], 0, len(source))
        source = "int a;\n int b;\n"
        edit["original"] = "  int b;"
        with self.assertRaisesRegex(ValueError, "missing_context"):
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

    def test_queued_repair_apply_and_preserve_existing_copy(self):
        job_id = "00000000-0000-0000-0000-000000000003"
        source = "int read_value(int *p) { return *p; }\n"
        finding = {"id":"f", "file":"main.c", "line":1, "message":"null dereference", "mapping_confidence":"high", "cwe":{"id":"CWE-476"}}
        job = {"id":job_id, "owner_id":"owner-a", "state":"complete", "provider":"auto", "findings":[finding]}
        proposal = providers.PatchProposal(file="main.c", edits=[providers.RepairEdit(start_line=1, end_line=1, original=source, replacement="int read_value(int *p) { return p ? *p : 0; }\n", reason="check pointer")], explanation="Check pointer", security_improvement="Avoid null dereference")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source_dir = root / job_id / "source"; source_dir.mkdir(parents=True)
            (source_dir / "main.c").write_bytes(source.encode())
            def begin(jid, owner, operation):
                job["repair_operation"] = operation
                return True
            with patch.dict(os.environ, {"AUTH_SECRET":"a"*64}), patch.object(app,"JOBS_ROOT",root), patch.object(worker,"JOBS_ROOT",root), patch.object(app,"get_job",return_value=job), patch.object(app,"_save_job"), patch.object(app,"recover_repairs"), patch.object(app,"begin_repair",side_effect=begin), patch.object(worker,"reserve_repair_attempt",return_value=1), patch.object(worker,"update_repair_operation",return_value=True), patch.object(worker,"_generate_with_deadline",return_value=(proposal,"ollama","model")), patch.object(worker,"enqueue_repair",side_effect=lambda jid,opid,repair,summary: job.update(repair=repair,proposals=[summary]) or True):
                client = TestClient(app.app); client.cookies.set("patchguard_session", auth.issue_session("owner-a","a@example.com"))
                queued = client.post(f"/api/jobs/{job_id}/repair/f")
                self.assertEqual(queued.status_code,202,queued.text)
                self.assertNotIn("repair",job)
                worker.generate_repair(job_id,job)
                repair_id=job["repair"]["id"]
                job["repair"].update(state="review_ready", checks={key:"passed" for key in ("build","tests","sanitizers","security")})
                (source_dir/"main.c").write_text("changed")
                url=f"/api/jobs/{job_id}/apply/{repair_id}?confirm_human_review=true"
                self.assertEqual(client.post(url).status_code,409)
                (source_dir/"main.c").write_bytes(source.encode())
                job["repair"]["checks"]["security"]="unverified"
                self.assertEqual(client.post(url+"&confirm_partial=true").status_code,409)
                job["repair"]["checks"]["security"]="passed"
                applied=client.post(url)
                self.assertEqual(applied.status_code,200,applied.text)
                self.assertEqual((source_dir/"main.c").read_bytes(),source.encode())
                self.assertIn("p ? *p : 0",(root/job_id/"patched"/"main.c").read_text())
                self.assertEqual(client.post(url).status_code,409)


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


class ApiTests(JobTestCase):
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
            self.assertTrue((target / "main.h").is_file())


class RepairValidationTests(unittest.TestCase):
    def test_compiler_diagnostics_classify_harness_and_system_headers(self):
        output = (
            "/project/CWE476.c:8:10: fatal error: 'std_testcase.h' file not found\n"
            "/project/main.c:2:10: fatal error: 'stdio.h' file not found\n"
            "/project/bad.c:4:5: error: expected expression\n"
            "/project/type.c:6:3: error: use of undeclared identifier 'value'\n"
        )
        diagnostics = worker._parse_compiler_diagnostics(output, Path("."), "proposed")
        self.assertEqual([item["category"] for item in diagnostics], [
            "missing_project_dependency", "missing_system_header", "syntax_error", "type_error",
        ])
        self.assertEqual(diagnostics[0]["file"], "CWE476.c")
        self.assertEqual(diagnostics[0]["line"], 8)
        self.assertEqual({item["source"] for item in diagnostics}, {"proposed"})

    def test_source_only_build_marks_matching_missing_dependency_unavailable(self):
        missing_original = {"category":"missing_project_dependency", "file":"main.c", "line":1, "column":10,
                            "message":"'std_testcase.h' file not found", "source":"original"}
        missing_proposed = {**missing_original, "source":"proposed"}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            baseline = root / "baseline"
            source.mkdir(); baseline.mkdir()
            with patch.object(worker, "_syntax_check", side_effect=[
                {"build":"not_available", "diagnostics":[missing_proposed], "details":"missing harness"},
                {"build":"not_available", "diagnostics":[missing_original], "details":"missing harness"},
            ]):
                checks = worker.validate_build(root, source, baseline_source=baseline)
        self.assertEqual(checks["build"], "not_available")
        self.assertTrue(checks["baseline_shared_dependency"])

    def test_source_only_build_fails_on_proposed_syntax_error(self):
        syntax = {"category":"syntax_error", "file":"main.c", "line":3, "column":4,
                  "message":"expected expression", "source":"proposed"}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            baseline = root / "baseline"
            source.mkdir(); baseline.mkdir()
            with patch.object(worker, "_syntax_check", side_effect=[
                {"build":"failed", "diagnostics":[syntax], "details":"syntax error"},
                {"build":"passed", "diagnostics":[], "details":"passed"},
            ]):
                checks = worker.validate_build(root, source, baseline_source=baseline)
        self.assertEqual(checks["build"], "failed")
        self.assertFalse(checks["baseline_shared_dependency"])

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
