import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import app
import db
import worker
from project_io import ProjectInputError, inspect_archive, safe_path
from verification import verification_outcome
from worker import safe_extract, _compile_database_flags


class FinalizationTests(unittest.TestCase):
    def test_build_scripts_receive_a_copy_and_unavailable_sandbox_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "source"; source.mkdir()
            (source / "Makefile").write_text("all:\n\ttrue\n")
            (source / "main.c").write_text("int original;\n")
            def unavailable(command, project, build):
                self.assertNotEqual(project, source)
                (project / "main.c").write_text("modified build copy")
                return None
            with patch.object(worker,"sandbox_command",side_effect=unavailable), patch.object(worker.subprocess,"run") as execute:
                checks = worker.validate_build(root,source)
            self.assertEqual(checks["build"],"not_available")
            execute.assert_not_called()
            self.assertEqual((source / "main.c").read_text(),"int original;\n")

    def test_verification_requires_security_and_finished_checks(self):
        base = {name: "passed" for name in ("build", "tests", "sanitizers", "security")}
        for security, expected in [("passed", "verified"), ("unverified", "not_verified"), ("failed", "failed")]:
            self.assertEqual(verification_outcome({**base, "security": security}), expected)
        self.assertEqual(verification_outcome({**base, "tests": "not_available"}), "partially_verified")
        self.assertEqual(verification_outcome({**base, "tests": "running"}), "not_verified")
        self.assertEqual(verification_outcome({"build": "not_available", "baseline_shared_dependency": True}), "not_verified")

    def test_cross_platform_paths(self):
        for name in ["../x.c", "a/../x.c", "/x.c", "C:/x.c", "C:\\x.c", "//host/x.c", "CON.c", "src/file.c ", "file.c:stream"]:
            with self.subTest(name=name), self.assertRaises(ProjectInputError):
                safe_path(name)
        self.assertEqual(str(safe_path("src\\valid.c")), "src/valid.c")

    def archive(self, files):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, data in files:
                archive.writestr(name, data)
        return stream.getvalue()

    def test_wrapped_and_root_projects_have_same_build_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for prefix in ["", "repository-commit/", "src-project/src-project/"]:
                archive = root / "upload.zip"
                archive.write_bytes(self.archive([(prefix + "CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)"), (prefix + "src/main.c", "int main(void){return 0;}"), (prefix + "assets/icon.bin", b"\x00\xff")]))
                output = root / (prefix.replace("/", "-") if prefix else "plain")
                safe_extract(archive, output)
                project = output / "src-project" if prefix == "src-project/src-project/" else output
                self.assertTrue((project / "CMakeLists.txt").is_file())
                self.assertTrue((project / "src/main.c").is_file())
                self.assertFalse((output / "assets/icon.bin").exists())

    def test_rejected_archives_leave_no_extracted_source(self):
        link = zipfile.ZipInfo("link.c"); link.create_system = 3; link.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases = [self.archive([("../main.c", "x")]), self.archive([("main.c", "x"), ("MAIN.c", "x")]), self.archive([(link, "main.c")]), self.archive([("main.c", b"a\x00b")]), b"broken"]
        encrypted = bytearray(self.archive([("main.c", "int x;")]))
        struct.pack_into("<H", encrypted, 6, 1)
        central = encrypted.index(b"PK\x01\x02"); struct.pack_into("<H", encrypted, central + 8, 1)
        cases.append(encrypted)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for content in cases:
                archive=root/"upload.zip"; archive.write_bytes(content); target=root/"output"
                with self.assertRaises(ProjectInputError): safe_extract(archive,target)
                self.assertFalse(target.exists())

    def test_expansion_and_source_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/"upload.zip"; archive.write_bytes(self.archive([("main.c","x"*101)]))
            for limits in [{"max_bytes":100}, {"max_source":100}, {"max_files":0}]:
                with self.assertRaises(ProjectInputError): inspect_archive(archive, **limits)

    def test_redirect_cannot_forward_provider_token_to_another_host(self):
        handler=app.GitHubRedirectHandler()
        request=app.urllib.request.Request("https://api.github.com/repos/example/project",headers={"Authorization":"Bearer test"})
        for destination in ["https://example.com", "http://api.github.com", "https://api.github.com:444/path"]:
            with self.assertRaises(app.HTTPException): handler.redirect_request(request,None,302,"redirect",{},destination)

    def test_compile_database_rejects_plugins_and_output_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/"main.c"; source.write_text("int x;")
            (root/"compile_commands.json").write_text(json.dumps([{"directory":str(root),"file":"main.c","arguments":["clang","-fplugin=/project/evil.so","-fprofile-use=/tmp/data","-o/tmp/out","-DTEST=1","-std=c11"]}]))
            self.assertEqual(_compile_database_flags(root,source),["-DTEST=1","-std=c11"])

    def test_claim_removes_verification_job_from_claimable_states(self):
        connection=MagicMock(); connection.execute.return_value.fetchone.return_value=None
        with patch.object(db,"connect") as connect:
            connect.return_value.__enter__.return_value=connection
            db.claim_job()
        sql=connection.execute.call_args.args[0]
        self.assertIn("ELSE 'verifying'",sql)
        self.assertIn("FOR UPDATE SKIP LOCKED",sql)
        self.assertIn("scan_lease_until",sql)

    def test_deep_repairs_are_claimable(self):
        connection=MagicMock(); connection.execute.return_value.fetchone.return_value=None
        with patch.object(db,"connect") as connect:
            connect.return_value.__enter__.return_value=connection
            db.claim_repair_generation()
        self.assertIn("'queued for deep repair'",connection.execute.call_args.args[0])

    def test_locked_mutation_preserves_other_payload_fields(self):
        connection=MagicMock(); connection.execute.return_value.fetchone.return_value=({"id":"job","state":"complete","repair_operation":{"stage":"latest"}},)
        with patch.object(db,"connect") as connect:
            connect.return_value.__enter__.return_value=connection
            with db.locked_job("job","owner") as job: job["explanations"]={"finding":{"summary":"explanation"}}
        saved=json.loads(connection.execute.call_args.args[1][1])
        self.assertEqual(saved["repair_operation"]["stage"],"latest")
        self.assertIn("FOR UPDATE",connection.execute.call_args_list[0].args[0])
