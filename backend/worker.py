from __future__ import annotations

import json
import hashlib
import difflib
import logging
import multiprocessing
import os
import queue
import re
import shlex
import shutil
import stat
import subprocess
import statistics
import tempfile
import time
import threading
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from db import (claim_job, claim_repair_generation, delete_expired_jobs, enqueue_repair,
                finish_repair, get_job, recover_repairs, reserve_repair_attempt,
                save_job, update_repair_operation)
from providers import generate_with_provider
from taxonomy import get_weakness
from app import (MAX_REPAIR_ATTEMPTS, REPAIR_GENERATION_TIMEOUT,
                 _build_repair_context, _proposal_summary, _rejected_attempt,
                 _repair_path, _tree_hash, _validate_edits)
from analysis_pipeline import run_analysis, validate_analysis_mode
from scanner import analyze

WORK_ROOT = Path(os.getenv("WORK_ROOT", str(Path(tempfile.gettempdir()) / "patchguard")))
JOBS_ROOT = WORK_ROOT / "jobs"
JOB_TTL = int(os.getenv("JOB_TTL_SECONDS", "3600"))
MAX_FILES = int(os.getenv("MAX_PROJECT_FILES", "5000"))
MAX_EXTRACTED = int(os.getenv("MAX_EXTRACTED_BYTES", "100000000"))
JOB_TIMEOUT = int(os.getenv("JOB_TIMEOUT_SECONDS", "90"))
ANALYSIS_MODE = validate_analysis_mode(os.getenv("ANALYSIS_MODE", "legacy"))
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "venv", ".venv", "__pycache__", "target", ".idea", ".vscode"}
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
JOBS_ROOT.mkdir(parents=True, exist_ok=True)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
SYSTEM_HEADERS = {
    "assert.h", "complex.h", "ctype.h", "errno.h", "fenv.h", "float.h", "inttypes.h",
    "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdalign.h",
    "stdarg.h", "stdatomic.h", "stdbool.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h",
    "stdnoreturn.h", "string.h", "tgmath.h", "threads.h", "time.h", "uchar.h", "wchar.h",
    "wctype.h", "algorithm", "array", "atomic", "bit", "cassert", "cctype", "cerrno",
    "cmath", "cstdio", "cstdlib", "cstring", "ctime", "iostream", "map", "memory", "optional",
    "string", "string_view", "utility", "vector",
}


def _generate_repair_child(result_queue, job_id: str, operation_id: str, provider: str, context: dict) -> None:
    try:
        generation_url = os.getenv("REPAIR_GENERATION_URL", "")
        if generation_url:
            secret = os.getenv("REPAIR_INTERNAL_SECRET", "")
            request = urllib.request.Request(generation_url, data=json.dumps({"provider": provider, "context": context}).encode(),
                headers={"Content-Type": "application/json", "X-Repair-Secret": secret}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=120) as response:
                    generated = json.loads(response.read().decode())
            except urllib.error.HTTPError as exc:
                try:
                    message = json.loads(exc.read().decode()).get("detail", str(exc))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    message = str(exc)
                raise RuntimeError(f"Repair provider request failed: {message}") from exc
            result_payload = generated["proposal"]
            provider_used, model_used = generated["provider_used"], generated["model"]
        else:
            result, provider_used = generate_with_provider(
                provider, context,
                on_event=lambda event: update_repair_operation(job_id, operation_id, event),
            )
            result_payload = result.model_dump()
            model_used = (os.getenv("GROQ_DEEP_MODEL", "openai/gpt-oss-120b") if provider == "deep"
                          else os.getenv("GROQ_MODEL", "openai/gpt-oss-120b") if provider_used == "groq"
                          else os.getenv("OLLAMA_MODEL", "qwen2.5:3b") if provider_used == "ollama"
                          else os.getenv("OPENAI_MODEL", "gpt-4.1-mini"))
        result_queue.put(("ok", result_payload, provider_used, model_used))
    except BaseException as exc:
        result_queue.put(("error", str(exc)[:500], "", ""))


def _generate_with_deadline(job_id: str, operation_id: str, provider: str, context: dict, deadline: float):
    remaining = deadline - time.time()
    if remaining <= 0:
        raise TimeoutError("Repair generation exceeded the 3-minute time limit.")
    mp = multiprocessing.get_context("fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn")
    result_queue = mp.Queue()
    process = mp.Process(target=_generate_repair_child,
                         args=(result_queue, job_id, operation_id, provider, context), daemon=True)
    process.start()
    process.join(remaining)
    if process.is_alive():
        process.terminate()
        process.join(3)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(2)
        result_queue.close()
        raise TimeoutError("Repair generation exceeded the 3-minute time limit.")
    try:
        status, payload, provider_used, model_used = result_queue.get(timeout=1)
    except queue.Empty as exc:
        raise RuntimeError("The model process stopped without returning a suggestion.") from exc
    finally:
        result_queue.close()
    if status != "ok":
        raise RuntimeError(payload)
    from providers import PatchProposal
    return PatchProposal.model_validate(payload), provider_used, model_used


def generate_repair(job_id: str, job: dict) -> None:
    operation = job.get("repair_operation") or {}
    operation_id = operation.get("id", "")
    finding_id = operation.get("finding_id", "")
    finding = next((item for item in job.get("findings", []) if item.get("id") == finding_id), None)
    source_root = (JOBS_ROOT / job_id / "source").resolve()
    candidate_root = None
    if not finding:
        update_repair_operation(job_id, operation_id, {"status": "failed", "stage": "failed", "error": "Finding no longer exists."})
        return
    target = (source_root / finding.get("file", "")).resolve()
    if not target.is_relative_to(source_root) or not target.is_file():
        update_repair_operation(job_id, operation_id, {"status": "failed", "stage": "failed", "error": "Finding source is no longer available."})
        return
    try:
        before = target.read_bytes().decode("utf-8")
        weakness = get_weakness((finding.get("cwe") or {}).get("id", ""))
        if not weakness:
            raise ValueError("CWE mapping could not be loaded.")
        context = _build_repair_context(before, finding, weakness, source_root, target)
    except Exception as exc:
        update_repair_operation(job_id, operation_id, {"status": "failed", "stage": "failed", "error": str(exc)[:500]})
        return

    attempts = list(operation.get("attempts", []))
    deadline = float(operation.get("deadline", time.time() + REPAIR_GENERATION_TIMEOUT))
    provider = "deep" if operation.get("mode") == "deep" else job.get("provider", "none")
    result = None
    provider_used = provider
    after = ""
    edits: list[dict] = []
    added = deleted = 0
    while time.time() < deadline:
        attempt = reserve_repair_attempt(job_id, operation_id)
        if not attempt:
            update_repair_operation(job_id, operation_id, {
                "status": "human_review", "stage": "human review",
                "error": "The three-suggestion limit has been reached. Review the original code and suggestions manually.",
                "attempts": attempts,
            })
            return
        update_repair_operation(job_id, operation_id, {
            "stage": "generating" if attempt == 1 else "retrying",
            "attempt": attempt,
        })
        result = None
        try:
            result, provider_used, model_used = _generate_with_deadline(job_id, operation_id, provider, context, deadline)
            if operation.get("mode") != "deep":
                provider = provider_used
            update_repair_operation(job_id, operation_id, {"stage": "checking edits", "provider": provider_used, "model": model_used})
            if result.file != finding["file"]:
                raise ValueError("invalid_path: Repair targets a different file.")
            after, edits, added, deleted = _validate_edits(
                before, [edit.model_dump() for edit in result.edits], context["scope_start"], context["scope_end"]
            )
            break
        except TimeoutError as exc:
            attempts.append({"attempt": attempt, "at": time.time(), "code": "timeout",
                             "stage": "generating", "message": "Repair generation timed out. Your original code is unchanged.",
                             "technical": str(exc), "retryable": attempt < MAX_REPAIR_ATTEMPTS, "edits": []})
            update_repair_operation(job_id, operation_id, {
                "status": "timed_out", "stage": "timed out", "attempts": attempts,
                "error": "Repair generation exceeded the 3-minute time limit. Your original code is unchanged.",
            })
            return
        except (ValueError, RuntimeError) as exc:
            detail = _rejected_attempt(exc, result, before, attempt)
            attempts.append(detail)
            exhausted = attempt >= MAX_REPAIR_ATTEMPTS
            update_repair_operation(job_id, operation_id, {
                "status": "human_review" if exhausted else "failed",
                "stage": "human review" if exhausted else "repair attempt failed",
                "attempts": attempts, "error_detail": detail, "error": detail["message"],
            })
            return
    else:
        update_repair_operation(job_id, operation_id, {
            "status": "timed_out", "stage": "timed out", "attempts": attempts,
            "error": "Repair generation exceeded the 3-minute time limit. Your original code is unchanged.",
        })
        return

    if time.time() >= deadline:
        update_repair_operation(job_id, operation_id, {
            "status": "timed_out", "stage": "timed out", "attempts": attempts,
            "error": "Repair generation exceeded the 3-minute time limit. Your original code is unchanged.",
        })
        return
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                        fromfile=f"a/{finding['file']}", tofile=f"b/{finding['file']}"))
    repair_id = str(uuid.uuid4())
    metadata = {"line": finding["line"], "scope_start_line": context["scope_start_line"],
                "scope_end_line": context["scope_end_line"], "localization": "bounded line window",
                "added_lines": added, "deleted_lines": deleted,
                "reasons": [edit["reason"] for edit in edits],
                "security_improvement": result.security_improvement,
                "warnings": ["Function boundaries were not established; scope is based on nearby lines."]}
    repair = {"id": repair_id, "finding_id": finding_id, "mode": operation.get("mode", "standard"), "file": finding["file"], "code": after,
              "diff": diff, "explanation": result.explanation, "provider_used": provider_used, "model_used": model_used,
              "state": "validating", "created_at": time.time(), "source_hash": hashlib.sha256(before.encode()).hexdigest(),
              "scope_start": context["scope_start"], "scope_end": context["scope_end"], "edits": edits,
              "metadata": metadata, "operation_id": operation_id,
              "checks": {"build": "pending", "tests": "pending", "sanitizers": "pending",
                         "security": "pending", "verification": "pending", "performance": "not_measured"}}
    repair_file = None
    try:
        candidate_root = JOBS_ROOT / job_id / "candidates" / repair_id
        candidate_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_root, candidate_root)
        candidate_target = (candidate_root / finding["file"]).resolve()
        if not candidate_target.is_relative_to(candidate_root.resolve()):
            raise ValueError("Invalid candidate path.")
        candidate_target.write_bytes(after.encode("utf-8"))
        repair["candidate_hash"] = _tree_hash(candidate_root)
        repair_dir = JOBS_ROOT / job_id / "repairs"
        repair_dir.mkdir(parents=True, exist_ok=True)
        repair_file = _repair_path(job_id, repair_id)
        repair_file.write_text(json.dumps(repair), encoding="utf-8")
        if not enqueue_repair(job_id, operation_id, repair, _proposal_summary(repair)):
            raise RuntimeError("Repair operation expired or was replaced.")
    except Exception as exc:
        if candidate_root:
            shutil.rmtree(candidate_root, ignore_errors=True)
        if repair_file:
            repair_file.unlink(missing_ok=True)
        update_repair_operation(job_id, operation_id, {
            "status": "failed", "stage": "failed", "attempts": attempts,
            "error": f"Could not prepare the repair candidate: {str(exc)[:300]}"})


def update(job_id: str, **changes) -> dict:
    job = get_job(job_id)
    if not job:
        return {}
    job.update(changes)
    save_job(job)
    return job


def safe_extract(archive_path: Path, target: Path) -> int:
    total = 0
    written = 0
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError(f"Archive has more than {MAX_FILES} entries.")
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if not name or PurePosixPath(name).is_absolute() or name.startswith("/") or ".." in parts:
                raise ValueError("Archive contains an unsafe path.")
            if any(part in SKIP_DIRS for part in parts):
                continue
            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("Archive contains a symbolic link.")
            if entry.is_dir():
                continue
            destination = (target / Path(*parts)).resolve()
            if not destination.is_relative_to(target.resolve()):
                raise ValueError("Archive contains an unsafe path.")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, destination.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_EXTRACTED:
                        raise ValueError(f"Expanded project exceeds {MAX_EXTRACTED // 1_000_000} MB.")
                    output.write(chunk)
            written += 1
    if written == 0 or not any(path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS for path in target.rglob("*")):
        raise ValueError("The ZIP archive must contain at least one C/C++ source file.")
    # ZIPs commonly wrap their contents in one top-level directory.
    children = list(target.iterdir())
    if len(children) == 1 and children[0].is_dir() and not any(path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS - {".h", ".hh", ".hpp", ".hxx"} for path in children[0].rglob("*")):
        nested = children[0]
        if any(path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS - {".h", ".hh", ".hpp", ".hxx"} for path in nested.rglob("*")):
            for child in nested.iterdir():
                shutil.move(str(child), target / child.name)
            nested.rmdir()
    return written


def _limits():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (JOB_TIMEOUT, JOB_TIMEOUT + 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def sandbox_command(command: list[str], project: Path, build: Path, extra_env: dict[str, str] | None = None) -> list[str] | None:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return None
    args = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr"]
    for path in ("/bin", "/lib", "/lib64", "/usr/local"):
        if Path(path).exists():
            args += ["--ro-bind", path, path]
    args += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--bind", str(project), "/project", "--bind", str(build), "/build", "--chdir", "/project", "--clearenv", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin"]
    for name, value in (extra_env or {}).items():
        args += ["--setenv", name, value]
    args += ["--", *command]
    return args


def _compile_database_flags(source: Path, file: Path) -> list[str]:
    database = source / "compile_commands.json"
    if not database.is_file() or database.stat().st_size > 5_000_000:
        return []
    try:
        entries = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    for entry in entries if isinstance(entries, list) else []:
        try:
            directory = Path(entry["directory"]).resolve()
            candidate = Path(entry["file"])
            candidate = (directory / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
            candidate.relative_to(source.resolve())
            if candidate != file.resolve():
                continue
            args = entry.get("arguments") or shlex.split(entry.get("command", ""))
            if not args or Path(args[0]).name not in {"clang", "clang++", "cc", "c++", "gcc", "g++"}:
                return []
            flags: list[str] = []
            index = 1
            while index < len(args):
                arg = args[index]
                if arg in {"-I", "-isystem"} and index + 1 < len(args):
                    include = Path(args[index + 1])
                    include = (directory / include).resolve() if not include.is_absolute() else include.resolve()
                    try:
                        relative = include.relative_to(source.resolve())
                        flags += [arg, "/project" if str(relative) == "." else f"/project/{relative.as_posix()}"]
                    except ValueError:
                        if include.is_relative_to(Path("/usr")):
                            flags += [arg, str(include)]
                    index += 2
                    continue
                if arg.startswith(("-D", "-U", "-std=", "-W", "-f", "-m")) or arg in {"-pthread", "-ansi"}:
                    flags.append(arg)
                index += 1
            return flags
        except (KeyError, OSError, TypeError, ValueError):
            continue
    return []


def _diagnostic_category(message: str, missing_header: str | None = None) -> str:
    if missing_header:
        return "missing_system_header" if Path(missing_header).name in SYSTEM_HEADERS else "missing_project_dependency"
    lower = message.lower()
    if any(token in lower for token in ("expected ", "unexpected ", "unterminated", "extraneous", "invalid preprocessing directive", "before '")):
        return "syntax_error"
    if any(token in lower for token in ("undeclared", "unknown type name", "not declared", "no member named", "incompatible", "cannot initialize", "no matching")):
        return "type_error"
    return "compiler_error"


def _parse_compiler_diagnostics(output: str, source: Path, source_name: str) -> list[dict]:
    diagnostics = []
    pattern = re.compile(r"^(.*?):(\d+):(\d+): (?:fatal )?error: (.*)$")
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        location, row, column, message = match.groups()
        header = re.search(r"['\"]([^'\"]+)['\"] file not found", message)
        try:
            normalized = Path(location.removeprefix("/project/")).as_posix()
            if location.startswith("/project/"):
                normalized = Path(location[len("/project/"):]).as_posix()
        except (OSError, ValueError):
            normalized = location
        diagnostics.append({"category": _diagnostic_category(message, header.group(1) if header else None),
                            "file": normalized, "line": int(row), "column": int(column),
                            "message": message, "source": source_name})
    return diagnostics


def _syntax_check(source: Path, build: Path, source_name: str = "original") -> dict:
    files = sorted(path for path in source.rglob("*") if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"})
    if not files:
        return {"build": "not_available", "diagnostics": [], "details": "No C/C++ translation units were found for a syntax check."}
    if not shutil.which("clang"):
        return {"build": "not_available", "diagnostics": [{"category": "toolchain_unavailable", "file": "", "line": 0, "column": 0, "message": "Clang is not installed.", "source": source_name}], "details": "Syntax check unavailable: Clang is not installed."}
    if not sandbox_command(["/bin/true"], source, build):
        return {"build": "not_available", "diagnostics": [{"category": "toolchain_unavailable", "file": "", "line": 0, "column": 0, "message": "bubblewrap is not installed.", "source": source_name}], "details": "Syntax check unavailable: bubblewrap is not installed."}
    diagnostics = []
    outputs = []
    deadline = time.monotonic() + 45
    limited = len(files) > 80
    for file in files[:80]:
        if time.monotonic() >= deadline:
            limited = True
            break
        relative = file.resolve().relative_to(source.resolve()).as_posix()
        compiler = "clang++" if file.suffix.lower() in {".cc", ".cpp", ".cxx"} else "clang"
        # Keep the source path as the final argument and apply only safe, project-local compile flags.
        command = [compiler, "-fsyntax-only", "-fno-color-diagnostics", "-I", "/project"]
        parent = file.parent.relative_to(source).as_posix()
        if parent != ".":
            command += ["-I", f"/project/{parent}"]
        command += _compile_database_flags(source, file)
        command.append(f"/project/{relative}")
        wrapped = sandbox_command(command, source, build)
        try:
            result = subprocess.run(wrapped or [], capture_output=True, text=True, timeout=min(5, max(1, deadline-time.monotonic())), check=False, preexec_fn=_limits)
            output = result.stderr + "\n" + result.stdout
            outputs.append(output.strip())
            file_diagnostics = _parse_compiler_diagnostics(output, source, source_name)
            diagnostics.extend(file_diagnostics)
            if result.returncode and not file_diagnostics:
                diagnostics.append({"category": "compiler_error", "file": relative, "line": 0, "column": 0,
                                    "message": f"Compiler exited with status {result.returncode} without a recognized diagnostic.", "source": source_name})
        except subprocess.TimeoutExpired:
            diagnostics.append({"category": "toolchain_unavailable", "file": relative, "line": 0, "column": 0,
                                "message": "Syntax check exceeded its per-file time limit.", "source": source_name})
        except OSError as exc:
            diagnostics.append({"category": "toolchain_unavailable", "file": relative, "line": 0, "column": 0,
                                "message": str(exc)[:500], "source": source_name})
    errors = [item for item in diagnostics if item["category"] not in {"missing_project_dependency", "missing_system_header", "toolchain_unavailable"}]
    missing = [item for item in diagnostics if item["category"] in {"missing_project_dependency", "missing_system_header"}]
    toolchain = [item for item in diagnostics if item["category"] == "toolchain_unavailable"]
    status = "failed" if errors else "not_available" if missing or toolchain or limited else "passed"
    details = "\n".join(output for output in outputs if output)[-6000:]
    if limited:
        details += "\nSyntax check limited to 80 files or 45 seconds."
    if not details and status == "passed":
        details = "Clang syntax checks passed."
    return {"build": status, "diagnostics": diagnostics, "details": details}


def validate_build(job_dir: Path, source: Path, on_check=None, baseline_source: Path | None = None) -> dict:
    def report(name, status):
        if on_check:
            on_check(name, status)
    build = job_dir / "validation-build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir()
    result = {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "performance": "not_measured", "details": "No recognized build system found.", "build_diagnostics": []}
    command = None
    tests = None
    if (source / "CMakeLists.txt").is_file():
        command = ["cmake", "-S", "/project", "-B", "/build", "-DCMAKE_BUILD_TYPE=Debug"]
        tests = ["ctest", "--test-dir", "/build", "--output-on-failure"]
    elif (source / "Makefile").is_file() or (source / "makefile").is_file():
        command = ["make", "-j1"]
        makefile = source / ("Makefile" if (source / "Makefile").is_file() else "makefile")
        if "test:" in makefile.read_text(encoding="utf-8", errors="replace"):
            tests = ["make", "test"]
    if not command:
        if on_check:
            on_check("build", "running")
        candidate = _syntax_check(source, build, "proposed" if baseline_source else "original")
        diagnostics = list(candidate["diagnostics"])
        status = candidate["build"]
        details = candidate["details"]
        if baseline_source:
            baseline = _syntax_check(baseline_source, build, "original")
            diagnostics = baseline["diagnostics"] + diagnostics
            candidate_missing = [item for item in candidate["diagnostics"] if item["category"] in {"missing_project_dependency", "missing_system_header"}]
            baseline_missing = {(item["category"], item["file"], item["message"]) for item in baseline["diagnostics"] if item["category"] in {"missing_project_dependency", "missing_system_header"}}
            introduced_missing = any((item["category"], item["file"], item["message"]) not in baseline_missing for item in candidate_missing)
            shared_missing = bool(candidate_missing) and not introduced_missing
            candidate_errors = [item for item in candidate["diagnostics"] if item["category"] in {"syntax_error", "type_error", "compiler_error"}]
            if candidate_errors or introduced_missing:
                status = "failed"
            elif candidate_missing or candidate["build"] == "not_available" or baseline["build"] == "not_available":
                status = "not_available"
            else:
                status = candidate["build"]
            details = "Original source:\n" + baseline["details"] + "\nProposed source:\n" + candidate["details"]
            result["baseline_shared_dependency"] = shared_missing and not candidate_errors
        result.update(build=status, build_diagnostics=diagnostics, details=details)
        if on_check:
            on_check("build", status)
        return result
    result["details"] = "Build scripts run only inside bubblewrap with separate network, process, and filesystem namespaces."
    wrapped = sandbox_command(command, source, build)
    if not wrapped:
        result["details"] = "Build/test checks unavailable: bubblewrap is not installed."
        return result
    try:
        probe = sandbox_command(["/bin/true"], source, build)
        probe_result = subprocess.run(probe or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
        if probe_result.returncode != 0:
            logging.warning("Build sandbox unavailable: %s", (probe_result.stderr or probe_result.stdout)[-1000:])
            result["details"] = "Build verification unavailable: the server could not start its isolated build environment."
            return result
        report("build", "running")
        build_result = subprocess.run(wrapped, capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
        result["build"] = "passed" if build_result.returncode == 0 else "failed"
        result["details"] = (build_result.stderr or build_result.stdout)[-3000:]
        result["build_diagnostics"] = _parse_compiler_diagnostics(build_result.stderr + "\n" + build_result.stdout, source, "proposed")
        if build_result.returncode != 0:
            return result
        if command[0] == "cmake":
            wrapped_compile = sandbox_command(["cmake", "--build", "/build", "--parallel", "1"], source, build)
            compile_result = subprocess.run(wrapped_compile or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
            result["details"] += "\nBuild:\n" + (compile_result.stderr or compile_result.stdout)[-3000:]
            result["build_diagnostics"] += _parse_compiler_diagnostics(compile_result.stderr + "\n" + compile_result.stdout, source, "proposed")
            if compile_result.returncode != 0:
                result["build"] = "failed"
                return result
        report("build", "passed")
        result["tests"] = "not_available"
        if tests and tests[0] == "ctest" and not list(build.rglob("CTestTestfile.cmake")):
            tests = None
        if tests and tests[0] == "ctest":
            listing_command = sandbox_command(["ctest", "--test-dir", "/build", "--show-only=json-v1"], source, build)
            listing = subprocess.run(listing_command or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
            try:
                discovered = json.loads(listing.stdout).get("tests", []) if listing.returncode == 0 else []
            except (ValueError, AttributeError):
                discovered = []
            if not discovered:
                tests = None
                result["details"] += "\nNo CTest tests were discovered."
        if tests:
            report("tests", "running")
            wrapped_tests = sandbox_command(tests, source, build)
            test_result = subprocess.run(wrapped_tests or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
            result["tests"] = "passed" if test_result.returncode == 0 else "failed"
            result["details"] += "\n" + (test_result.stderr or test_result.stdout)[-3000:]
        report("tests", result["tests"])
        if command[0] == "cmake" and result["tests"] == "passed":
            report("sanitizers", "running")
            sanitizer_build = job_dir / "sanitizer-build"
            if sanitizer_build.exists():
                shutil.rmtree(sanitizer_build)
            sanitizer_build.mkdir()
            flags = "-fsanitize=address,undefined -fno-omit-frame-pointer"
            sanitizer_command = [
                "cmake", "-S", "/project", "-B", "/build", "-DCMAKE_BUILD_TYPE=Debug",
                f"-DCMAKE_C_FLAGS={flags}", f"-DCMAKE_CXX_FLAGS={flags}",
                "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined",
                "-DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address,undefined",
            ]
            sanitizer_env = {"ASAN_OPTIONS": "detect_leaks=0", "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1"}
            wrapped_sanitizers = sandbox_command(sanitizer_command, source, sanitizer_build, sanitizer_env)
            sanitizer_build_result = subprocess.run(wrapped_sanitizers or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
            if sanitizer_build_result.returncode == 0:
                sanitizer_compile = sandbox_command(["cmake", "--build", "/build", "--parallel", "1"], source, sanitizer_build, sanitizer_env)
                sanitizer_build_result = subprocess.run(sanitizer_compile or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
            if sanitizer_build_result.returncode == 0:
                sanitizer_tests = sandbox_command(["ctest", "--test-dir", "/build", "--output-on-failure"], source, sanitizer_build, sanitizer_env)
                sanitizer_test_result = subprocess.run(sanitizer_tests or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
                result["sanitizers"] = "passed" if sanitizer_test_result.returncode == 0 else "failed"
                result["details"] += "\nSanitizer checks:\n" + (sanitizer_test_result.stderr or sanitizer_test_result.stdout)[-2000:]
            else:
                result["sanitizers"] = "failed"
                result["details"] += "\nSanitizer build:\n" + (sanitizer_build_result.stderr or sanitizer_build_result.stdout)[-2000:]
    except subprocess.TimeoutExpired:
        result.update(build="failed", details="Build/test command exceeded the time limit.")
    except OSError as exc:
        result.update(build="failed", details=f"Could not run isolated validation: {exc}")
    return result


def verify_repair_security(source: Path, job: dict) -> dict:
    repair = job.get("repair") or {}
    target = next((item for item in job.get("findings", []) if item.get("id") == repair.get("finding_id")), None)
    if not target:
        return {"status": "unverified", "details": "The original finding is unavailable for comparison."}

    report = analyze(source)
    original_cwe = (target.get("cwe") or {}).get("id")
    candidates = [item for item in report.get("findings", [])
        if item.get("file") == target.get("file")
        and item.get("rule_id") == target.get("rule_id")
        and (item.get("cwe") or {}).get("id") == original_cwe]
    original_peers = [item for item in job.get("findings", [])
        if item.get("file") == target.get("file") and item.get("rule_id") == target.get("rule_id")
        and (item.get("cwe") or {}).get("id") == original_cwe]
    if candidates:
        if len(original_peers) <= 1:
            return {"status": "failed", "details": "A matching target finding remains after the repair."}
        target_line = target.get("line")
        if not isinstance(target_line, int) or any(not isinstance(item.get("line"), int) for item in candidates + original_peers):
            return {"status": "unverified", "details": "Multiple matching findings cannot be distinguished by location."}
        def adjusted(line):
            for edit in sorted(repair.get("edits", []), key=lambda e: e.get("line", 0)):
                if edit.get("line", 0) < line:
                    line += edit["replacement"].count("\n") - edit["original"].count("\n")
            return line
        target_adjusted = adjusted(target_line)
        for item in candidates:
            distances = sorted((abs(item["line"] - adjusted(peer["line"])), peer.get("id")) for peer in original_peers)
            if len(distances) > 1 and distances[0][0] == distances[1][0]:
                return {"status": "unverified", "details": "Matching findings have ambiguous locations after the repair."}
            if distances[0][1] == target.get("id") or item["line"] == target_adjusted:
                return {"status": "failed", "details": "The target finding remains after the repair."}

    def key(item: dict) -> tuple:
        return item.get("file"), item.get("rule_id"), (item.get("cwe") or {}).get("id"), item.get("message")

    original_counts: dict[tuple, int] = {}
    for item in job.get("findings", []):
        identity = key(item)
        original_counts[identity] = original_counts.get(identity, 0) + 1
    patched_counts: dict[tuple, int] = {}
    for item in report.get("findings", []):
        identity = key(item)
        patched_counts[identity] = patched_counts.get(identity, 0) + 1
    new_findings = sum(max(0, count - original_counts.get(identity, 0)) for identity, count in patched_counts.items())
    if new_findings:
        return {"status": "failed", "details": f"The patched scan reported {new_findings} new finding(s)."}
    if report.get("scan_status") != "COMPLETED":
        return {"status": "unverified", "details": "One or more analyzers did not complete successfully."}
    return {"status": "passed", "details": "The target finding is absent and no new findings were reported."}


def run_benchmark(source: Path, build: Path) -> dict | None:
    manifest_path = source / ".patchguard" / "benchmark.json"
    if not manifest_path.is_file() or manifest_path.stat().st_size > 16_000:
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        command = manifest["command"]
        runs = int(manifest.get("runs", 3))
        if not isinstance(command, list) or not command or len(command) > 32 or not all(isinstance(arg, str) and "\x00" not in arg for arg in command) or not 2 <= runs <= 5:
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    wrapped = sandbox_command(command, source, build)
    if not wrapped:
        return None
    samples = []
    try:
        for _ in range(runs):
            start = time.perf_counter()
            result = subprocess.run(wrapped, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25, check=False, preexec_fn=_limits)
            if result.returncode:
                return None
            samples.append((time.perf_counter() - start) * 1000)
    except (OSError, subprocess.TimeoutExpired):
        return None
    samples.sort()
    return {"median_ms": round(statistics.median(samples), 2), "samples_ms": [round(item, 2) for item in samples], "runs": runs}


def clean_expired() -> None:
    now = time.time()
    delete_expired_jobs()
    for path in JOBS_ROOT.iterdir():
        if not path.is_dir():
            continue
        try:
            created_at = float((path / ".created").read_text(encoding="ascii"))
        except (OSError, ValueError):
            created_at = path.stat().st_mtime
        if created_at + JOB_TTL <= now:
            shutil.rmtree(path, ignore_errors=True)


def process(job_id: str) -> None:
    job_dir = JOBS_ROOT / job_id
    original = job_dir / "upload.zip"
    source = job_dir / "source"
    try:
        job = get_job(job_id) or {}
        update(job_id, state="analyzing", progress="Preparing source")
        if job.get("upload_kind") == "source":
            source.mkdir(parents=True, exist_ok=True)
            uploaded = job_dir / "upload-source" / job.get("upload_filename", "")
            if not uploaded.is_file():
                raise ValueError("Uploaded source file is missing.")
            shutil.move(str(uploaded), source / uploaded.name)
        elif job.get("upload_kind") == "project":
            shutil.copytree(job_dir / "upload-source", source)
            shutil.rmtree(job_dir / "upload-source", ignore_errors=True)
        else:
            safe_extract(original, source)
            original.unlink(missing_ok=True)
        progress = "Running Clang, Cppcheck, and Semgrep" if ANALYSIS_MODE == "legacy" else f"Running PatchGuard {ANALYSIS_MODE} analysis with Clang, Cppcheck, and Semgrep"
        update(job_id, progress=progress)
        report = run_analysis(source, ANALYSIS_MODE)
        update(job_id, progress="Checking project build and tests")
        validation_source = job_dir / "validation-source"
        shutil.copytree(source, validation_source)
        checks = validate_build(job_dir, validation_source)
        baseline = run_benchmark(validation_source, job_dir / "validation-build") if checks["build"] == "passed" else None
        shutil.rmtree(validation_source, ignore_errors=True)
        if baseline:
            checks["performance"] = "baseline_ready"
        report.update({"taxonomy_version": "5.0", "schema_version": "8.0", "checks": checks, "performance_baseline": baseline, "evaluated_at": time.time()})
        progress = "Scan complete" if report["scan_status"] == "COMPLETED" else f"Scan {report['scan_status'].lower()}: review analyzer status"
        update(job_id, state="complete", progress=progress, findings=report["findings"], report=report, checks=checks, performance_baseline=baseline, source_files=report["source_files"])
    except Exception as exc:
        update(job_id, state="failed", progress="Scan failed", error=str(exc)[:500])


def validate_repair(job_id: str, job: dict | None = None) -> None:
    job = job or get_job(job_id) or {}
    if not job or not job.get("repair"):
        return
    operation_id = (job.get("repair_operation") or {}).get("id", "")
    candidate_id = job["repair"]["id"]
    stop = threading.Event()
    def heartbeat():
        while not stop.wait(20):
            try:
                if not update_repair_operation(job_id, operation_id, {"lease_until": time.time() + 120}):
                    return
            except Exception:
                logging.exception("Verification heartbeat failed")
    heart = threading.Thread(target=heartbeat, daemon=True)
    heart.start()
    check_states = {key: "pending" for key in ("build", "tests", "sanitizers", "security")}
    def report(name, status):
        check_states[name] = status
        stage = {"build": "building", "tests": "testing", "sanitizers": "sanitizer checks", "security": "security rescan"}[name]
        if not update_repair_operation(job_id, operation_id, {"stage": stage, "check_states": dict(check_states), "lease_until": time.time() + 120}):
            raise RuntimeError("Verification operation expired or was replaced.")
    workspace = None
    try:
        job_dir = JOBS_ROOT / job_id
        workspace = Path(tempfile.mkdtemp(prefix="verification-", dir=job_dir))
        validation_source = workspace / "source"
        candidate = job_dir / "candidates" / candidate_id
        shutil.copytree(candidate, validation_source)
        if not update_repair_operation(job_id, operation_id, {"status": "verifying", "stage": "preparing verification", "lease_until": time.time() + 120}):
            return
        baseline_source = workspace / "baseline-source"
        original_source = job_dir / "source"
        if original_source.is_dir():
            shutil.copytree(original_source, baseline_source)
            checks = validate_build(workspace, validation_source, on_check=report, baseline_source=baseline_source)
            shutil.rmtree(baseline_source, ignore_errors=True)
        else:
            checks = validate_build(workspace, validation_source, on_check=report)
        baseline_diagnostics = (job.get("checks") or {}).get("build_diagnostics", [])
        candidate_diagnostics = [item for item in checks.get("build_diagnostics", []) if item.get("source") == "proposed"]
        dependency_categories = {"missing_project_dependency", "missing_system_header"}
        baseline_dependencies = {(item.get("category"), item.get("file"), item.get("message")) for item in baseline_diagnostics if item.get("category") in dependency_categories}
        candidate_dependencies = [item for item in candidate_diagnostics if item.get("category") in dependency_categories]
        candidate_compile_errors = [item for item in candidate_diagnostics if item.get("category") in {"syntax_error", "type_error", "compiler_error"}]
        shared_missing_dependency = bool(candidate_dependencies) and not candidate_compile_errors and all((item.get("category"), item.get("file"), item.get("message")) in baseline_dependencies for item in candidate_dependencies)
        checks["baseline_shared_dependency"] = bool(checks.get("baseline_shared_dependency") or shared_missing_dependency)
        if checks.get("build") == "failed" and shared_missing_dependency:
            checks["build"] = "not_available"
            checks["details"] = (checks.get("details", "") + "\nThe same missing dependency prevents compiling the original and proposed source.").strip()
        for key in ("build", "tests", "sanitizers"):
            report(key, checks[key])
        shutil.rmtree(validation_source, ignore_errors=True)
        shutil.copytree(candidate, validation_source)
        report("security", "running")
        security = verify_repair_security(validation_source, job)
        checks["security"] = security["status"]
        checks["security_details"] = security["details"]
        report("security", security["status"])
        patched_benchmark = run_benchmark(validation_source, workspace / "validation-build") if checks["build"] == "passed" else None
        shutil.rmtree(validation_source, ignore_errors=True)
        baseline = job.get("performance_baseline")
        performance = None
        if baseline and patched_benchmark:
            delta = round((patched_benchmark["median_ms"] - baseline["median_ms"]) / baseline["median_ms"] * 100, 2) if baseline["median_ms"] else None
            performance = {"baseline_median_ms": baseline["median_ms"], "patched_median_ms": patched_benchmark["median_ms"], "delta_percent": delta, "baseline_samples_ms": baseline["samples_ms"], "patched_samples_ms": patched_benchmark["samples_ms"]}
            checks["performance"] = "measured"
        elif baseline:
            checks["performance"] = "not_available"
        required_checks = ("build", "tests", "sanitizers", "security")
        checks["verification"] = (
            "failed" if any(checks.get(name) == "failed" for name in required_checks)
            else "passed" if all(checks.get(name) == "passed" for name in required_checks)
            else "unverified"
        )
        available = [checks.get(name) for name in required_checks]
        checks["verification_outcome"] = (
            "failed" if "failed" in available else
            "verified" if all(value == "passed" for value in available) else
            "partially_verified" if "passed" in available or (checks.get("baseline_shared_dependency") and checks.get("build") == "not_available") else "not_verified"
        )
        finish_repair(job_id, operation_id, candidate_id, checks, performance)
    except Exception as exc:
        logging.exception("Candidate verification interrupted: %s", candidate_id)
        checks = {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "security": "unverified", "verification": "unverified", "verification_outcome": "not_verified", "performance": "not_measured", "details": "Verification could not finish. Retry the repair."}
        finish_repair(job_id, operation_id, candidate_id, checks, error="Verification could not finish. Your original code is unchanged.")
    finally:
        stop.set()
        heart.join(timeout=6)
        if workspace:
            shutil.rmtree(workspace, ignore_errors=True)


def main() -> None:
    last_cleanup = 0.0
    retry_delay = 5
    while True:
        try:
            recover_repairs()
            repair_item = claim_repair_generation()
            item = None if repair_item else claim_job()
        except Exception as exc:
            message = str(exc).splitlines()[0]
            logging.error(
                "Supabase queue check failed; retrying in %ss: %s. "
                "For IPv4-only Docker, use the Supabase session-pooler URL on port 5432.",
                retry_delay,
                message,
            )
            time.sleep(retry_delay)
            retry_delay = min(60, retry_delay * 2)
            continue
        retry_delay = 5
        if repair_item:
            job_id, job = repair_item
            try:
                generate_repair(job_id, job)
            except Exception as exc:
                logging.exception("Repair generation for job %s failed unexpectedly", job_id)
                try:
                    operation = (get_job(job_id) or {}).get("repair_operation") or {}
                    if operation.get("status") in ("queued", "running"):
                        update_repair_operation(job_id, operation.get("id", ""), {
                            "status": "failed", "stage": "failed",
                            "error": f"Repair generation stopped unexpectedly: {str(exc)[:300]}",
                        })
                except Exception:
                    logging.exception("Could not save repair failure for job %s", job_id)
        elif item:
            job_id, job = item
            try:
                if job.get("state") in ("validating", "verifying"):
                    validate_repair(job_id, job)
                else:
                    process(job_id)
            except Exception:
                logging.exception("Job %s failed unexpectedly", job_id)
        else:
            time.sleep(2)
        if time.time() - last_cleanup > 60:
            try:
                clean_expired()
            except Exception:
                logging.exception("Expired-job cleanup failed")
            last_cleanup = time.time()


if __name__ == "__main__":
    main()
