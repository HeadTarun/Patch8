from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import subprocess
import statistics
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath

from db import claim_job, delete_expired_jobs, get_job, save_job
from analysis_pipeline import run_analysis, validate_analysis_mode
from scanner import analyze

WORK_ROOT = Path(os.getenv("WORK_ROOT", str(Path(tempfile.gettempdir()) / "patchguard")))
JOBS_ROOT = WORK_ROOT / "jobs"
JOB_TTL = int(os.getenv("JOB_TTL_SECONDS", "3600"))
MAX_FILES = int(os.getenv("MAX_PROJECT_FILES", "5000"))
MAX_EXTRACTED = int(os.getenv("MAX_EXTRACTED_BYTES", "100000000"))
JOB_TIMEOUT = int(os.getenv("JOB_TIMEOUT_SECONDS", "90"))
ANALYSIS_MODE = validate_analysis_mode(os.getenv("ANALYSIS_MODE", "legacy"))
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".idea", ".vscode"}
JOBS_ROOT.mkdir(parents=True, exist_ok=True)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


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
    if written == 0 or not any(path.is_file() and path.suffix.lower() in {".c", ".cpp", ".h"} for path in target.rglob("*")):
        raise ValueError("The ZIP archive must contain at least one .c, .cpp, or .h source file.")
    # ZIPs commonly wrap their contents in one top-level directory.
    children = list(target.iterdir())
    if len(children) == 1 and children[0].is_dir() and not any(children[0].glob("*.c")):
        nested = children[0]
        if any(nested.rglob("*.c")) or any(nested.rglob("*.cpp")):
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


def validate_build(job_dir: Path, source: Path) -> dict:
    build = job_dir / "validation-build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir()
    result = {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "performance": "not_measured", "details": "No recognized build system found."}
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
        return result
    result["details"] = "Build scripts run only inside bubblewrap with separate network, process, and filesystem namespaces."
    wrapped = sandbox_command(command, source, build)
    if not wrapped:
        result["details"] = "Build/test checks unavailable: bubblewrap is not installed."
        return result
    try:
        build_result = subprocess.run(wrapped, capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
        result["build"] = "passed" if build_result.returncode == 0 else "failed"
        result["details"] = (build_result.stderr or build_result.stdout)[-3000:]
        if build_result.returncode != 0:
            return result
        result["tests"] = "not_available"
        if tests and tests[0] == "ctest" and not list(build.rglob("CTestTestfile.cmake")):
            tests = None
        if tests:
            wrapped_tests = sandbox_command(tests, source, build)
            test_result = subprocess.run(wrapped_tests or [], capture_output=True, text=True, timeout=JOB_TIMEOUT, check=False, preexec_fn=_limits)
            result["tests"] = "passed" if test_result.returncode == 0 else "failed"
            result["details"] += "\n" + (test_result.stderr or test_result.stdout)[-3000:]
        if command[0] == "cmake" and result["tests"] == "passed":
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
    target_remains = any(
        item.get("file") == target.get("file")
        and item.get("rule_id") == target.get("rule_id")
        and (item.get("cwe") or {}).get("id") == original_cwe
        for item in report.get("findings", [])
    )
    if target_remains:
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
    try:
        job_dir = JOBS_ROOT / job_id
        validation_source = job_dir / "patched-validation-source"
        shutil.rmtree(validation_source, ignore_errors=True)
        shutil.copytree(job_dir / "patched", validation_source)
        checks = validate_build(job_dir, validation_source)
        security = verify_repair_security(validation_source, job)
        checks["security"] = security["status"]
        checks["security_details"] = security["details"]
        patched_benchmark = run_benchmark(validation_source, job_dir / "validation-build") if checks["build"] == "passed" else None
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
        job["checks"] = checks
        job["performance"] = performance
        job["repair"]["checks"] = checks
        job["repair"]["state"] = "applied_to_copy"
        job["state"] = "complete"
        job["progress"] = f"Patch verification {checks['verification']}"
        save_job(job)
    except Exception as exc:
        job["state"] = "complete"
        job["progress"] = "Patch applied; validation failed to run"
        job["checks"] = {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "security": "unverified", "security_details": str(exc)[:1000], "verification": "unverified", "performance": "not_measured", "details": str(exc)[:1000]}
        job["performance"] = None
        job["repair"]["checks"] = job["checks"]
        job["repair"]["state"] = "applied_to_copy"
        save_job(job)


def main() -> None:
    last_cleanup = 0.0
    retry_delay = 5
    while True:
        try:
            item = claim_job()
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
        if item:
            job_id, job = item
            try:
                if job.get("state") == "validating":
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
