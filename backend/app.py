from __future__ import annotations

import difflib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from db import get_job, save_job
from providers import generate
from scanner import sarif_report
from taxonomy import catalog, get_weakness, supported_weaknesses

WORK_ROOT = Path(os.getenv("WORK_ROOT", str(Path(tempfile.gettempdir()) / "patchguard")))
JOBS_ROOT = WORK_ROOT / "jobs"
JOBS_ROOT.mkdir(parents=True, exist_ok=True)
JOB_TTL = int(os.getenv("JOB_TTL_SECONDS", "3600"))
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_BYTES", "25000000"))
MAX_FILES = int(os.getenv("MAX_PROJECT_FILES", "5000"))
MAX_EXTRACTED = int(os.getenv("MAX_EXTRACTED_BYTES", "100000000"))
MAX_SOURCE = int(os.getenv("MAX_SOURCE_BYTES", "200000"))
SOURCE_EXTENSIONS = {".c", ".cpp", ".h"}
app = FastAPI(title="PatchGuard IoT", version="0.1.0", docs_url=None, redoc_url=None)


def _job_key(job_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f-]{36}", job_id):
        raise HTTPException(404, "Job not found")
    return job_id


def _read_job(job_id: str) -> dict:
    job = get_job(_job_key(job_id))
    if not job:
        raise HTTPException(404, "This job has expired or does not exist.")
    return job


def _save_job(job: dict) -> None:
    save_job(job)


def _repair_path(job_id: str, repair_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f-]{36}", repair_id):
        raise HTTPException(404, "Repair proposal not found.")
    return JOBS_ROOT / job_id / "repairs" / f"{repair_id}.json"


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "taxonomy_version": catalog()["version"], "analyzers": ["Clang Static Analyzer", "Cppcheck", "Semgrep"]}


@app.get("/api/weaknesses")
def weaknesses() -> dict:
    data = catalog()
    return {"version": data["version"], "schema": data["schema"], "items": supported_weaknesses()}


@app.post("/api/jobs", status_code=202)
async def create_job(file: UploadFile = File(...), provider: str = Form("none")) -> dict:
    if provider not in {"none", "hosted", "ollama"}:
        raise HTTPException(400, "Choose scan only, hosted, or ollama.")
    name = Path((file.filename or "firmware.zip").replace("\\", "/")).name
    suffix = Path(name).suffix.lower()
    if suffix not in {".zip", ".c", ".cpp"}:
        raise HTTPException(415, "Upload a ZIP project, .c file, or .cpp file. Header files must be inside a ZIP project.")
    job_id = str(uuid.uuid4())
    job_dir = JOBS_ROOT / job_id
    job_dir.mkdir(parents=True)
    created_at = time.time()
    (job_dir / ".created").write_text(str(created_at), encoding="ascii")
    zip_path = job_dir / "upload.zip"
    source_path = job_dir / "upload-source" / name
    if suffix in {".c", ".cpp"}:
        source_path.parent.mkdir(parents=True)
    total = 0
    try:
        target_path = zip_path if suffix == ".zip" else source_path
        with target_path.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                limit = MAX_UPLOAD if suffix == ".zip" else MAX_SOURCE
                if total > limit:
                    if suffix != ".zip":
                        raise HTTPException(413, f"Source file exceeds the {MAX_SOURCE // 1000} KB limit.")
                    raise HTTPException(413, f"Upload exceeds the {MAX_UPLOAD // 1_000_000} MB limit.")
                output.write(chunk)
        if suffix in {".c", ".cpp"}:
            source_bytes = source_path.read_bytes()
            if not source_bytes:
                raise HTTPException(400, "The source file is empty.")
            try:
                source_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HTTPException(400, "The source file must use UTF-8 encoding.") from exc
        else:
            with zipfile.ZipFile(zip_path) as archive:
                entries = archive.infolist()
                if not entries:
                    raise HTTPException(400, "The ZIP archive is empty.")
                if len(entries) > MAX_FILES:
                    raise HTTPException(413, f"Archive exceeds the {MAX_FILES} entry limit.")
                expanded_size = 0
                source_count = 0
                for entry in entries:
                    name_in_archive = entry.filename.replace("\\", "/")
                    parts = PurePosixPath(name_in_archive).parts
                    if not name_in_archive or PurePosixPath(name_in_archive).is_absolute() or name_in_archive.startswith("/") or ".." in parts:
                        raise HTTPException(400, "Archive contains an unsafe path.")
                    if stat.S_ISLNK(entry.external_attr >> 16):
                        raise HTTPException(400, "Symbolic links are not accepted in uploaded archives.")
                    expanded_size += entry.file_size
                    if expanded_size > MAX_EXTRACTED:
                        raise HTTPException(413, f"Expanded project exceeds the {MAX_EXTRACTED // 1_000_000} MB limit.")
                    if not entry.is_dir() and PurePosixPath(name_in_archive).suffix.lower() in SOURCE_EXTENSIONS:
                        source_count += 1
                        if entry.file_size == 0:
                            raise HTTPException(400, f"Source file {PurePosixPath(name_in_archive).name} is empty.")
                        try:
                            with archive.open(entry) as source:
                                source.read().decode("utf-8")
                        except UnicodeDecodeError as exc:
                            raise HTTPException(400, f"Source file {PurePosixPath(name_in_archive).name} must use UTF-8 encoding.") from exc
                if not source_count:
                    raise HTTPException(400, "The ZIP archive must contain at least one .c, .cpp, or .h source file.")
    except (zipfile.BadZipFile, OSError) as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(400, "Could not read this ZIP archive.") from exc
    except HTTPException:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise
    finally:
        await file.close()

    job = {
        "id": job_id,
        "name": name,
        "provider": provider,
        "upload_kind": "zip" if suffix == ".zip" else "source",
        "upload_filename": name,
        "state": "queued",
        "created_at": created_at,
        "expires_at": created_at + JOB_TTL,
        "findings": [],
        "checks": {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "performance": "not_measured"},
    }
    _save_job(job)
    return {"id": job_id, "state": "queued", "expires_in_seconds": JOB_TTL}


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> dict:
    return _read_job(job_id)


@app.post("/api/jobs/{job_id}/repair/{finding_id}")
def create_repair(job_id: str, finding_id: str) -> dict:
    job = _read_job(job_id)
    if job["state"] != "complete":
        raise HTTPException(409, "Wait for the scan to finish before generating a repair.")
    if job["provider"] == "none":
        raise HTTPException(409, "Select a repair provider before requesting a patch.")
    finding = next((item for item in job.get("findings", []) if item["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    if not finding.get("cwe"):
        raise HTTPException(409, "Suspicious candidates need manual review and do not support automated repair.")
    source_root = JOBS_ROOT / job_id / "source"
    target = (source_root / finding["file"]).resolve()
    if not target.is_relative_to(source_root.resolve()) or not target.is_file():
        raise HTTPException(400, "Finding source is no longer available.")
    if target.stat().st_size > 200_000:
        raise HTTPException(413, "This file is too large for one repair request.")
    before = target.read_text(encoding="utf-8", errors="replace")
    cwe = get_weakness(finding["cwe"]["id"])
    if not cwe:
        raise HTTPException(400, "CWE mapping could not be loaded.")
    prompt = (
        f"Repair this C/C++ firmware finding with the smallest safe change.\n\n"
        f"Finding: {finding['message']}\nCWE: {cwe['id']} — {cwe['name']}\n"
        f"CWE description: {cwe['description']}\n"
        f"CWE mapping-use guidance: {cwe['mapping_usage']}\n"
        f"CWE mitigations: {' '.join(cwe['mitigations'][:2])}\n"
        f"Mapping confidence: {finding['mapping_confidence']}\n"
        f"File path: {finding['file']}\nLine: {finding['line']}\n"
        "Return JSON with keys file, code, explanation. The file value must exactly match the provided path.\n\n"
        f"Current file content:\n{before[:24000]}"
    )
    try:
        result = json.loads(generate(job["provider"], prompt))
    except (RuntimeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(502, str(exc)) from exc
    if result.get("file") != finding["file"] or not isinstance(result.get("code"), str):
        raise HTTPException(502, "The repair response did not match the requested file.")
    after = result["code"]
    if len(after) > 300_000 or after == before:
        raise HTTPException(422, "The model returned no usable source change.")
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"a/{finding['file']}", tofile=f"b/{finding['file']}"))
    repair_id = str(uuid.uuid4())
    repair = {"id": repair_id, "finding_id": finding_id, "file": finding["file"], "code": after, "diff": diff, "explanation": str(result.get("explanation", ""))[:2000], "state": "proposed", "created_at": time.time()}
    repair_dir = JOBS_ROOT / job_id / "repairs"
    repair_dir.mkdir(parents=True, exist_ok=True)
    _repair_path(job_id, repair_id).write_text(json.dumps(repair), encoding="utf-8")
    return {key: repair[key] for key in ("id", "finding_id", "file", "diff", "explanation", "state")}


@app.post("/api/jobs/{job_id}/apply/{repair_id}")
def apply_repair(job_id: str, repair_id: str) -> dict:
    job = _read_job(job_id)
    repair_path = _repair_path(job_id, repair_id)
    try:
        repair = json.loads(repair_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(404, "Repair proposal expired.")
    source_root = JOBS_ROOT / job_id / "source"
    patched_root = JOBS_ROOT / job_id / "patched"
    if patched_root.exists():
        shutil.rmtree(patched_root)
    shutil.copytree(source_root, patched_root)
    target = (patched_root / repair["file"]).resolve()
    if not target.is_relative_to(patched_root.resolve()):
        raise HTTPException(400, "Invalid patch path.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(repair["code"], encoding="utf-8")
    repair["state"] = "validating"
    repair["checks"] = {"build": "running", "tests": "not_available", "sanitizers": "not_available", "performance": "not_measured"}
    job["state"] = "validating"
    job["progress"] = "Checking the patched copy in an offline sandbox"
    job["repair"] = {key: repair[key] for key in ("id", "finding_id", "file", "diff", "explanation", "state", "checks")}
    job["checks"] = repair["checks"]
    _save_job(job)
    return {"state": repair["state"], "download": f"/api/jobs/{job_id}/download", "checks": repair["checks"]}


@app.get("/api/jobs/{job_id}/sarif")
def download_sarif(job_id: str) -> JSONResponse:
    job = _read_job(job_id)
    return JSONResponse(sarif_report(job_id, job.get("findings", [])), headers={"Content-Disposition": f'attachment; filename="patchguard-{job_id}.sarif"'})


@app.get("/api/jobs/{job_id}/download")
def download_project(job_id: str) -> StreamingResponse:
    job = _read_job(job_id)
    project = JOBS_ROOT / job_id / "patched"
    repair = job.get("repair")
    if not project.is_dir() or not repair:
        raise HTTPException(409, "Apply a repair to a copy before downloading.")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in project.rglob("*"):
            if file.is_file():
                archive.write(file, file.relative_to(project).as_posix())
        archive.writestr("PATCHGUARD-REPAIR.json", json.dumps({"taxonomy": "CWE 5.0 / Schema 8.0", "repair": repair, "checks": job["checks"], "performance": job.get("performance")}, indent=2))
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="firmware-{job_id[:8]}-patched.zip"'})


@app.get("/api/jobs/{job_id}/diff")
def download_diff(job_id: str) -> StreamingResponse:
    job = _read_job(job_id)
    repair = job.get("repair")
    if not repair:
        raise HTTPException(404, "No repair has been applied.")
    payload = repair["diff"].encode()
    return StreamingResponse(io.BytesIO(payload), media_type="text/x-diff", headers={"Content-Disposition": "attachment; filename=patchguard-fix.diff"})
