from __future__ import annotations

import difflib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import threading
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from auth import issue_session, read_session, supabase_auth, supabase_user
from db import get_job, list_user_jobs, save_job, begin_repair, update_repair_operation, enqueue_repair, recover_repairs
from providers import explain_with_provider, generate_with_provider
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
MAX_REPAIR_CONTEXT_CHARS = int(os.getenv("MAX_REPAIR_CONTEXT_CHARS", "24000"))
MAX_EXPLANATION_CONTEXT_CHARS = 6_000
MAX_REPAIR_CHANGED_LINES = int(os.getenv("MAX_REPAIR_CHANGED_LINES", "200"))
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx"}
PROJECT_EXTENSIONS = SOURCE_EXTENSIONS | {".cmake", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".mk", ".xml", ".sh", ".properties", ".gradle", ".bazel", ".bzl", ".make", ".conf"}
PROJECT_FILENAMES = {"makefile", "cmakelists.txt", "dockerfile", "meson.build", "meson.options", "configure", "configure.ac", "readme", ".gitignore", ".editorconfig"}
SKIP_UPLOAD_DIRS = {".git", "node_modules", "build", "dist", "vendor", "venv", ".venv", "__pycache__", "target"}
app = FastAPI(title="PatchGuard", version="0.1.0", docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class AuthCallback(BaseModel):
    access_token: str = Field(min_length=20, max_length=8192)


_auth_attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_auth_attempts_lock = threading.Lock()


def _auth_rate_limit(request: Request, action: str, max_attempts: int = 8) -> None:
    # ponytail: process-local rate limit; use shared counters before horizontal scaling.
    key = (request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown"), action)
    now = time.time()
    with _auth_attempts_lock:
        attempts = _auth_attempts[key]
        while attempts and attempts[0] < now - 900:
            attempts.popleft()
        if len(attempts) >= max_attempts:
            raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
        attempts.append(now)


def _set_session(response: Response, user_id: str, email: str, token: str | None = None) -> None:
    try:
        token = token or issue_session(user_id, email)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    response.set_cookie("patchguard_session", token, max_age=28800, httponly=True,
        secure=os.getenv("AUTH_COOKIE_SECURE", "true").lower() == "true", samesite="lax", path="/")


def _current_user(request: Request) -> dict:
    claims = read_session(request.cookies.get("patchguard_session", ""))
    if not claims or not claims.get("id"):
        raise HTTPException(401, "Sign in to access this workspace.")
    return {"id": claims["id"], "email": claims["email"]}


@app.post("/api/auth/register", status_code=201, response_model=None)
def register(credentials: Credentials, request: Request, response: Response) -> dict | JSONResponse:
    _auth_rate_limit(request, "register")
    email = credentials.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "Enter a valid email address.")
    try:
        redirect_url = os.getenv("FRONTEND_URL", "http://localhost:8000").rstrip("/") + "/auth/callback"
        redirect_query = urllib.parse.urlencode({"redirect_to": redirect_url})
        result = supabase_auth(f"signup?{redirect_query}", {"email": email, "password": credentials.password})
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    user = result.get("user") or {}
    if not user.get("id"):
        raise HTTPException(502, "Supabase Auth did not return an account.")
    if result.get("access_token"):
        _set_session(response, user["id"], user.get("email", email))
        response.status_code = 201
        return {"id": user["id"], "email": user.get("email", email)}
    response.status_code = 202
    return JSONResponse(status_code=202, content={"requires_email_confirmation": True})


@app.post("/api/auth/login")
def login(credentials: Credentials, request: Request, response: Response) -> dict:
    _auth_rate_limit(request, "login")
    try:
        result = supabase_auth("token?grant_type=password", {"email": credentials.email.strip().lower(), "password": credentials.password})
    except RuntimeError as exc:
        message = str(exc)
        status = 401 if "invalid login credentials" in message.lower() or "email not confirmed" in message.lower() else 503
        raise HTTPException(status, "Email or password is incorrect." if status == 401 else message) from exc
    user = result.get("user") or {}
    if not user.get("id") or not user.get("email"):
        raise HTTPException(502, "Supabase Auth returned an incomplete account.")
    _set_session(response, user["id"], user["email"])
    return {"id": user["id"], "email": user["email"]}


@app.get("/api/auth/github")
def github_sign_in() -> RedirectResponse:
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    if not base:
        raise HTTPException(503, "Set SUPABASE_URL to enable GitHub sign-in.")
    callback = os.getenv("FRONTEND_URL", "http://localhost:8000").rstrip("/") + "/auth/callback"
    params = urllib.parse.urlencode({"provider": "github", "redirect_to": callback})
    return RedirectResponse(f"{base}/auth/v1/authorize?{params}", status_code=302)


@app.get("/api/auth/demo/status")
def demo_status() -> dict:
    return {"enabled": bool(os.getenv("DEMO_EMAIL") and os.getenv("DEMO_PASSWORD"))}


@app.post("/api/auth/demo")
def demo_login(request: Request, response: Response) -> dict:
    _auth_rate_limit(request, "demo", max_attempts=15)
    email, password = os.getenv("DEMO_EMAIL", "").strip().lower(), os.getenv("DEMO_PASSWORD", "")
    if not email or not password:
        raise HTTPException(404, "Demo access is not configured for this instance.")
    try:
        result = supabase_auth("token?grant_type=password", {"email": email, "password": password})
    except RuntimeError as exc:
        raise HTTPException(503, "The configured demo account could not sign in. Check its Supabase Auth credentials.") from exc
    user = result.get("user") or {}
    if not user.get("id") or not user.get("email"):
        raise HTTPException(503, "Supabase Auth returned an incomplete demo account.")
    _set_session(response, user["id"], user["email"])
    return {"id": user["id"], "email": user["email"]}


@app.post("/api/auth/callback")
def auth_callback(payload: AuthCallback, request: Request, response: Response) -> dict:
    _auth_rate_limit(request, "callback")
    try:
        user = supabase_user(payload.access_token)
    except RuntimeError as exc:
        raise HTTPException(401, "Confirmation link is invalid or expired. Sign in to continue.") from exc
    if not user.get("id"):
        raise HTTPException(401, "Confirmation link is invalid or expired. Sign in to continue.")
    email = user.get("email") or ""
    _set_session(response, user["id"], email)
    return {"id": user["id"], "email": email}


@app.post("/api/auth/logout")
def logout(response: Response) -> dict:
    response.delete_cookie("patchguard_session", path="/", httponly=True,
        secure=os.getenv("AUTH_COOKIE_SECURE", "true").lower() == "true", samesite="lax")
    return {"ok": True}


@app.get("/api/auth/me")
def current_user(request: Request) -> dict:
    user = _current_user(request)
    return {"id": user["id"], "email": user["email"]}


def _job_key(job_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f-]{36}", job_id):
        raise HTTPException(404, "Job not found")
    return job_id


def _read_job(job_id: str, owner_id: str) -> dict:
    job = get_job(_job_key(job_id))
    if not job or job.get("owner_id") != owner_id:
        raise HTTPException(404, "This job has expired or does not exist.")
    return job


def _save_job(job: dict) -> None:
    save_job(job)


def _repair_path(job_id: str, repair_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f-]{36}", repair_id):
        raise HTTPException(404, "Repair proposal not found.")
    return JOBS_ROOT / job_id / "repairs" / f"{repair_id}.json"


def _build_repair_context(before: str, finding: dict, cwe: dict, source_root: Path, target: Path) -> dict:
    lines = before.splitlines(keepends=True)
    line = int(finding["line"])
    if line < 1 or line > len(lines):
        raise HTTPException(422, "Finding location is outside the source file.")
    start, end = max(0, line - 41), min(len(lines), line + 40)
    while sum(map(len, lines[start:end])) > MAX_REPAIR_CONTEXT_CHARS and end - start > 1:
        if line - start > end - line:
            start += 1
        else:
            end -= 1
    localized = "".join(lines[start:end])
    if len(localized) > MAX_REPAIR_CONTEXT_CHARS:
        raise HTTPException(413, "Finding line exceeds the configured repair context limit.")
    headers = []
    header_chars = 0
    seen_headers = set()
    for include in re.findall(r'^\s*#\s*include\s*"([^"]+)"', before, flags=re.MULTILINE):
        header = (target.parent / include).resolve()
        if header.suffix.lower() not in HEADER_EXTENSIONS or not header.is_relative_to(source_root.resolve()) or not header.is_file() or header in seen_headers:
            continue
        seen_headers.add(header)
        try:
            if header.stat().st_size > 6_000 - header_chars:
                continue
            content = header.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        addition = len(content)
        if addition > 6_000 - header_chars:
            continue
        headers.append(f"{header.relative_to(source_root.resolve()).as_posix()}:\n{content}")
        header_chars += addition
    return {
        "finding": finding["message"],
        "evidence": finding.get("evidence", finding["message"]),
        "cwe": f"{cwe['id']} — {cwe['name']}",
        "description": cwe["description"],
        "mapping_usage": cwe["mapping_usage"],
        "mitigations": " ".join(cwe["mitigations"][:2]),
        "mapping_confidence": finding["mapping_confidence"],
        "file": finding["file"],
        "line": finding["line"],
        "source": localized,
        "numbered_source": "".join(f"{n}: {text}" for n, text in enumerate(lines[start:end], start + 1)),
        "retry_feedback": "None",
        "scope_start": sum(map(len, lines[:start])),
        "scope_end": sum(map(len, lines[:end])),
        "scope_start_line": start + 1,
        "scope_end_line": end,
        "headers": "\n\n".join(headers) or "No bounded project headers were included.",
        "includes": "".join(line for line in lines if re.match(r"^\s*#\s*include\s*[<\"]", line))[:2000] or "No include lines.",
    }


def _validate_edits(before: str, edits: list[dict], scope_start: int, scope_end: int) -> tuple[str, list[dict], int, int]:
    spans = []
    lines = before.splitlines(keepends=True)
    endings = {"crlf" if line.endswith("\r\n") else "lf" for line in lines if line.endswith("\n")}
    if len(endings) > 1 or "\r" in before.replace("\r\n", ""):
        raise ValueError("mixed_line_endings: Source uses unsupported mixed line endings.")
    newline = "\r\n" if "crlf" in endings else "\n"
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    for index, edit in enumerate(edits):
        original, replacement = edit["original"], edit["replacement"]
        first, last = edit.get("start_line"), edit.get("end_line")
        if not isinstance(first, int) or not isinstance(last, int) or first < 1 or last < first or last > len(lines):
            raise ValueError(f"wrong_range: Edit {index + 1} has an invalid line range.")
        range_start, range_end = offsets[first - 1], offsets[last]
        region = before[range_start:range_end]
        normalized = region.replace("\r\n", "\n")
        expected = original.replace("\r\n", "\n")
        if not expected:
            raise ValueError(f"missing_context: Edit {index + 1} has no expected source text.")
        position = normalized.find(expected)
        if position < 0:
            raise ValueError(f"text_mismatch: Edit {index + 1} does not match lines {first}-{last}.")
        if normalized.find(expected, position + 1) >= 0:
            raise ValueError(f"ambiguous_context: Edit {index + 1} matches more than once in its declared range.")
        start = range_start + len(normalized[:position].replace("\n", newline))
        end = start + len(expected.replace("\n", newline))
        original = before[start:end]
        replacement = replacement.replace("\r\n", "\n").replace("\n", newline)
        kind = edit.get("kind", "code")
        if kind == "include":
            if not re.fullmatch(r'[ \t]*#[ \t]*include[^\r\n]*(?:\r?\n)', original):
                raise ValueError("include_context: Include edit must anchor to one existing include line.")
            extra = replacement.removeprefix(original)
            if not replacement.startswith(original) or not re.fullmatch(r'[ \t]*#[ \t]*include[ \t]*<[^>\r\n]+>[ \t]*(?:\r?\n)', extra):
                raise ValueError("include_context: Include edit must only add one standard include.")
        elif kind != "code" or start < scope_start or end > scope_end:
            raise ValueError(f"scope_violation: Edit {index + 1} exceeds the localized repair scope.")
        if original == replacement:
            raise ValueError("no_change: Edit makes no change.")
        spans.append((start, end, {**edit, "original": original, "replacement": replacement}))
    spans.sort(key=lambda item: item[0])
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError("overlap: Repair edits overlap.")
    after = before
    for start, end, edit in reversed(spans):
        after = after[:start] + edit["replacement"] + after[end:]
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines(), autojunk=False)
    added = deleted = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag != "equal":
            deleted += i2 - i1
            added += j2 - j1
    if max(added, deleted) > MAX_REPAIR_CHANGED_LINES:
        raise ValueError("size_limit: Repair exceeds the configured changed-line limit.")
    return after, [{**edit, "start": start, "end": end, "line": before.count("\n", 0, start) + 1} for start, end, edit in spans], added, deleted


def _changed_line_count(before: str, after: str) -> int:
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines())
    return sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != "equal")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "taxonomy_version": catalog()["version"], "analyzers": ["Clang Static Analyzer", "Cppcheck", "Semgrep"]}


@app.get("/api/providers")
def providers_status() -> dict:
    ollama_configured = bool(os.getenv("OLLAMA_BASE_URL"))
    ollama_available = False
    ollama_model_available = False
    ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    if ollama_configured:
        try:
            with urllib.request.urlopen(os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434").rstrip("/") + "/api/tags", timeout=2) as response:
                ollama_available = response.status == 200
                if ollama_available:
                    payload = json.loads(response.read().decode())
                    installed = {item.get("name", "").removesuffix(":latest") for item in payload.get("models", [])}
                    ollama_model_available = ollama_model.removesuffix(":latest") in installed
        except (OSError, urllib.error.URLError, TimeoutError):
            pass
        except (json.JSONDecodeError, AttributeError, TypeError):
            ollama_available = False
    groq_configured = bool(os.getenv("GROQ_API_KEY"))
    return {
        "providers": {
            "auto": {"configured": ollama_configured or groq_configured, "label": "Automatic (Ollama → Groq)"},
            "ollama": {"configured": ollama_configured, "available": ollama_available, "model_available": ollama_model_available, "model": ollama_model},
            "groq": {"configured": groq_configured, "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")},
            "none": {"configured": True, "label": "Scan only"},
        }
    }


@app.get("/api/jobs")
def jobs(request: Request, limit: int = 100) -> list[dict]:
    if not 1 <= limit <= 500:
        raise HTTPException(400, "Limit must be between 1 and 500.")
    return list_user_jobs(_current_user(request)["id"], limit)


@app.get("/api/dashboard")
def dashboard(request: Request) -> dict:
    items = list_user_jobs(_current_user(request)["id"], 500)
    finished = [item for item in items if item.get("state") == "complete"]
    findings = [finding for job in finished for finding in job.get("findings", [])]
    open_findings = [finding for finding in findings if finding.get("status", "open") == "open"]
    return {
        "projects": len(items), "scans": len(items), "vulnerabilities": len(open_findings),
        "critical": sum(f.get("severity") == "critical" for f in open_findings),
        "fixed": sum(bool(job.get("repair")) and job["repair"].get("state") == "applied_to_copy" for job in finished),
        "security_score": None, "recent_scans": items[:8], "findings_by_severity": {
            severity: sum(f.get("severity") == severity for f in open_findings)
            for severity in ("critical", "high", "medium", "low", "informational")
        },
    }


@app.get("/api/weaknesses")
def weaknesses() -> dict:
    data = catalog()
    return {"version": data["version"], "schema": data["schema"], "items": supported_weaknesses()}


@app.post("/api/jobs", status_code=202)
async def create_job(request: Request, files: list[UploadFile] = File(default=[]), file: UploadFile | None = File(default=None), provider: str = Form("auto")) -> dict:
    uploads = files or ([file] if file else [])
    if not uploads:
        raise HTTPException(400, "Choose source files or a ZIP project.")
    if len(uploads) > MAX_FILES:
        raise HTTPException(413, f"Upload exceeds the {MAX_FILES} file limit.")
    if provider not in {"none", "auto", "groq", "hosted", "ollama"}:
        raise HTTPException(400, "Choose scan only, automatic, Ollama, or Groq.")
    user = _current_user(request)
    _auth_rate_limit(request, "scan_upload", 30)
    names = [(upload.filename or "").replace("\\", "/") for upload in uploads]
    is_zip = len(uploads) == 1 and Path(names[0]).suffix.lower() == ".zip"
    if any(not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts for path in names):
        raise HTTPException(400, "Uploaded file contains an unsafe path.")
    for path in names:
        ext = Path(path).suffix.lower()
        if ext not in ({".zip"} if is_zip else PROJECT_EXTENSIONS) and Path(path).name.casefold() not in PROJECT_FILENAMES:
            raise HTTPException(415, "Project uploads must contain C/C++ source and supported text project files.")

    job_id = str(uuid.uuid4())
    job_dir = JOBS_ROOT / job_id
    job_dir.mkdir(parents=True)
    source_root = job_dir / "upload-source"
    created_at = time.time()
    (job_dir / ".created").write_text(str(created_at), encoding="ascii")
    total = 0
    try:
        if is_zip:
            zip_path = job_dir / "upload.zip"
            with zip_path.open("wb") as output:
                while chunk := await uploads[0].read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_UPLOAD:
                        raise HTTPException(413, "ZIP project exceeds the upload size limit.")
                    output.write(chunk)
            with zipfile.ZipFile(zip_path) as archive:
                entries = archive.infolist()
                if not entries or len(entries) > MAX_FILES:
                    raise HTTPException(400, "ZIP is empty or exceeds the file limit.")
                expanded = 0
                source_count = 0
                for entry in entries:
                    arcname = entry.filename.replace("\\", "/")
                    parts = PurePosixPath(arcname).parts
                    if not arcname or PurePosixPath(arcname).is_absolute() or arcname.startswith("/") or ".." in parts or stat.S_ISLNK(entry.external_attr >> 16):
                        raise HTTPException(400, "Archive contains an unsafe path or symbolic link.")
                    expanded += entry.file_size
                    if expanded > MAX_EXTRACTED:
                        raise HTTPException(413, "Expanded project exceeds the size limit.")
                    if not entry.is_dir() and PurePosixPath(arcname).suffix.lower() in SOURCE_EXTENSIONS:
                        source_count += 1
                        if entry.file_size > MAX_SOURCE:
                            raise HTTPException(413, f"Source file {PurePosixPath(arcname).name} exceeds the {MAX_SOURCE // 1000} KB limit.")
                        if entry.file_size == 0:
                            raise HTTPException(400, f"Source file {PurePosixPath(arcname).name} is empty.")
                        try:
                            with archive.open(entry) as source:
                                source.read().decode("utf-8")
                        except UnicodeDecodeError as exc:
                            raise HTTPException(400, "Source files must use UTF-8 encoding.") from exc
                if not source_count:
                    raise HTTPException(400, "ZIP must contain a .c, .cpp, or .h source file.")
        else:
            seen: set[str] = set()
            for upload, upload_name in zip(uploads, names):
                relative = PurePosixPath(upload_name)
                parts = relative.parts if len(uploads) > 1 or len(relative.parts) > 1 else (Path(upload_name).name,)
                if any(part in {"", ".", ".."} for part in parts):
                    raise HTTPException(400, "Uploaded project contains an unsafe path or unsupported file.")
                if any(part.casefold() in SKIP_UPLOAD_DIRS for part in parts):
                    continue
                if Path(parts[-1]).suffix.lower() not in PROJECT_EXTENSIONS and parts[-1].casefold() not in PROJECT_FILENAMES:
                    raise HTTPException(415, f"Unsupported project file: {parts[-1]}.")
                rel = Path(*parts)
                key = rel.as_posix().casefold()
                if key in seen:
                    raise HTTPException(400, "Uploaded project contains duplicate file paths.")
                seen.add(key)
                target = source_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                size = 0
                with target.open("wb") as output:
                    while chunk := await upload.read(1024 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if (Path(upload_name).suffix.lower() in SOURCE_EXTENSIONS and size > MAX_SOURCE) or size > MAX_SOURCE * 10 or total > MAX_UPLOAD:
                            raise HTTPException(413, "Uploaded source exceeds the configured size limit.")
                        output.write(chunk)
                if size == 0:
                    raise HTTPException(400, "Uploaded source file is empty.")
                try:
                    target.read_text(encoding="utf-8")
                except UnicodeDecodeError as exc:
                    raise HTTPException(400, "Source files must use UTF-8 encoding.") from exc
    except zipfile.BadZipFile as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(400, "Could not read this ZIP archive.") from exc
    except (OSError, HTTPException):
        shutil.rmtree(job_dir, ignore_errors=True)
        raise
    finally:
        for upload in uploads:
            await upload.close()

    if not is_zip and not any((source_root / Path(*PurePosixPath(path).parts)).suffix.lower() in SOURCE_EXTENSIONS for path in names if not any(part.casefold() in SKIP_UPLOAD_DIRS for part in PurePosixPath(path).parts)):
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(400, "Project upload must contain at least one C/C++ source file.")

    upload_kind = "zip" if is_zip else ("source" if len(uploads) == 1 and len(PurePosixPath(names[0]).parts) == 1 else "project")
    job = {
        "id": job_id, "owner_id": user["id"], "name": Path(names[0]).name, "provider": provider,
        "upload_kind": upload_kind,
        "upload_filename": names[0] if upload_kind == "source" else None,
        "uploaded_files": [PurePosixPath(path).as_posix() for path in names],
        "state": "queued", "created_at": created_at, "expires_at": created_at + JOB_TTL,
        "findings": [], "checks": {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "performance": "not_measured"},
    }
    try:
        _save_job(job)
    except Exception as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(503, "Scan storage is unavailable. Please retry the upload.") from exc
    return {"id": job_id, "state": "queued", "expires_in_seconds": JOB_TTL}


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, request: Request) -> dict:
    return _read_job(job_id, _current_user(request)["id"])


@app.get("/api/jobs/{job_id}/files")
def job_files(job_id: str, request: Request) -> dict:
    _read_job(job_id, _current_user(request)["id"])
    root = JOBS_ROOT / job_id / "source"
    return {"files": sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()) if root.is_dir() else []}


@app.get("/api/jobs/{job_id}/findings/{finding_id}")
def finding_detail(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    finding = next((item for item in job.get("findings", []) if item["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    source_root = JOBS_ROOT / job_id / "source"
    target = (source_root / finding["file"]).resolve()
    if not target.is_relative_to(source_root.resolve()) or not target.is_file():
        raise HTTPException(404, "Finding source is no longer available.")
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    start, end = max(0, finding["line"] - 4), min(len(lines), finding["line"] + 3)
    return {**finding, "source_lines": lines[start:end], "source_start_line": start + 1, "job_id": job_id}


@app.post("/api/jobs/{job_id}/explain/{finding_id}")
def explain_finding(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    if job.get("state") != "complete":
        raise HTTPException(409, "Wait for the scan to finish before requesting an explanation.")
    if job.get("provider") == "none":
        raise HTTPException(409, "This scan was created without AI. Start a new scan to request an explanation.")
    finding = next((item for item in job.get("findings", []) if item.get("id") == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    explanations = job.setdefault("explanations", {})
    if finding_id in explanations:
        return explanations[finding_id]

    source_root = (JOBS_ROOT / job_id / "source").resolve()
    target = (source_root / finding.get("file", "")).resolve()
    if not target.is_relative_to(source_root) or not target.is_file():
        raise HTTPException(404, "Finding source is no longer available.")
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise HTTPException(404, "Finding source is no longer available.") from exc
    line = max(1, int(finding.get("line", 1)))
    start, end = max(0, line - 9), min(len(lines), line + 8)
    source = "\n".join(f"{index + 1}: {text[:400]}" for index, text in enumerate(lines[start:end], start))[:4_000]
    context = {
        "finding": str(finding.get("message", "Static analysis finding"))[:1_000],
        "severity": str(finding.get("severity", "unknown"))[:30],
        "file": str(finding.get("file", ""))[:512],
        "line": line,
        "classification": str(finding.get("classification", "static analysis finding"))[:100],
        "cwe": str((finding.get("cwe") or {}).get("id", "Unmapped"))[:40],
        "evidence": str(finding.get("evidence", ""))[:1_000],
        "source": source,
    }
    if sum(len(str(value)) for value in context.values()) > MAX_EXPLANATION_CONTEXT_CHARS:
        raise HTTPException(413, "Finding context exceeds the explanation limit.")
    try:
        result, provider_used = explain_with_provider(job.get("provider", "none"), context)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    explanation = {**result.model_dump(), "provider_used": provider_used}
    explanations[finding_id] = explanation
    _save_job(job)
    return explanation


@app.get("/api/jobs/{job_id}/explain/{finding_id}")
def saved_finding_explanation(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    if not any(item.get("id") == finding_id for item in job.get("findings", [])):
        raise HTTPException(404, "Finding not found.")
    explanation = job.get("explanations", {}).get(finding_id)
    if not explanation:
        raise HTTPException(404, "No saved AI explanation for this finding.")
    return explanation


@app.post("/api/jobs/{job_id}/findings/{finding_id}/false-positive")
def mark_false_positive(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    finding = next((item for item in job.get("findings", []) if item["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    finding["status"] = "false_positive"
    _save_job(job)
    return {"id": finding_id, "status": finding["status"]}


def _proposal_summary(repair: dict) -> dict:
    return {key: repair[key] for key in ("id", "finding_id", "file", "diff", "explanation", "provider_used", "state", "metadata") if key in repair}


@app.get("/api/jobs/{job_id}/repair/{finding_id}")
def get_repair(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    proposal = next((item for item in job.get("proposals", []) if item.get("finding_id") == finding_id and item.get("state") in ("proposed", "validating", "review_ready", "verification_failed")), None)
    if not proposal:
        raise HTTPException(404, "No proposed repair is saved for this finding.")
    return proposal


@app.get("/api/jobs/{job_id}/findings/{finding_id}/source")
def finding_source(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    finding = next((f for f in job.get("findings", []) if f["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    root = (JOBS_ROOT / job_id / "source").resolve()
    target = (root / finding["file"]).resolve()
    if not target.is_relative_to(root) or not target.is_file() or target.stat().st_size > 200_000:
        raise HTTPException(404, "Source preview is unavailable or has expired.")
    data = target.read_bytes()
    return {"file": finding["file"], "line": finding["line"], "original": data.decode("utf-8", errors="replace"), "source_hash": hashlib.sha256(data).hexdigest(), "expires_at": job.get("expires_at")}


@app.get("/api/jobs/{job_id}/repair-status")
def repair_status(job_id: str, request: Request, finding_id: str | None = None) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    recover_repairs(job_id)
    job = _read_job(job_id, _current_user(request)["id"])
    operation = job.get("repair_operation") or {}
    active = operation.get("status") in ("running", "queued", "verifying")
    repair = job.get("repair") or {}
    if finding_id and operation.get("finding_id") != finding_id:
        operation = {}
    if (finding_id and repair.get("finding_id") != finding_id) or (operation and repair.get("operation_id") != operation.get("id")):
        repair = {}
    preview = None
    if repair.get("id") and repair.get("file"):
        source_root = JOBS_ROOT / job_id / "source"
        original = (source_root / repair["file"]).resolve()
        if original.is_relative_to(source_root.resolve()) and original.is_file():
            preview = {"original": original.read_text(encoding="utf-8", errors="replace"), "proposed": repair.get("code", ""), "line": (repair.get("metadata") or {}).get("line")}
    return {"operation": operation, "job_busy": active, "repair": _proposal_summary(repair) if repair else None, "checks": repair.get("checks") if repair else None, "preview": preview}


def _rejected_attempt(exc: Exception, result, before: str, attempt: int) -> dict:
    technical = str(exc)[:500]
    code = technical.split(":", 1)[0]
    if code not in {"missing_context", "text_mismatch", "wrong_range", "ambiguous_context", "overlap", "scope_violation", "include_context", "no_change", "size_limit", "mixed_line_endings", "invalid_path"}:
        code = "provider_unavailable" if isinstance(exc, RuntimeError) else "invalid_schema"
    match = re.search(r"Edit (\d+)", technical)
    edit_index = int(match.group(1)) if match else None
    snippets = []
    budget = 12000
    for index, edit in enumerate(result.edits if result else []):
        if index >= 8 or budget <= 0:
            break
        first, last = edit.start_line, edit.end_line
        actual = "".join(before.splitlines(keepends=True)[first - 1:last]) if 1 <= first <= last <= len(before.splitlines()) else ""
        limit = min(2000, budget // 3)
        snippets.append({"edit_index": index + 1, "start_line": first, "end_line": last, "actual": actual[:limit], "expected": edit.original[:limit], "replacement": edit.replacement[:limit], "reason": edit.reason[:500], "truncated": any(len(s) > limit for s in (actual, edit.original, edit.replacement))})
        budget -= sum(len(snippets[-1][key]) for key in ("actual", "expected", "replacement"))
    failed = next((s for s in snippets if s["edit_index"] == edit_index), None)
    location = f" at line {failed['start_line']}" if failed else ""
    message = (f"The AI suggested replacing code that does not match your uploaded file{location}." if code in ("text_mismatch", "missing_context", "ambiguous_context", "wrong_range") else "The suggestion did not pass the repair safety checks.")
    if code == "provider_unavailable":
        message = "The AI provider could not generate a suggestion. Check provider availability or try again later."
    if attempt == 2:
        message += " A second attempt also failed."
    message += " Your original code is unchanged. Build and security verification have not started."
    return {"attempt": attempt, "at": time.time(), "code": code, "stage": "generating" if code == "provider_unavailable" else "checking edits", "edit_index": edit_index, "start_line": failed["start_line"] if failed else None, "end_line": failed["end_line"] if failed else None, "message": message, "technical": technical, "retryable": True, "edits": snippets}


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Candidate contains a symbolic link.")
        if path.is_file():
            name = path.relative_to(root).as_posix().encode("utf-8")
            digest.update(len(name).to_bytes(8, "big")); digest.update(name)
            content = path.read_bytes()
            digest.update(len(content).to_bytes(8, "big")); digest.update(content)
    return digest.hexdigest()

@app.post("/api/jobs/{job_id}/repair/{finding_id}")
def create_repair(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    if job["state"] != "complete":
        raise HTTPException(409, "Wait for the scan to finish before generating a repair.")
    if job["provider"] == "none":
        raise HTTPException(409, "This scan was created without AI. Start a new scan to request a repair.")
    finding = next((item for item in job.get("findings", []) if item["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    if finding.get("status") == "false_positive":
        raise HTTPException(409, "False-positive findings do not support automated repair.")
    if (JOBS_ROOT / job_id / "patched").exists():
        raise HTTPException(409, "A working copy already exists. Download it or start a new scan.")
    existing = next((item for item in job.get("proposals", []) if item.get("finding_id") == finding_id and item.get("state") in ("validating", "review_ready")), None)
    if existing:
        return existing
    if not finding.get("cwe"):
        raise HTTPException(409, "Suspicious candidates need manual review and do not support automated repair.")
    source_root = JOBS_ROOT / job_id / "source"
    target = (source_root / finding["file"]).resolve()
    if not target.is_relative_to(source_root.resolve()) or not target.is_file():
        raise HTTPException(400, "Finding source is no longer available.")
    if target.stat().st_size > 200_000:
        raise HTTPException(413, "This file is too large for one repair request.")
    try:
        before = target.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "Repair requires UTF-8 source; the original file was preserved.") from exc
    cwe = get_weakness(finding["cwe"]["id"])
    if not cwe:
        raise HTTPException(400, "CWE mapping could not be loaded.")
    context = _build_repair_context(before, finding, cwe, source_root, target)
    operation_id = str(uuid.uuid4())
    operation = {"id": operation_id, "finding_id": finding_id, "stage": "locating code", "status": "running", "started_at": time.time(), "deadline": time.time() + 400, "attempt": 0, "events": [{"at": time.time(), "stage": "locating code", "status": "running"}], "scope_start_line": context["scope_start_line"], "scope_end_line": context["scope_end_line"]}
    if not begin_repair(job_id, _current_user(request)["id"], operation):
        raise HTTPException(409, "Another repair is already in progress. View its status.")
    chosen_provider = job["provider"]
    attempts = []
    for attempt in range(2):
        result = None
        try:
            update_repair_operation(job_id, operation_id, {"stage": "generating" if attempt == 0 else "retrying", "attempt": attempt + 1})
            result, provider_used = generate_with_provider(chosen_provider, context, on_event=lambda event: update_repair_operation(job_id, operation_id, event))
            chosen_provider = provider_used
            update_repair_operation(job_id, operation_id, {"stage": "checking edits", "provider": provider_used})
            if result.file != finding["file"]:
                raise ValueError("invalid_path: Repair targets a different file.")
            after, edits, added, deleted = _validate_edits(before, [edit.model_dump() for edit in result.edits], context["scope_start"], context["scope_end"])
            break
        except (ValueError, RuntimeError) as exc:
            detail = _rejected_attempt(exc, result, before, attempt + 1)
            attempts.append(detail)
            update_repair_operation(job_id, operation_id, {"attempts": attempts, "error_detail": detail})
            if attempt == 1:
                update_repair_operation(job_id, operation_id, {"stage": detail["stage"], "status": "failed", "error": detail["message"]})
                raise HTTPException(422, detail) from exc
            context["retry_feedback"] = f"{detail['technical']} Allowed source lines: {context['scope_start_line']}-{context['scope_end_line']}. Use absolute line numbers and exact original text, including indentation. Actual source at failed ranges: {json.dumps(detail['edits'])[:12000]}"
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"a/{finding['file']}", tofile=f"b/{finding['file']}"))
    repair_id = str(uuid.uuid4())
    metadata = {"line": finding["line"], "scope_start_line": context["scope_start_line"], "scope_end_line": context["scope_end_line"], "localization": "bounded line window", "added_lines": added, "deleted_lines": deleted, "reasons": [edit["reason"] for edit in edits], "security_improvement": result.security_improvement, "warnings": ["Function boundaries were not established; scope is based on nearby lines."]}
    repair = {"id": repair_id, "finding_id": finding_id, "file": finding["file"], "code": after, "diff": diff, "explanation": result.explanation, "provider_used": provider_used, "state": "proposed", "created_at": time.time(), "source_hash": hashlib.sha256(before.encode("utf-8")).hexdigest(), "scope_start": context["scope_start"], "scope_end": context["scope_end"], "edits": edits, "metadata": metadata}
    repair["operation_id"] = operation_id
    update_repair_operation(job_id, operation_id, {"stage": "preparing candidate", "error_detail": None})
    candidate_root = JOBS_ROOT / job_id / "candidates" / repair_id
    try:
        candidate_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_root, candidate_root)
        candidate_target = (candidate_root / repair["file"]).resolve()
        if not candidate_target.is_relative_to(candidate_root.resolve()):
            raise ValueError("Invalid candidate path.")
        candidate_target.write_bytes(after.encode("utf-8"))
        repair["candidate_hash"] = _tree_hash(candidate_root)
        repair["state"] = "validating"
        repair["checks"] = {"build": "pending", "tests": "pending", "sanitizers": "pending", "security": "pending", "verification": "pending", "performance": "not_measured"}
        repair_dir = JOBS_ROOT / job_id / "repairs"
        repair_dir.mkdir(parents=True, exist_ok=True)
        _repair_path(job_id, repair_id).write_text(json.dumps(repair), encoding="utf-8")
        if not enqueue_repair(job_id, operation_id, repair, _proposal_summary(repair)):
            raise ValueError("Repair operation expired or was replaced.")
    except Exception as exc:
        shutil.rmtree(candidate_root, ignore_errors=True)
        update_repair_operation(job_id, operation_id, {"stage": "failed", "status": "failed", "error": "Could not prepare repair candidate."})
        raise HTTPException(409, "Could not prepare repair candidate; retry the repair.") from exc
    return _proposal_summary(repair)


@app.post("/api/jobs/{job_id}/repair/{repair_id}/reject")
def reject_repair(job_id: str, repair_id: str, request: Request) -> dict:
    _read_job(job_id, _current_user(request)["id"])
    path = _repair_path(job_id, repair_id)
    try:
        repair = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(404, "Repair proposal not found.") from exc
    if repair.get("state") != "proposed":
        raise HTTPException(409, "Only a proposed repair can be rejected.")
    repair["state"] = "rejected"
    path.write_text(json.dumps(repair), encoding="utf-8")
    job = _read_job(job_id, _current_user(request)["id"])
    for proposal in job.get("proposals", []):
        if proposal.get("id") == repair_id:
            proposal["state"] = "rejected"
    _save_job(job)
    return {"id": repair_id, "state": "rejected"}


@app.post("/api/jobs/{job_id}/apply/{repair_id}")
def apply_repair(job_id: str, repair_id: str, request: Request, confirm_partial: bool = False) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    repair_path = _repair_path(job_id, repair_id)
    try:
        repair = json.loads(repair_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(404, "Repair proposal expired.")
    current = job.get("repair") or {}
    if current.get("id") != repair_id or current.get("state") != "review_ready":
        raise HTTPException(409, "This repair has not finished verification or is no longer available.")
    outcome = (current.get("checks") or {}).get("verification_outcome", "not_verified")
    if outcome not in ("verified", "partially_verified"):
        raise HTTPException(409, "This repair cannot be accepted because verification failed or is unavailable.")
    if outcome == "partially_verified" and not confirm_partial:
        raise HTTPException(409, "Confirm acceptance with unavailable checks before continuing.")
    source_root = JOBS_ROOT / job_id / "source"
    target = (source_root / repair.get("file", "")).resolve()
    if not target.is_relative_to(source_root.resolve()) or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != repair.get("source_hash"):
        raise HTTPException(409, "Source changed since proposal generation. Generate a new repair.")
    candidate = JOBS_ROOT / job_id / "candidates" / repair_id
    if not candidate.is_dir() or _tree_hash(candidate) != repair.get("candidate_hash"):
        raise HTTPException(409, "The verified candidate changed or expired. Generate a new repair.")
    patched_root = JOBS_ROOT / job_id / "patched"
    try:
        patched_root.mkdir()
    except FileExistsError as exc:
        raise HTTPException(409, "A working copy already exists. Download it or start a new scan.") from exc
    try:
        os.rename(candidate, patched_root)
    except Exception:
        patched_root.rmdir()
        raise
    repair["state"] = "applied_to_copy"
    _repair_path(job_id, repair_id).write_text(json.dumps(repair), encoding="utf-8")
    job["repair"]["state"] = "applied_to_copy"
    job["progress"] = "Verified candidate accepted to working copy"
    for proposal in job.get("proposals", []):
        if proposal.get("id") == repair_id:
            proposal["state"] = "applied_to_copy"
    _save_job(job)
    return {"state": "applied_to_copy", "download": f"/api/jobs/{job_id}/download", "checks": current["checks"]}


@app.get("/api/jobs/{job_id}/sarif")
def download_sarif(job_id: str, request: Request) -> JSONResponse:
    job = _read_job(job_id, _current_user(request)["id"])
    return JSONResponse(sarif_report(job_id, job.get("findings", [])), headers={"Content-Disposition": f'attachment; filename="patchguard-{job_id}.sarif"'})


@app.get("/api/jobs/{job_id}/download")
def download_project(job_id: str, request: Request) -> StreamingResponse:
    job = _read_job(job_id, _current_user(request)["id"])
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
def download_diff(job_id: str, request: Request) -> StreamingResponse:
    job = _read_job(job_id, _current_user(request)["id"])
    repair = job.get("repair")
    if not repair:
        raise HTTPException(404, "No repair has been applied.")
    payload = repair["diff"].encode()
    return StreamingResponse(io.BytesIO(payload), media_type="text/x-diff", headers={"Content-Disposition": "attachment; filename=patchguard-fix.diff"})
