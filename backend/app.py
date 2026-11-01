from __future__ import annotations

import asyncio
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import secrets
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
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from auth import issue_session, read_session, supabase_auth, supabase_user
from db import (begin_repair, enqueue_repair, get_job, list_user_jobs, recover_repairs,
                reserve_repair_attempt, save_job, update_repair_operation, locked_job)
from providers import explain_with_provider, generate_with_provider
from project_io import inspect_archive, safe_path, validate_text, ProjectInputError
from verification import verification_outcome
from scanner import sarif_report
from taxonomy import catalog, get_weakness, supported_weaknesses
from dotenv import load_dotenv
load_dotenv()

WORK_ROOT = Path(os.getenv("WORK_ROOT", str(Path(tempfile.gettempdir()) / "patchguard")))
JOBS_ROOT = WORK_ROOT / "jobs"
JOBS_ROOT.mkdir(parents=True, exist_ok=True)
JOB_TTL = int(os.getenv("JOB_TTL_SECONDS", "3600"))
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_BYTES", "25000000"))
MAX_FILES = int(os.getenv("MAX_PROJECT_FILES", "5000"))
MAX_EXTRACTED = int(os.getenv("MAX_EXTRACTED_BYTES", "100000000"))
MAX_SOURCE = int(os.getenv("MAX_SOURCE_BYTES", "200000"))
MAX_REPAIR_CONTEXT_CHARS = int(os.getenv("MAX_REPAIR_CONTEXT_CHARS", "24000"))
MAX_DEEP_REPAIR_CONTEXT_CHARS = int(os.getenv("MAX_DEEP_REPAIR_CONTEXT_CHARS", "48000"))
MAX_EXPLANATION_CONTEXT_CHARS = 6_000
MAX_REPAIR_CHANGED_LINES = int(os.getenv("MAX_REPAIR_CHANGED_LINES", "200"))
MAX_REPAIR_ATTEMPTS = 3
REPAIR_GENERATION_TIMEOUT = 180
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx"}
PROJECT_EXTENSIONS = SOURCE_EXTENSIONS | {".cmake", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".mk", ".xml", ".sh", ".properties", ".gradle", ".bazel", ".bzl", ".make", ".conf"}
PROJECT_FILENAMES = {"makefile", "cmakelists.txt", "dockerfile", "meson.build", "meson.options", "configure", "configure.ac", "readme", ".gitignore", ".editorconfig"}
SKIP_UPLOAD_DIRS = {".git", "node_modules", "build", "dist", "vendor", "venv", ".venv", "__pycache__", "target"}
app = FastAPI(title="Patch8", version="0.1.0", docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")

@app.middleware("http")
async def validate_browser_origin(request: Request, call_next):
    origin = request.headers.get("origin")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and origin:
        allowed = {os.getenv("FRONTEND_URL", "http://localhost:8000").rstrip("/"), str(request.base_url).rstrip("/")}
        if origin.rstrip("/") not in allowed:
            return JSONResponse({"detail": "Request origin is not allowed."}, status_code=403)
    return await call_next(request)


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class AuthCallback(BaseModel):
    access_token: str = Field(min_length=20, max_length=8192)


class GitHubRepositoriesRequest(BaseModel):
    provider_token: str = Field(min_length=1, max_length=8192)
    page: int = Field(default=1, ge=1, le=1000)


class GitHubScanRequest(GitHubRepositoriesRequest):
    full_name: str = Field(min_length=3, max_length=201)


class InternalRepairRequest(BaseModel):
    provider: str
    context: dict


@app.post("/api/internal/repair/generate")
def internal_repair_generate(payload: InternalRepairRequest, x_repair_secret: str = Header(default="")) -> dict:
    secret = os.getenv("REPAIR_INTERNAL_SECRET", "")
    if not secret or not secrets.compare_digest(x_repair_secret, secret):
        raise HTTPException(404, "Not found.")
    try:
        proposal, provider_used = generate_with_provider(payload.provider, payload.context)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    model = (os.getenv("GROQ_DEEP_MODEL", "openai/gpt-oss-120b") if payload.provider == "deep"
             else os.getenv("GROQ_MODEL", "openai/gpt-oss-120b") if provider_used == "groq"
             else os.getenv("OLLAMA_MODEL", "qwen2.5:3b") if provider_used == "ollama"
             else os.getenv("OPENAI_MODEL", "gpt-4.1-mini"))
    return {"proposal": proposal.model_dump(), "provider_used": provider_used, "model": model}


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
    callback = os.getenv("FRONTEND_URL", "http://localhost:8000").rstrip("/") + "/auth/callback?source=github"
    params = urllib.parse.urlencode({"provider": "github", "redirect_to": callback})
    return RedirectResponse(f"{base}/auth/v1/authorize?{params}", status_code=302)


class GitHubRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urllib.parse.urlsplit(newurl)
        if destination.scheme != "https" or destination.hostname != "api.github.com" or destination.port not in (None, 443):
            raise HTTPException(502, "GitHub returned an unexpected API location.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _github_request(path: str, token: str, max_bytes: int = 5_000_000) -> bytes:
    if not token or any(ord(character) < 33 or ord(character) > 126 for character in token):
        raise HTTPException(401, "GitHub authorization is missing. Sign in with GitHub again.")
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PatchGuard-MVP",
        },
    )
    try:
        with urllib.request.build_opener(GitHubRedirectHandler()).open(request, timeout=20) as response:
            host = urllib.parse.urlsplit(response.geturl()).hostname
            if host != "api.github.com":
                raise HTTPException(502, "GitHub returned an unexpected API location.")
            data = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise HTTPException(401, "GitHub authorization expired. Sign in with GitHub again.") from exc
        if exc.code == 403 and (exc.headers or {}).get("X-RateLimit-Remaining") == "0":
            raise HTTPException(429, "GitHub API rate limit reached. Try again later.") from exc
        if exc.code == 403:
            raise HTTPException(403, "GitHub denied access. Only public repositories are supported.") from exc
        if exc.code == 404:
            raise HTTPException(404, "Public GitHub repository or branch was not found.") from exc
        raise HTTPException(502, "GitHub could not complete the request.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(502, "Could not reach GitHub. Try again.") from exc
    if len(data) > max_bytes:
        raise HTTPException(413, "GitHub repository archive exceeds the upload size limit.")
    return data


def _github_archive(owner: str, repo: str, sha: str) -> bytes:
    url = f"https://codeload.github.com/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}/zip/{sha}"
    request = urllib.request.Request(url, headers={"Accept": "application/zip", "User-Agent": "PatchGuard-MVP"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if urllib.parse.urlsplit(response.geturl()).hostname != "codeload.github.com":
                raise HTTPException(502, "GitHub returned an unexpected archive location.")
            data = response.read(MAX_UPLOAD + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(404, "Public GitHub repository or commit was not found.") from exc
        if exc.code == 429:
            raise HTTPException(429, "GitHub is temporarily rate limiting archive downloads. Try again later.") from exc
        raise HTTPException(502, "GitHub could not download this repository snapshot.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(502, "Could not download this GitHub repository. Try again.") from exc
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "GitHub repository archive exceeds the upload size limit.")
    return data


def _github_json(path: str, token: str):
    try:
        result = json.loads(_github_request(path, token).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(502, "GitHub returned an invalid response.") from exc
    return result


def _github_repo_path(full_name: str) -> tuple[str, str, str]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", full_name):
        raise HTTPException(400, "Choose a valid public GitHub repository.")
    owner, repo = full_name.split("/", 1)
    return owner, repo, f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"


def _github_snapshot(provider_token: str, full_name: str) -> tuple[bytes, dict]:
    owner, repo_name, repo_path = _github_repo_path(full_name)
    repo = _github_json(repo_path, provider_token)
    if not isinstance(repo, dict) or repo.get("private"):
        raise HTTPException(404, "Only public GitHub repositories can be scanned.")
    branch = repo.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise HTTPException(422, "GitHub repository does not have a default branch.")
    commit = _github_json(f"{repo_path}/commits/{urllib.parse.quote(branch, safe='')}", provider_token)
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
        raise HTTPException(502, "GitHub did not return a valid commit for the default branch.")
    archive = _github_archive(owner, repo_name, sha)
    metadata = {"type": "github", "repository": f"{owner}/{repo_name}", "branch": branch, "commit_sha": sha}
    return archive, metadata


@app.post("/api/github/repositories")
def github_repositories(payload: GitHubRepositoriesRequest, request: Request) -> dict:
    _current_user(request)
    _auth_rate_limit(request, "github_repositories", 60)
    repositories = _github_json(f"/user/repos?visibility=public&sort=updated&per_page=100&page={payload.page}", payload.provider_token)
    if not isinstance(repositories, list):
        raise HTTPException(502, "GitHub returned an invalid repository list.")
    return {"next_page": payload.page + 1 if len(repositories) == 100 else None, "repositories": [
        {"full_name": item["full_name"], "default_branch": item["default_branch"], "description": item.get("description"), "updated_at": item.get("updated_at")}
        for item in repositories
        if isinstance(item, dict) and not item.get("private") and isinstance(item.get("full_name"), str) and isinstance(item.get("default_branch"), str) and item["full_name"] and item["default_branch"]
    ]}


@app.post("/api/github/scan", status_code=202)
async def github_scan(payload: GitHubScanRequest, request: Request) -> dict:
    _current_user(request)
    _auth_rate_limit(request, "github_scan", 20)
    archive, source = await asyncio.to_thread(_github_snapshot, payload.provider_token, payload.full_name)
    upload = UploadFile(file=io.BytesIO(archive), filename=f"{source['repository'].split('/')[-1]}.zip")
    return await _create_job(request, [upload], "auto", source)


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


@contextmanager
def _locked_job(job_id: str, owner_id: str):
    _job_key(job_id)
    try:
        with locked_job(job_id, owner_id) as job:
            yield job
    except KeyError as exc:
        raise HTTPException(404, "Job not found or expired.") from exc


def _repair_path(job_id: str, repair_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f-]{36}", repair_id):
        raise HTTPException(404, "Repair proposal not found.")
    return JOBS_ROOT / job_id / "repairs" / f"{repair_id}.json"


def _build_repair_context(before: str, finding: dict, cwe: dict, source_root: Path, target: Path, deep: bool = False, verification_feedback: str = "No previous verification results.") -> dict:
    lines = before.splitlines(keepends=True)
    line = int(finding["line"])
    if line < 1 or line > len(lines):
        raise HTTPException(422, "Finding location is outside the source file.")
    context_limit = MAX_DEEP_REPAIR_CONTEXT_CHARS if deep else MAX_REPAIR_CONTEXT_CHARS
    radius = 120 if deep else 40
    start, end = max(0, line - radius - 1), min(len(lines), line + radius)
    while sum(map(len, lines[start:end])) > context_limit and end - start > 1:
        if line - start > end - line:
            start += 1
        else:
            end -= 1
    localized = "".join(lines[start:end])
    if len(localized) > context_limit:
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
        "verification_feedback": verification_feedback[:8_000] if deep else "No previous verification results.",
        "scope_start": sum(map(len, lines[:start])),
        "scope_end": sum(map(len, lines[:end])),
        "scope_start_line": start + 1,
        "scope_end_line": end,
        "headers": "\n\n".join(headers) or "No bounded project headers were included.",
        "includes": "".join(line for line in lines if re.match(r"^\s*#\s*include\s*[<\"]", line))[:2000] or "No include lines.",
    }


def _validate_edits(before: str, edits: list[dict], scope_start: int, scope_end: int) -> tuple[str, list[dict], int, int]:
    if not edits:
        raise ValueError("no_change: Repair contains no source edits.")
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
            raise ValueError(f"missing_context: Edit {index + 1} does not match lines {first}-{last}.")
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
                raise ValueError("include_context: Include edit must only add one standard include after its anchor.")
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


def _rejected_attempt(exc: Exception, result, before: str, attempt: int) -> dict:
    technical = str(exc)[:500]
    code = technical.split(":", 1)[0]
    if code not in {"missing_context", "text_mismatch", "wrong_range", "ambiguous_context", "overlap", "scope_violation", "include_context", "no_change", "size_limit", "mixed_line_endings", "invalid_path"}:
        code = "provider_unavailable" if isinstance(exc, RuntimeError) else "invalid_schema"
    match = re.search(r"Edit (\d+)", technical)
    edit_index = int(match.group(1)) if match else None
    snippets = []
    budget = 12_000
    for index, edit in enumerate(result.edits if result else []):
        if index >= 8 or budget <= 0:
            break
        first, last = edit.start_line, edit.end_line
        source_lines = before.splitlines(keepends=True)
        actual = "".join(source_lines[first - 1:last]) if 1 <= first <= last <= len(source_lines) else ""
        limit = min(2_000, budget // 3)
        snippets.append({"edit_index": index + 1, "start_line": first, "end_line": last,
                         "actual": actual[:limit], "expected": edit.original[:limit],
                         "replacement": edit.replacement[:limit], "reason": edit.reason[:500],
                         "truncated": any(len(value) > limit for value in (actual, edit.original, edit.replacement))})
        budget -= sum(len(snippets[-1][key]) for key in ("actual", "expected", "replacement"))
    failed = next((item for item in snippets if item["edit_index"] == edit_index), None)
    location = f" at line {failed['start_line']}" if failed else ""
    message = (f"The AI suggested replacing code that does not match your uploaded file{location}."
               if code in ("text_mismatch", "missing_context", "ambiguous_context", "wrong_range")
               else "The suggestion did not pass the repair safety checks.")
    if code == "provider_unavailable":
        message = "The AI provider could not generate a suggestion. Check provider availability or try again later."
    if attempt >= MAX_REPAIR_ATTEMPTS:
        message += " The suggestion limit has been reached; human review is required."
    message += " Your original code is unchanged. Build and security verification have not started."
    return {"attempt": attempt, "at": time.time(), "code": code,
            "stage": "generating" if code == "provider_unavailable" else "checking edits",
            "edit_index": edit_index, "start_line": failed["start_line"] if failed else None,
            "end_line": failed["end_line"] if failed else None, "message": message,
            "technical": technical, "retryable": attempt < MAX_REPAIR_ATTEMPTS, "edits": snippets}


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
            "groq": {"configured": groq_configured, "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
                     "deep_model": os.getenv("GROQ_DEEP_MODEL", "openai/gpt-oss-120b")},
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
            severity: sum((f.get("severity") if f.get("severity") in {"critical", "high", "medium", "low", "informational"} else "unassessed") == severity for f in open_findings)
            for severity in ("critical", "high", "medium", "low", "informational", "unassessed")
        },
    }


@app.get("/api/weaknesses")
def weaknesses() -> dict:
    data = catalog()
    return {"version": data["version"], "schema": data["schema"], "items": supported_weaknesses()}


@app.post("/api/jobs", status_code=202)
async def create_job(request: Request, files: list[UploadFile] = File(default=[]), file: UploadFile | None = File(default=None), provider: str = Form("auto")) -> dict:
    uploads = files or ([file] if file else [])
    return await _create_job(request, uploads, provider)


async def _create_job(request: Request, uploads: list[UploadFile], provider: str, source_metadata: dict | None = None) -> dict:
    if not uploads:
        raise HTTPException(400, "Choose source files or a ZIP project.")
    if len(uploads) > MAX_FILES:
        raise HTTPException(413, f"Upload exceeds the {MAX_FILES} file limit.")
    if provider not in {"none", "auto", "groq", "hosted", "ollama"}:
        raise HTTPException(400, "Choose scan only, automatic, Ollama, or Groq.")
    user = _current_user(request)
    _auth_rate_limit(request, "scan_upload", 30)
    names = [(upload.filename or "").replace("\\", "/") for upload in uploads]
    try:
        for name in names:
            safe_path(name)
    except ProjectInputError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
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
            inspect_archive(zip_path, max_files=MAX_FILES, max_bytes=MAX_EXTRACTED, max_source=MAX_SOURCE)
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
                    validate_text(target.read_bytes(), Path(upload_name).suffix.lower() in SOURCE_EXTENSIONS)
                except UnicodeDecodeError as exc:
                    raise HTTPException(400, "Source files must use UTF-8 encoding.") from exc
    except ProjectInputError as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(exc.status_code, str(exc)) from exc
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
        "id": job_id, "owner_id": user["id"], "name": source_metadata.get("repository", Path(names[0]).name) if source_metadata else Path(names[0]).name, "provider": provider,
        "upload_kind": upload_kind,
        "upload_filename": names[0] if upload_kind == "source" else None,
        "uploaded_files": [PurePosixPath(path).as_posix() for path in names],
        **({"source": source_metadata} if source_metadata else {}),
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


@app.get("/api/jobs/{job_id}/source")
def project_source(job_id: str, request: Request, path: str) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    relative = PurePosixPath(path.replace("\\", "/"))
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise HTTPException(400, "Invalid source path.")
    if Path(relative.name).suffix.lower() not in SOURCE_EXTENSIONS:
        raise HTTPException(415, "Only C/C++ source files can be previewed.")
    root = (JOBS_ROOT / job_id / "source").resolve()
    target = (root / Path(*relative.parts)).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise HTTPException(404, "Source preview is unavailable or has expired.")
    if target.stat().st_size > MAX_SOURCE:
        raise HTTPException(413, "Source file is too large to preview.")
    try:
        data = target.read_bytes()
        content = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "Source preview requires UTF-8 text.") from exc
    return {"file": relative.as_posix(), "original": content,
            "source_hash": hashlib.sha256(data).hexdigest(),
            "expires_at": job.get("expires_at")}


@app.get("/api/jobs/{job_id}/findings/{finding_id}/source")
def finding_source(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    finding = next((item for item in job.get("findings", []) if item.get("id") == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    source = project_source(job_id, request, finding["file"])
    return {**source, "line": finding["line"]}


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
    with _locked_job(job_id, job["owner_id"]) as latest:
        latest.setdefault("explanations", {})[finding_id] = explanation
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
    with _locked_job(job_id, _current_user(request)["id"]) as job:
        finding = next((item for item in job.get("findings", []) if item["id"] == finding_id), None)
        if not finding:
            raise HTTPException(404, "Finding not found.")
        finding["status"] = "false_positive"
    return {"id": finding_id, "status": "false_positive"}


def _proposal_summary(repair: dict) -> dict:
    return {key: repair[key] for key in ("id", "finding_id", "mode", "file", "diff", "explanation", "provider_used", "model_used", "state", "metadata", "review") if key in repair}


@app.get("/api/jobs/{job_id}/repair-status")
def repair_status(job_id: str, request: Request, finding_id: str | None = None) -> dict:
    user_id = _current_user(request)["id"]
    recover_repairs(job_id)
    job = _read_job(job_id, user_id)
    job_operation = job.get("repair_operation") or {}
    operation = job_operation
    if finding_id and operation.get("finding_id") != finding_id:
        operation = {}
    repair = job.get("repair") or {}
    if finding_id and repair.get("finding_id") != finding_id:
        repair = {}
    preview = None
    if repair.get("id") and repair.get("file"):
        try:
            original = project_source(job_id, request, repair["file"])["original"]
            preview = {"original": original, "proposed": repair.get("code", ""),
                       "line": (repair.get("metadata") or {}).get("line")}
        except HTTPException:
            pass
    counts = job.get("repair_attempt_counts", {})
    history = job.get("repair_attempt_history", {})
    attempts = history.get(finding_id, []) if finding_id else operation.get("attempts", [])
    active = job_operation.get("status") in ("queued", "running", "verifying")
    last_operation = job_operation if not finding_id or job_operation.get("finding_id") == finding_id else {}
    last_failed = last_operation.get("status") in ("failed", "timed_out", "human_review") or repair.get("state") == "verification_failed"
    attempts_used = int(counts.get(finding_id, 0)) if finding_id else int(operation.get("attempt_count", 0))
    return {"job_busy": active, "scan_provider": job.get("provider", "none"),
            "attempt_count": attempts_used,
            "max_attempts": MAX_REPAIR_ATTEMPTS,
            "deep_repair_available": bool(os.getenv("GROQ_API_KEY")) and (last_failed or (job.get("provider") == "none" and attempts_used == 0)) and attempts_used < MAX_REPAIR_ATTEMPTS and not active,
            "deep_repair_configured": bool(os.getenv("GROQ_API_KEY")),
            "deep_model": os.getenv("GROQ_DEEP_MODEL", "openai/gpt-oss-120b"),
            "attempt_history": attempts,
            "operation": operation,
            "repair": _proposal_summary(repair) if repair else None,
            "checks": repair.get("checks") if repair else None,
            "preview": preview}


@app.get("/api/jobs/{job_id}/repair/{finding_id}")
def get_repair(job_id: str, finding_id: str, request: Request) -> dict:
    job = _read_job(job_id, _current_user(request)["id"])
    proposal = next((item for item in job.get("proposals", []) if item.get("finding_id") == finding_id and item.get("state") in ("proposed", "validating", "review_ready", "verification_failed")), None)
    if not proposal:
        raise HTTPException(404, "No proposed repair is saved for this finding.")
    return proposal


@app.post("/api/jobs/{job_id}/repair/{finding_id}", status_code=202)
def create_repair(job_id: str, finding_id: str, request: Request, mode: str = "standard") -> dict:
    user_id = _current_user(request)["id"]
    recover_repairs(job_id)
    job = _read_job(job_id, user_id)
    if job["state"] != "complete":
        raise HTTPException(409, "Wait for the scan to finish before generating a repair.")
    if mode not in ("standard", "deep"):
        raise HTTPException(400, "Choose standard or deep repair.")
    if mode == "deep" and not os.getenv("GROQ_API_KEY"):
        raise HTTPException(409, "Deep repair requires Groq. Configure GROQ_API_KEY first.")
    if mode == "standard" and job["provider"] == "none":
        raise HTTPException(409, "This scan was created without AI. Start a new scan to request a repair.")
    finding = next((item for item in job.get("findings", []) if item["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    if finding.get("status") == "false_positive":
        raise HTTPException(409, "False-positive findings do not support automated repair.")
    existing = next((item for item in job.get("proposals", []) if item.get("finding_id") == finding_id and item.get("state") in ("proposed", "validating", "review_ready")), None)
    if existing:
        if existing.get("state") in ("validating", "review_ready"):
            return {"id": existing["id"], "state": existing["state"], "operation_id": (job.get("repair_operation") or {}).get("id")}
    if mode == "deep":
        previous = job.get("repair_operation") or {}
        failed = previous.get("finding_id") == finding_id and previous.get("status") in ("failed", "timed_out", "human_review")
        failed = failed or (job.get("repair", {}).get("finding_id") == finding_id and job.get("repair", {}).get("state") == "verification_failed")
        if job.get("provider") != "none" and not failed:
            raise HTTPException(409, "Try a standard repair first. Deep repair is available after it fails.")
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
    previous_repair = job.get("repair") or {}
    feedback = "No previous verification results."
    if mode == "deep":
        checks = previous_repair.get("checks", {}) if previous_repair.get("finding_id") == finding_id else {}
        feedback = json.dumps({"checks": checks, "attempts": job.get("repair_attempt_history", {}).get(finding_id, []),
                               "previous_error": (job.get("repair_operation") or {}).get("error"),
                               "security_details": checks.get("security_details"), "build_details": checks.get("details")}, ensure_ascii=False)[:8_000]
    context = _build_repair_context(before, finding, cwe, source_root, target, deep=mode == "deep", verification_feedback=feedback)
    if mode == "standard":
        history = job.get("repair_attempt_history", {}).get(finding_id, [])
        if history:
            latest = history[-1]
            context["retry_feedback"] = f"Previous repair was rejected: {latest.get('technical', latest.get('message', 'No details'))}. " + json.dumps(latest.get("edits", []), ensure_ascii=False)[:12_000]
    used_attempts = int(job.get("repair_attempt_counts", {}).get(finding_id, 0))
    if used_attempts >= MAX_REPAIR_ATTEMPTS:
        raise HTTPException(409, "The three-suggestion limit has been reached. Human review is required.")
    now = time.time()
    operation_id = str(uuid.uuid4())
    operation = {"id": operation_id, "finding_id": finding_id, "mode": mode, "stage": "queued for deep repair" if mode == "deep" else "queued for generation",
                 "status": "queued", "started_at": now, "deadline": now + REPAIR_GENERATION_TIMEOUT,
                 "attempt": used_attempts, "attempt_count": used_attempts,
                 "attempts": job.get("repair_attempt_history", {}).get(finding_id, []),
                 "scope_start_line": context["scope_start_line"], "scope_end_line": context["scope_end_line"],
                 "events": [{"at": now, "stage": "queued for deep repair" if mode == "deep" else "queued for generation", "status": "queued",
                             **({"provider": "groq", "model": os.getenv("GROQ_DEEP_MODEL", "openai/gpt-oss-120b")} if mode == "deep" else {})}]}
    if mode == "deep":
        operation.update(provider="groq", model=os.getenv("GROQ_DEEP_MODEL", "openai/gpt-oss-120b"))
    if not begin_repair(job_id, user_id, operation):
        current = _read_job(job_id, user_id).get("repair_operation") or {}
        if current.get("status") in ("queued", "running", "verifying"):
            raise HTTPException(409, "Another repair is already in progress. View its status.")
        raise HTTPException(409, "The repair could not be queued. Refresh the scan and retry.")
    return {"id": operation_id, "operation_id": operation_id, "finding_id": finding_id,
            "state": "queued", "status": "queued"}


@app.post("/api/jobs/{job_id}/repair/{repair_id}/reject")
def reject_repair(job_id: str, repair_id: str, request: Request) -> dict:
    with _locked_job(job_id, _current_user(request)["id"]) as job:
        path = _repair_path(job_id, repair_id)
        try:
            repair = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(404, "Repair proposal not found.") from exc
        current = job.get("repair") or {}
        if current.get("id") == repair_id:
            repair.update(current)
        if repair.get("state") not in ("proposed", "review_ready", "verification_failed"):
            raise HTTPException(409, "Only a completed repair proposal can be rejected.")
        repair["state"] = "rejected"
        path.write_text(json.dumps(repair), encoding="utf-8")
        for proposal in job.get("proposals", []):
            if proposal.get("id") == repair_id:
                proposal["state"] = "rejected"
        if job.get("repair", {}).get("id") == repair_id:
            job["repair"]["state"] = "rejected"
            operation = job.get("repair_operation") or {}
            operation.update(status="complete", stage="review rejected", finished_at=time.time())
        return {"id": repair_id, "state": "rejected"}


@app.post("/api/jobs/{job_id}/apply/{repair_id}")
def apply_repair(job_id: str, repair_id: str, request: Request, confirm_partial: bool = False, confirm_human_review: bool = False) -> dict:
    user_id = _current_user(request)["id"]
    moved = []
    try:
        with _locked_job(job_id, user_id) as job:
            return _accept_candidate(job_id, repair_id, user_id, job, confirm_partial, confirm_human_review, moved)
    except Exception:
        for patched, candidate, record, original in moved:
            if patched.exists() and not candidate.exists():
                os.rename(patched, candidate)
            record.write_text(original, encoding="utf-8")
        raise


def _accept_candidate(job_id, repair_id, user_id, job, confirm_partial, confirm_human_review, moved):
    repair_path = _repair_path(job_id, repair_id)
    try:
        original_record = repair_path.read_text(encoding="utf-8")
        repair = json.loads(original_record)
    except (OSError, json.JSONDecodeError):
        raise HTTPException(404, "Repair proposal expired.")
    current = job.get("repair") or {}
    if current.get("id") != repair_id or current.get("state") != "review_ready":
        raise HTTPException(409, "This repair has not finished verification or is no longer available.")
    outcome = verification_outcome(current.get("checks") or {})
    if outcome not in ("verified", "partially_verified"):
        raise HTTPException(409, "This repair cannot be accepted because verification failed or is unavailable.")
    if not confirm_human_review:
        raise HTTPException(409, "Review the original and proposed code and diagnostics before accepting this repair.")
    if outcome == "partially_verified" and not confirm_partial:
        raise HTTPException(409, "Confirm acceptance with unavailable checks before continuing.")
    repair.update(current)
    repair["review"] = {"reviewed_by": user_id, "reviewed_at": time.time(), "verification_outcome": outcome}
    source_root = JOBS_ROOT / job_id / "source"
    target = (source_root / repair.get("file", "")).resolve()
    if not target.is_relative_to(source_root.resolve()) or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != repair.get("source_hash"):
        raise HTTPException(409, "Source changed since proposal generation. Generate a new repair.")
    candidate = JOBS_ROOT / job_id / "candidates" / repair_id
    if not candidate.is_dir() or _tree_hash(candidate) != repair.get("candidate_hash"):
        raise HTTPException(409, "The verified candidate changed or expired. Generate a new repair.")
    patched_root = JOBS_ROOT / job_id / "patched"
    if patched_root.exists():
        raise HTTPException(409, "A working copy already exists. Download it or start a new scan.")
    try:
        os.rename(candidate, patched_root)
        moved.append((patched_root, candidate, repair_path, original_record))
    except FileExistsError as exc:
        raise HTTPException(409, "A working copy already exists. Download it or start a new scan.") from exc
    repair["state"] = "applied_to_copy"
    _repair_path(job_id, repair_id).write_text(json.dumps(repair), encoding="utf-8")
    job["repair"].update(state="applied_to_copy", review=repair["review"])
    job["progress"] = "Verified candidate accepted to working copy"
    for proposal in job.get("proposals", []):
        if proposal.get("id") == repair_id:
            proposal.update(state="applied_to_copy", review=repair["review"])
    operation = job.get("repair_operation") or {}
    if operation.get("id") == repair.get("operation_id"):
        operation.update(status="complete", stage="review complete", finished_at=time.time())
        operation["events"] = (operation.get("events", []) + [{"at": time.time(), "stage": "review complete", "status": "complete"}])[-100:]
    return {"state": "applied_to_copy", "download": f"/api/jobs/{job_id}/download", "checks": current["checks"], "review": repair["review"]}


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
