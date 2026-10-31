"""Supabase Auth client and short-lived, signed workspace session cookies."""
from __future__ import annotations

import base64
import hmac
import json
import os
import time
import urllib.error
import urllib.request

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _secret() -> bytes:
    value = os.getenv("AUTH_SECRET", "")
    if len(value) < 32 or value.startswith("replace-with-"):
        raise RuntimeError("Set AUTH_SECRET to at least 32 random characters before using accounts.")
    return value.encode()


def supabase_auth(path: str, payload: dict) -> dict:
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
    if not base or not key:
        raise RuntimeError("Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY to enable accounts.")
    request = urllib.request.Request(
        f"{base}/auth/v1/{path.lstrip('/')}", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "apikey": key}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            details = json.loads(exc.read().decode())
            message = details.get("msg") or details.get("message") or details.get("error_description")
        except (ValueError, UnicodeDecodeError):
            message = None
        raise RuntimeError(message or "Supabase Auth rejected the request.") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError("Could not reach Supabase Auth.") from exc


def supabase_user(access_token: str) -> dict:
    base = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
    if not base or not key:
        raise RuntimeError("Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY to enable accounts.")
    request = urllib.request.Request(
        f"{base}/auth/v1/user",
        headers={"apikey": key, "Authorization": f"Bearer {access_token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError("Supabase Auth rejected the confirmation session.") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError("Could not reach Supabase Auth.") from exc


def issue_session(user_id: str, email: str, lifetime: int = 28800) -> str:
    payload = _b64(json.dumps({"id": user_id, "email": email, "exp": int(time.time()) + lifetime}, separators=(",", ":")).encode())
    signature = hmac.new(_secret(), payload.encode(), "sha256").digest()
    return f"{payload}.{_b64(signature)}"


def read_session(token: str) -> dict | None:
    try:
        payload, signature = token.split(".", 1)
        expected = _b64(hmac.new(_secret(), payload.encode(), "sha256").digest())
        if not hmac.compare_digest(signature, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if int(data["exp"]) <= time.time():
            return None
        return data
    except (RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
