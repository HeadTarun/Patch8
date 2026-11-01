"""Small PostgreSQL persistence layer backed by Supabase Postgres."""
from __future__ import annotations

import json
import os
import time
from dotenv import load_dotenv
from contextlib import contextmanager
from verification import verification_outcome

# Load environment variables from the .env file (if present)
load_dotenv()

DATABASE_URL = os.getenv("SUPABASE_DB_URL", "")


def connect():
    if not DATABASE_URL:
        raise RuntimeError("SUPABASE_DB_URL is not configured. Set it to the Supabase Postgres connection string.")
    import psycopg

    return psycopg.connect(DATABASE_URL, connect_timeout=5)


def get_job(job_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT payload FROM public.patchguard_jobs WHERE id = %s AND expires_at > now()",
            (job_id,),
        ).fetchone()
    return row[0] if row else None


def list_user_jobs(owner_id: str, limit: int = 100) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """SELECT payload FROM public.patchguard_jobs
               WHERE payload->>'owner_id' = %s AND expires_at > now()
               ORDER BY created_at DESC LIMIT %s""",
            (owner_id, limit),
        ).fetchall()
    return [row[0] for row in rows]


def save_job(job: dict) -> None:
    expires_at = float(job.get("expires_at", time.time() + 3600))
    created_at = float(job.get("created_at", time.time()))
    with connect() as conn:
        conn.execute(
            """INSERT INTO public.patchguard_jobs (id, state, created_at, expires_at, payload, updated_at)
               VALUES (%s, %s, to_timestamp(%s), to_timestamp(%s), %s::jsonb, now())
               ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state,
                 expires_at = EXCLUDED.expires_at, payload = EXCLUDED.payload, updated_at = now()""",
            (job["id"], job.get("state", "queued"), created_at, expires_at, json.dumps(job)),
        )


def claim_job() -> tuple[str, dict] | None:
    """Claim the oldest pending job atomically; concurrent workers skip locked rows."""
    with connect() as conn:
        row = conn.execute(
            """WITH candidate AS (
                 SELECT id FROM public.patchguard_jobs
                 WHERE state IN ('queued', 'validating') AND expires_at > now()
                 ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
               )
               UPDATE public.patchguard_jobs AS job
               SET state = CASE WHEN job.state = 'queued' THEN 'analyzing' ELSE 'verifying' END,
                   payload = jsonb_set(job.payload, '{state}', to_jsonb(CASE WHEN job.state = 'queued' THEN 'analyzing'::text ELSE 'verifying'::text END)) || CASE WHEN job.state = 'queued' THEN jsonb_build_object('scan_lease_until', extract(epoch from now()) + 120) ELSE '{}'::jsonb END,
                   updated_at = now()
               FROM candidate WHERE job.id = candidate.id
               RETURNING job.id::text, job.payload"""
        ).fetchone()
    return (row[0], row[1]) if row else None


def begin_repair(job_id: str, owner_id: str, operation: dict) -> bool:
    with connect() as conn:
        row = conn.execute(
            """UPDATE public.patchguard_jobs
               SET payload = jsonb_set(payload, '{repair_operation}', %s::jsonb), updated_at = now()
               WHERE id = %s AND payload->>'owner_id' = %s AND state = 'complete' AND expires_at > now()
                 AND (payload->'repair_operation' IS NULL
                   OR payload->'repair_operation'->>'status' NOT IN ('queued', 'running', 'verifying'))
               RETURNING id""",
            (json.dumps(operation), job_id, owner_id),
        ).fetchone()
    return bool(row)


def claim_repair_generation() -> tuple[str, dict] | None:
    with connect() as conn:
        row = conn.execute(
            """SELECT id::text, payload FROM public.patchguard_jobs
               WHERE expires_at > now()
                 AND payload->'repair_operation'->>'status' = 'queued'
                 AND payload->'repair_operation'->>'stage' IN ('queued for generation', 'queued for deep repair')
               ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED"""
        ).fetchone()
        if not row:
            return None
        job = row[1]
        operation = job.get("repair_operation", {})
        now = time.time()
        if float(operation.get("deadline", 0)) <= now:
            operation.update(status="timed_out", stage="timed out", finished_at=now,
                             error="Repair generation exceeded the 3-minute time limit. Your original source is unchanged.")
        else:
            operation.update(status="running", stage="locating code", lease_until=min(now + 60, float(operation["deadline"])))
        operation["events"] = (operation.get("events", []) + [{"at": now, "stage": operation["stage"], "status": operation["status"]}])[-100:]
        job["repair_operation"] = operation
        conn.execute(
            "UPDATE public.patchguard_jobs SET payload = %s::jsonb, updated_at = now() WHERE id = %s",
            (json.dumps(job), row[0]),
        )
        return (row[0], job) if operation["status"] == "running" else None


def reserve_repair_attempt(job_id: str, operation_id: str) -> int:
    with connect() as conn:
        row = conn.execute(
            "SELECT payload FROM public.patchguard_jobs WHERE id = %s FOR UPDATE", (job_id,)
        ).fetchone()
        if not row:
            return 0
        job = row[0]
        operation = job.get("repair_operation", {})
        now = time.time()
        if operation.get("id") != operation_id or operation.get("status") != "running" or float(operation.get("deadline", 0)) <= now:
            return 0
        finding_id = operation.get("finding_id", "")
        counts = job.setdefault("repair_attempt_counts", {})
        count = int(counts.get(finding_id, 0))
        if count >= 3:
            return 0
        count += 1
        counts[finding_id] = count
        operation.update(attempt=count, attempt_count=count, lease_until=min(now + 60, float(operation["deadline"])))
        job["repair_operation"] = operation
        conn.execute(
            "UPDATE public.patchguard_jobs SET payload = %s::jsonb, updated_at = now() WHERE id = %s",
            (json.dumps(job), job_id),
        )
        return count


def update_repair_operation(job_id: str, operation_id: str, changes: dict) -> bool:
    with connect() as conn:
        row = conn.execute(
            """SELECT payload FROM public.patchguard_jobs WHERE id = %s
               AND payload->'repair_operation'->>'id' = %s
               AND payload->'repair_operation'->>'status' IN ('queued', 'running', 'verifying')
               AND expires_at > now() FOR UPDATE""",
            (job_id, operation_id),
        ).fetchone()
        if not row:
            return False
        job = row[0]
        operation = job["repair_operation"]
        now = time.time()
        if operation.get("status") in ("queued", "running") and float(operation.get("deadline", 0)) <= now:
            return False
        if any(key in changes and changes[key] != operation.get(key) for key in ("stage", "status", "provider", "model", "check_states", "attempt")):
            event = {"at": now, "stage": changes.get("stage", operation.get("stage")),
                     "status": changes.get("status", operation.get("status")),
                     "provider": changes.get("provider", operation.get("provider")),
                     "model": changes.get("model", operation.get("model")),
                     "attempt": changes.get("attempt", operation.get("attempt"))}
            operation["events"] = (operation.get("events", []) + [event])[-100:]
        operation.update(changes)
        if "attempts" in changes:
            history = job.setdefault("repair_attempt_history", {})
            history[operation.get("finding_id", "")] = changes["attempts"]
        if operation.get("status") in ("failed", "timed_out", "human_review", "complete"):
            operation.setdefault("finished_at", now)
        job["repair_operation"] = operation
        conn.execute(
            "UPDATE public.patchguard_jobs SET payload = %s::jsonb, updated_at = now() WHERE id = %s",
            (json.dumps(job), job_id),
        )
        return True


def enqueue_repair(job_id: str, operation_id: str, repair: dict, proposal: dict) -> bool:
    now = time.time()
    with connect() as conn:
        row = conn.execute(
            """SELECT payload FROM public.patchguard_jobs WHERE id = %s AND state = 'complete'
               AND payload->'repair_operation'->>'id' = %s
               AND payload->'repair_operation'->>'status' = 'running' FOR UPDATE""",
            (job_id, operation_id),
        ).fetchone()
        if not row:
            return False
        job = row[0]
        operation = job["repair_operation"]
        if float(operation.get("deadline", 0)) <= now:
            return False
        operation.update(status="verifying", stage="preparing verification", candidate_id=repair["id"],
                         generation_finished_at=now, deadline=now + 1200, lease_until=now + 120,
                         check_states={key: "pending" for key in ("build", "tests", "sanitizers", "security")})
        operation["events"] = (operation.get("events", []) + [{"at": now, "stage": operation["stage"], "status": operation["status"]}])[-100:]
        job.update(state="validating", progress="Verifying the repair candidate", repair=repair,
                   checks=repair["checks"], repair_operation=operation)
        job.setdefault("proposals", []).append(proposal)
        conn.execute(
            "UPDATE public.patchguard_jobs SET state = 'validating', payload = %s::jsonb, updated_at = now() WHERE id = %s",
            (json.dumps(job), job_id),
        )
        return True


def finish_repair(job_id: str, operation_id: str, candidate_id: str, checks: dict, performance=None, error=None) -> bool:
    with connect() as conn:
        row = conn.execute(
            """SELECT payload FROM public.patchguard_jobs WHERE id = %s
               AND payload->'repair_operation'->>'id' = %s
               AND payload->'repair_operation'->>'status' = 'verifying'
               AND payload->'repair'->>'id' = %s FOR UPDATE""",
            (job_id, operation_id, candidate_id),
        ).fetchone()
        if not row:
            return False
        job = row[0]
        checks["verification_outcome"] = verification_outcome(checks)
        ready = checks["verification_outcome"] in ("verified", "partially_verified")
        state = "review_ready" if ready else "verification_failed"
        job["repair"].update(checks=checks, state=state)
        for proposal in job.get("proposals", []):
            if proposal.get("id") == candidate_id:
                proposal["state"] = state
        operation = job["repair_operation"]
        operation.update(status="failed" if error else "complete",
                         stage="verification failed" if error or not ready else "review ready",
                         finished_at=time.time(), check_states={key: checks.get(key, "not_available") for key in ("build", "tests", "sanitizers", "security")})
        if error:
            operation["error"] = error
        operation["events"] = (operation.get("events", []) + [{"at": time.time(), "stage": operation["stage"], "status": operation["status"]}])[-100:]
        job.update(state="complete", progress=f"Repair verification: {checks.get('verification_outcome', 'not_verified')}",
                   checks=checks, performance=performance, repair_operation=operation)
        conn.execute(
            "UPDATE public.patchguard_jobs SET state = 'complete', payload = %s::jsonb, updated_at = now() WHERE id = %s",
            (json.dumps(job), job_id),
        )
        return True


def recover_repairs(job_id: str | None = None) -> None:
    now = time.time()
    with connect() as conn:
        rows = conn.execute(
            """SELECT id::text, payload FROM public.patchguard_jobs
               WHERE expires_at > now() AND (%s::text IS NULL OR id::text = %s)
                 AND payload->'repair_operation'->>'status' IN ('queued', 'running', 'verifying')
               FOR UPDATE SKIP LOCKED""",
            (job_id, job_id),
        ).fetchall()
        for identifier, job in rows:
            operation = job.get("repair_operation", {})
            status = operation.get("status")
            deadline_expired = float(operation.get("deadline", 0)) <= now
            generation_expired = status in ("queued", "running") and deadline_expired
            verification_expired = status == "verifying" and (deadline_expired or float(operation.get("lease_until", 0)) <= now)
            if not generation_expired and not verification_expired:
                continue
            operation.update(status="timed_out" if generation_expired else "failed",
                             stage="timed out" if generation_expired else "verification failed",
                             finished_at=now,
                             error="Repair generation exceeded the 3-minute time limit. Your original source is unchanged." if generation_expired else "Verification worker stopped before finishing. Retry the repair.")
            operation["events"] = (operation.get("events", []) + [{"at": now, "stage": operation["stage"], "status": operation["status"]}])[-100:]
            job["repair_operation"] = operation
            fields = {"repair_operation": operation}
            if verification_expired and (job.get("repair") or {}).get("id") == operation.get("candidate_id"):
                checks = {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "security": "unverified", "verification": "unverified", "verification_outcome": "not_verified", "performance": "not_measured", "details": "Verification was interrupted; results are incomplete."}
                job["repair"].update(state="verification_failed", checks=checks)
                job.update(state="complete", checks=checks)
                for proposal in job.get("proposals", []):
                    if proposal.get("id") == operation.get("candidate_id"):
                        proposal["state"] = "verification_failed"
            if job.get("state") != "complete":
                job["state"] = "complete"
            conn.execute(
                "UPDATE public.patchguard_jobs SET state = 'complete', payload = %s::jsonb, updated_at = now() WHERE id = %s",
                (json.dumps(job), identifier),
            )


def delete_expired_jobs() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM public.patchguard_jobs WHERE expires_at <= now()")




@contextmanager
def locked_job(job_id: str, owner_id: str | None = None):
    """Serialize a bounded job mutation without replacing unrelated newer fields."""
    with connect() as conn:
        row = conn.execute(
            "SELECT payload FROM public.patchguard_jobs WHERE id = %s AND expires_at > now() "
            "AND (%s::text IS NULL OR payload->>'owner_id' = %s) FOR UPDATE",
            (job_id, owner_id, owner_id),
        ).fetchone()
        if not row:
            raise KeyError("Job not found or expired")
        job = row[0]
        yield job
        conn.execute("UPDATE public.patchguard_jobs SET state = %s, payload = %s::jsonb, updated_at = now() WHERE id = %s",
                     (job["state"], json.dumps(job), job_id))


def update_job_fields(job_id: str, changes: dict, expected_state: str | None = None) -> dict:
    with locked_job(job_id) as job:
        if expected_state and job.get("state") != expected_state:
            raise RuntimeError("Job ownership expired; start a new scan.")
        job.update(changes)
        return job


def renew_scan_lease(job_id: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE public.patchguard_jobs SET payload = jsonb_set(payload, '{scan_lease_until}', to_jsonb(%s::double precision)) "
                     "WHERE id = %s AND state = 'analyzing' AND expires_at > now()", (time.time() + 120, job_id))


def recover_scans() -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE public.patchguard_jobs SET state = 'failed', payload = payload || %s::jsonb, updated_at = now() "
            "WHERE state = 'analyzing' AND COALESCE((payload->>'scan_lease_until')::double precision, "
            "extract(epoch from updated_at) + 120) < extract(epoch from now())",
            (json.dumps({"state": "failed", "error": "The scan worker stopped before finishing. Upload the project again to retry.", "progress": "Scan interrupted"}),),
        )
