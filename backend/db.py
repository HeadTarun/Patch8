"""Small PostgreSQL persistence layer backed by Supabase Postgres."""
from __future__ import annotations

import json
import os
import time

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
            "SELECT payload FROM public.patchguard_jobs WHERE payload->>'owner_id' = %s AND expires_at > now() ORDER BY created_at DESC LIMIT %s",
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
    recover_repairs()
    with connect() as conn:
        row = conn.execute(
            """WITH candidate AS (
                 SELECT id FROM public.patchguard_jobs
                 WHERE state IN ('queued', 'validating') AND expires_at > now()
                 ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
               )
               UPDATE public.patchguard_jobs AS job
               SET state = CASE WHEN job.state = 'queued' THEN 'analyzing' ELSE 'verifying' END,
                   payload = jsonb_set(job.payload, '{state}', to_jsonb(CASE WHEN job.state = 'queued' THEN 'analyzing'::text ELSE 'verifying'::text END)),
                   updated_at = now()
               FROM candidate WHERE job.id = candidate.id
               RETURNING job.id::text, job.payload"""
        ).fetchone()
        if row and row[1].get("state") == "verifying":
            operation = row[1].get("repair_operation", {})
            operation.update(status="verifying", lease_until=time.time() + 120)
            conn.execute("UPDATE public.patchguard_jobs SET payload = jsonb_set(payload, '{repair_operation}', %s::jsonb) WHERE id = %s", (json.dumps(operation), row[0]))
            row[1]["repair_operation"] = operation
    return (row[0], row[1]) if row else None


def delete_expired_jobs() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM public.patchguard_jobs WHERE expires_at <= now()")




def begin_repair(job_id: str, owner_id: str, operation: dict) -> bool:
    with connect() as conn:
        row = conn.execute("""UPDATE public.patchguard_jobs SET payload = jsonb_set(payload, '{repair_operation}', %s::jsonb), updated_at = now()
            WHERE id = %s AND payload->>'owner_id' = %s AND state = 'complete' AND expires_at > now()
            AND (payload->'repair_operation' IS NULL OR payload->'repair_operation'->>'status' NOT IN ('running', 'queued', 'verifying') OR COALESCE((payload->'repair_operation'->>'deadline')::double precision, 0) < EXTRACT(EPOCH FROM now())) RETURNING id""", (json.dumps(operation), job_id, owner_id)).fetchone()
        return bool(row)


def update_repair_operation(job_id: str, operation_id: str, changes: dict) -> bool:
    with connect() as conn:
        row = conn.execute("""SELECT payload->'repair_operation' FROM public.patchguard_jobs
            WHERE id = %s AND payload->'repair_operation'->>'id' = %s AND payload->'repair_operation'->>'status' IN ('running', 'queued', 'verifying') AND expires_at > now() FOR UPDATE""", (job_id, operation_id)).fetchone()
        if not row:
            return False
        operation = row[0]
        if any(key in changes and changes[key] != operation.get(key) for key in ("stage", "status", "provider", "check_states")):
            operation["events"] = (operation.get("events", []) + [{"at": time.time(), "stage": changes.get("stage", operation.get("stage")), "status": changes.get("status", operation.get("status")), "provider": changes.get("provider", operation.get("provider")), "attempt": changes.get("attempt", operation.get("attempt"))}])[-100:]
        operation.update(changes)
        if operation.get("status") in ("failed", "complete"):
            operation.setdefault("finished_at", time.time())
        conn.execute("UPDATE public.patchguard_jobs SET payload = jsonb_set(payload, '{repair_operation}', %s::jsonb), updated_at = now() WHERE id = %s", (json.dumps(operation), job_id))
        return True


def enqueue_repair(job_id: str, operation_id: str, repair: dict, proposal: dict) -> bool:
    with connect() as conn:
        row = conn.execute("""UPDATE public.patchguard_jobs SET state = 'validating', payload = payload || jsonb_build_object('state', 'validating', 'repair', %s::jsonb, 'checks', %s::jsonb, 'proposals', COALESCE(payload->'proposals', '[]'::jsonb) || jsonb_build_array(%s::jsonb), 'repair_operation', payload->'repair_operation' || jsonb_build_object('stage', 'queued for verification', 'status', 'queued', 'candidate_id', %s::text, 'deadline', EXTRACT(EPOCH FROM now()) + 1200, 'lease_until', EXTRACT(EPOCH FROM now()) + 300, 'events', COALESCE(payload->'repair_operation'->'events', '[]'::jsonb) || jsonb_build_array(jsonb_build_object('at', EXTRACT(EPOCH FROM now()), 'stage', 'queued for verification', 'status', 'queued')))), updated_at = now()
            WHERE id = %s AND state = 'complete' AND payload->'repair_operation'->>'id' = %s AND payload->'repair_operation'->>'status' = 'running' AND expires_at > now() RETURNING id""", (json.dumps(repair), json.dumps(repair['checks']), json.dumps(proposal), repair['id'], job_id, operation_id)).fetchone()
        return bool(row)


def finish_repair(job_id: str, operation_id: str, candidate_id: str, checks: dict, performance=None, error=None) -> bool:
    """Publish worker results only for the still-active candidate, retaining other job fields."""
    with connect() as conn:
        row = conn.execute("""SELECT payload FROM public.patchguard_jobs WHERE id = %s
            AND payload->'repair_operation'->>'id' = %s AND payload->'repair_operation'->>'status' = 'verifying'
            AND payload->'repair'->>'id' = %s AND expires_at > now() FOR UPDATE""", (job_id, operation_id, candidate_id)).fetchone()
        if not row:
            return False
        job = row[0]
        ready = checks.get("verification_outcome") in ("verified", "partially_verified")
        job["repair"].update(checks=checks, state="review_ready" if ready else "verification_failed")
        for proposal in job.get("proposals", []):
            if proposal.get("id") == candidate_id:
                proposal["state"] = job["repair"]["state"]
        stage = "review ready" if ready else "verification failed"
        op = job["repair_operation"]
        op.update(status="failed" if error else "complete", stage=stage, finished_at=time.time(), check_states={key: checks.get(key, "not_available") for key in ("build", "tests", "sanitizers", "security")})
        if error:
            op["error"] = error
        op["events"] = (op.get("events", []) + [{"at": time.time(), "stage": stage, "status": op["status"]}])[-100:]
        fields = {"repair": job["repair"], "proposals": job.get("proposals", []), "repair_operation": op, "checks": checks, "performance": performance, "state": "complete", "progress": f"Repair verification: {checks['verification_outcome']}"}
        conn.execute("UPDATE public.patchguard_jobs SET state = 'complete', payload = payload || %s::jsonb, updated_at = now() WHERE id = %s", (json.dumps(fields), job_id))
        return True


def recover_repairs(job_id: str | None = None) -> None:
    """Expire abandoned requests and worker leases without accepting late results."""
    with connect() as conn:
        rows = conn.execute("""SELECT id, payload FROM public.patchguard_jobs WHERE expires_at > now()
            AND (%s::text IS NULL OR id::text = %s)
            AND payload->'repair_operation'->>'status' IN ('running', 'queued', 'verifying')
            AND (COALESCE((payload->'repair_operation'->>'deadline')::double precision, 0) < EXTRACT(EPOCH FROM now())
                OR (payload->'repair_operation'->>'status' IN ('queued', 'verifying') AND COALESCE((payload->'repair_operation'->>'lease_until')::double precision, (payload->'repair_operation'->>'deadline')::double precision, 0) < EXTRACT(EPOCH FROM now())))
            FOR UPDATE SKIP LOCKED""", (job_id, job_id)).fetchall()
        for identifier, job in rows:
            op = job["repair_operation"]
            op.update(status="failed", finished_at=time.time(), error="This operation was interrupted or timed out. Your original code is unchanged. Retry the repair.")
            op["events"] = (op.get("events", []) + [{"at": time.time(), "stage": op.get("stage"), "status": "failed"}])[-100:]
            fields = {"repair_operation": op, "state": "complete"}
            if op.get("candidate_id") == (job.get("repair") or {}).get("id"):
                checks = {"build": "not_available", "tests": "not_available", "sanitizers": "not_available", "security": "unverified", "verification": "unverified", "verification_outcome": "not_verified", "details": "Verification was interrupted; results are incomplete."}
                job["repair"].update(state="verification_failed", checks=checks)
                fields.update(repair=job["repair"], checks=checks)
                fields["proposals"] = [{**p, "state": "verification_failed"} if p.get("id") == op.get("candidate_id") else p for p in job.get("proposals", [])]
            conn.execute("UPDATE public.patchguard_jobs SET state = 'complete', payload = payload || %s::jsonb, updated_at = now() WHERE id = %s", (json.dumps(fields), identifier))
