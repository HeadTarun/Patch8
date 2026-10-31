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
               SET state = CASE WHEN job.state = 'queued' THEN 'analyzing' ELSE 'validating' END,
                   payload = jsonb_set(job.payload, '{state}', to_jsonb(CASE WHEN job.state = 'queued' THEN 'analyzing'::text ELSE 'validating'::text END)),
                   updated_at = now()
               FROM candidate WHERE job.id = candidate.id
               RETURNING job.id::text, job.payload"""
        ).fetchone()
    return (row[0], row[1]) if row else None


def delete_expired_jobs() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM public.patchguard_jobs WHERE expires_at <= now()")


