"""Opt-in PostgreSQL integration checks against a disposable localhost database only."""
import concurrent.futures
import os
from pathlib import Path
import time
from unittest.mock import patch
from urllib.parse import urlsplit
import uuid

url = os.environ.get("PATCH8_TEST_DB_URL", "")
parsed = urlsplit(url)
if parsed.hostname not in {"localhost", "127.0.0.1"} or parsed.port != 55439 or parsed.path != "/postgres":
    raise SystemExit("Set PATCH8_TEST_DB_URL to the disposable localhost:55439/postgres database.")
os.environ["SUPABASE_DB_URL"] = url
os.environ["AUTH_SECRET"] = "isolated-db-test-session-secret-" * 3
os.environ["WORK_ROOT"] = str(Path(__file__).resolve().parents[1] / ".test-work" / "db")
with patch("dotenv.load_dotenv", return_value=False):
    import db
    import app
    import auth
from fastapi.testclient import TestClient
import psycopg

with psycopg.connect(url, autocommit=True) as connection:
    connection.execute("DO $$ BEGIN CREATE ROLE anon; EXCEPTION WHEN duplicate_object THEN NULL; END $$")
    connection.execute("DO $$ BEGIN CREATE ROLE authenticated; EXCEPTION WHEN duplicate_object THEN NULL; END $$")
    connection.execute((Path(__file__).resolve().parents[1] / "supabase/migrations/202610310001_patchguard_jobs.sql").read_text())

owner = str(uuid.uuid4())
def new_job(state):
    job = {"id":str(uuid.uuid4()), "owner_id":owner, "state":state, "created_at":time.time(), "expires_at":time.time()+600, "findings":[]}
    db.save_job(job)
    return job

def claim_once(state, expected):
    job = new_job(state)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: db.claim_job(), range(2)))
    claimed = [result for result in results if result]
    assert len(claimed) == 1 and claimed[0][0] == job["id"], results
    assert claimed[0][1]["state"] == expected
    return job

scan = claim_once("queued", "analyzing")
db.update_job_fields(scan["id"], {"scan_lease_until":time.time()-1})
db.recover_scans()
assert db.get_job(scan["id"])["state"] == "failed"
verification = claim_once("validating", "verifying")
db.update_job_fields(verification["id"], {"state":"complete"})

def edit(field):
    with db.locked_job(verification["id"], owner) as job:
        time.sleep(0.05)
        job[field] = {"value":field}
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    list(pool.map(edit, ["explanations", "repair_operation"]))
current=db.get_job(verification["id"])
assert current["explanations"] == {"value":"explanations"}
assert current["repair_operation"] == {"value":"repair_operation"}

client=TestClient(app.app)
assert client.get("/api/jobs").status_code == 401
client.cookies.set("patchguard_session",auth.issue_session(owner,"test@example.com"))
assert client.get(f"/api/jobs/{scan['id']}").status_code == 200
client.cookies.set("patchguard_session",auth.issue_session(str(uuid.uuid4()),"other@example.com"))
for path in ["", "/files", "/source?path=main.c", "/repair-status", "/sarif", "/diff", "/download"]:
    response=client.get(f"/api/jobs/{scan['id']}{path}")
    assert response.status_code == 404, (path,response.status_code)
assert client.get("/api/jobs").json() == []
print("PASS: PostgreSQL exclusive scan/verification claims, lease recovery, transactional updates, and cross-owner API isolation.")
