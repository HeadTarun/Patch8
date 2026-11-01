"""Opt-in real local Docker demo; uses only the configured dedicated demo account.

Creates expiring demo scans, requests a proposal, and records evidence without
accepting it on behalf of a human reviewer. Never prints cookies or credentials.
"""
import io
import json
from pathlib import Path
import time
import zipfile

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    with httpx.Client(base_url="http://localhost:8000", timeout=210) as client:
        health = client.get("/api/health")
        print("Health:", health.status_code, flush=True)
        status = client.get("/api/auth/demo/status")
        if not status.is_success or not status.json().get("enabled"):
            print("BLOCKED: dedicated demo credentials are not configured.", flush=True)
            return
        login = client.post("/api/auth/demo")
        print("Real Supabase demo login:", login.status_code, flush=True)
        if not login.is_success:
            return
        providers = client.get("/api/providers")
        print("Provider availability:", json.dumps(providers.json()), flush=True)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as bundle:
            for file in (ROOT / "examples/demo/vulnerable").iterdir():
                bundle.write(file,"patch8-demo/"+file.name)
        response = client.post("/api/jobs",files={"file":("patch8-controlled-demo.zip",archive.getvalue(),"application/zip")},data={"provider":"auto"})
        print("Wrapped demo upload:",response.status_code,flush=True)
        response.raise_for_status()
        identifier=response.json()["id"]
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            job=client.get(f"/api/jobs/{identifier}").json()
            if job["state"] in {"complete","failed"}: break
            time.sleep(2)
        print("Scan:",json.dumps({"id":identifier,"state":job["state"],"report":job.get("report"),"checks":job.get("checks")}),flush=True)
        client.get(f"/api/jobs/{identifier}/sarif").raise_for_status()
        findings=job.get("findings",[])
        if job["state"]!="complete" or not findings:
            return
        finding=findings[0]["id"]
        explanation=client.post(f"/api/jobs/{identifier}/explain/{finding}")
        print("Explanation:",explanation.status_code, "provider="+(explanation.json().get("provider_used", "unavailable")),flush=True)
        generation=client.post(f"/api/jobs/{identifier}/repair/{finding}")
        print("Asynchronous repair:",generation.status_code,flush=True)
        if generation.status_code!=202:return
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            result=client.get(f"/api/jobs/{identifier}/repair-status",params={"finding_id":finding}).json()
            if not result.get("job_busy"):break
            time.sleep(2)
        evidence=ROOT/".test-work/live-demo-evidence.json"
        evidence.parent.mkdir(exist_ok=True)
        evidence.write_text(json.dumps(result,indent=2),encoding="utf-8")
        print("Repair:",json.dumps({"operation":result.get("operation"),"checks":result.get("checks"),"repair":result.get("repair")}),flush=True)
        print("Review evidence saved; no proposal was accepted automatically.",flush=True)


if __name__=="__main__":
    main()
