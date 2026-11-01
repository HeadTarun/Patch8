"""One acceptance policy for worker results and API review actions."""
CHECKS = ("build", "tests", "sanitizers", "security")


def verification_outcome(checks: dict) -> str:
    values = [checks.get(name) for name in CHECKS]
    if "failed" in values:
        return "failed"
    if checks.get("security") != "passed" or any(value in {None, "pending", "running", "not_run"} for value in values):
        return "not_verified"
    if all(value == "passed" for value in values):
        return "verified"
    if all(value in {"passed", "not_available", "unverified"} for value in values):
        return "partially_verified"
    return "not_verified"
