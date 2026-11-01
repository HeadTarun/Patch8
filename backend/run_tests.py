"""Run isolated unit tests without loading local credentials or using OS temp folders."""
import faulthandler
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

root = Path(__file__).resolve().parent
work = Path(os.getenv("PATCH8_TEST_WORK", str(root.parent / ".test-work")))
work.mkdir(exist_ok=True)
tempfile.tempdir = str(work)
os.environ["WORK_ROOT"] = str(work / "worker")
os.environ["SUPABASE_DB_URL"] = ""
for key in ("GROQ_API_KEY", "OPENAI_API_KEY", "SUPABASE_PUBLISHABLE_KEY", "DEMO_EMAIL", "DEMO_PASSWORD"):
    os.environ.pop(key, None)

if __name__ == "__main__":
    faulthandler.dump_traceback_later(120, exit=True)
    with patch("dotenv.load_dotenv", return_value=False), patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Unexpected live HTTP request in unit test")):
        suite = unittest.defaultTestLoader.discover(str(root), pattern="test_*.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    faulthandler.cancel_dump_traceback_later()
    raise SystemExit(not result.wasSuccessful())
