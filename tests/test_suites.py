"""
Run every tests/suite_*.py in its own Python process.

The suites are end-to-end: they start local HTTP(S) servers and fake
external tools, then run the real CLI against them. Several of them patch
module globals in js_extractor.cli (Playwright, OSV lookups, PATH), so each
one gets a fresh interpreter instead of sharing pytest's.

    pytest                         # all suites
    pytest -k chunks               # one suite
    python tests/suite_chunks.py   # run a suite directly, with full output
"""
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO = TESTS_DIR.parent
SUITES = sorted(TESTS_DIR.glob("suite_*.py"))
TIMEOUT = 600


@pytest.mark.parametrize("suite", SUITES, ids=[s.stem.removeprefix("suite_") for s in SUITES])
def test_suite(suite: Path):
    proc = subprocess.run(
        [sys.executable, "-I", str(suite), str(REPO)],
        capture_output=True, text=True, timeout=TIMEOUT, cwd=REPO,
    )
    out = proc.stdout + proc.stderr
    checks = [l for l in out.splitlines() if l.startswith(("PASS ", "FAIL "))]
    failed = [l for l in checks if l.startswith("FAIL ")]
    summary = f"{len(checks) - len(failed)}/{len(checks)} checks passed"

    if proc.returncode != 0 or failed or "RESULT: ALL PASS" not in out:
        detail = "\n".join(failed) if failed else out[-4000:]
        pytest.fail(f"{suite.name}: {summary}, exit code {proc.returncode}\n{detail}", pytrace=False)
    assert checks, f"{suite.name} reported no checks"
