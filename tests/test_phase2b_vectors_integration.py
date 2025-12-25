from pathlib import Path
import subprocess
import sys


def test_phase2b_vectors_validation_script():
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "validate_phase2b_vectors.py"

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
