from pathlib import Path
import subprocess
import sys


def test_statements_module_imports_as_script():
    package_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-m", "privacy_protocol.statements"],
        cwd=package_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
