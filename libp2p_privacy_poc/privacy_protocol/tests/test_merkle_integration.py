from pathlib import Path
import subprocess
import sys


def test_merkle_module_imports():
    package_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-c", "from privacy_protocol.merkle import build_tree"],
        cwd=package_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
