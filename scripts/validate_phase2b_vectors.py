from __future__ import annotations

import sys

from libp2p_privacy_poc.privacy_protocol.test_vectors import phase2b_vectors


def main() -> int:
    data = phase2b_vectors.load_vectors()
    errors = phase2b_vectors.validate_vectors(data)
    if errors:
        for error in errors:
            print(f"phase2b_vectors.json: {error}")
        return 1
    print("phase2b_vectors.json: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
