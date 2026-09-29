"""Read one Worker token from a pipe and protect it with Windows DPAPI."""

import argparse
from pathlib import Path
import sys
from uuid import UUID

from .credential_store import WindowsDpapiCredentialStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Store a Worker token")
    parser.add_argument("--worker-id", type=UUID, required=True)
    parser.add_argument("--store-path", type=Path)
    args = parser.parse_args()
    if sys.stdin.isatty():
        raise SystemExit("Provide the token through stdin, not an interactive prompt")
    token = sys.stdin.read().rstrip("\r\n")
    WindowsDpapiCredentialStore(args.store_path).save(args.worker_id, token)
    print("Worker credential stored")


if __name__ == "__main__":
    main()
