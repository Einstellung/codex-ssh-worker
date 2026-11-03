import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .config import DEFAULT_PRIVATE, load_settings
from .privacy import make_redactor


def main():
    os.umask(0o077)
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    parser = argparse.ArgumentParser(description="Private execution worker; do not expose its administrative commands to Claude.")
    parser.add_argument("mode", choices=("serve", "mcp", "internal", "filter", "check"))
    parser.add_argument("--private-dir", type=Path, default=DEFAULT_PRIVATE)
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--target", default="gpu-server")
    parser.add_argument("--job")
    args = parser.parse_args()
    socket_path = args.socket or args.private_dir / "worker.sock"
    try:
        if args.mode == "mcp":
            from .mcp_api import public_mcp
            public_mcp(socket_path)
        elif args.mode == "serve":
            from .service import serve
            serve(args.private_dir, socket_path)
        elif args.mode == "internal":
            from .mcp_api import internal_mcp
            internal_mcp(args.private_dir, args.target, args.job)
        else:
            private, settings, credentials, policy = load_settings(args.private_dir)
            redactor = make_redactor(settings, credentials, policy, private)
            if args.mode == "filter":
                result = redactor.clean(json.load(sys.stdin))
            else:
                from .remote import Remote
                result = Remote(private, settings, credentials, args.target).execute("python3 --version", timeout=20)
                result = redactor.clean(result)
            print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    except Exception:
        print('{"error_code":"worker_operation_failed"}', file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
