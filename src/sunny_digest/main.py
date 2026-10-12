from __future__ import annotations

import asyncio
import sys

from .storage import Paths


def main() -> int:
    if (len(sys.argv) < 2 or sys.argv[1] not in ("guardian", "collector", "web", "bootstrap", "configure-origin", "migration-check", "repair-manifest")
            or (sys.argv[1] in {"guardian", "collector", "web"} and len(sys.argv) != 2)):
        print("usage: python -m sunny_digest.main {guardian|collector|web|bootstrap|configure-origin|migration-check|repair-manifest}", file=sys.stderr)
        return 2
    from .memory_guard import protect_process
    protect_process()
    if sys.argv[1] == "guardian":
        from .guardian_ipc import serve
        return asyncio.run(serve(Paths.from_env()))
    elif sys.argv[1] == "collector":
        from .collector import serve
        serve()
    elif sys.argv[1] in ("bootstrap", "configure-origin", "migration-check", "repair-manifest"):
        from .console import main as console_main
        return console_main(sys.argv[1:])
    else:
        from .secure_web import serve
        serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
