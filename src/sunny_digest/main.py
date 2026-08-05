from __future__ import annotations

import asyncio
import sys

from .storage import Paths


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("collector", "web"):
        print("usage: python -m sunny_digest.main {collector|web}", file=sys.stderr)
        return 2
    if sys.argv[1] == "collector":
        from .ipc import serve
        asyncio.run(serve(Paths.from_env()))
    else:
        from .web import serve
        serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
