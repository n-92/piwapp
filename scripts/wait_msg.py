"""Block until a new line appears in convo_in.log beyond a baseline, print it, exit.

Used to make the live conversation event-driven: the agent launches this in the
background; when a new incoming message is logged, it exits and prints the new
line(s), which notifies the agent. Re-arm after each response.

Usage: python scripts/wait_msg.py <baseline_line_count> [timeout_seconds]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

LOG = Path("convo_in.log")


def main() -> int:
    baseline = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 540.0
    deadline = time.time() + timeout
    while time.time() < deadline:
        lines = LOG.read_text(encoding="utf-8").splitlines() if LOG.exists() else []
        if len(lines) > baseline:
            for line in lines[baseline:]:
                print(line, flush=True)
            print(f"__TOTAL_LINES__={len(lines)}", flush=True)
            return 0
        time.sleep(1.0)
    cur = len(LOG.read_text(encoding="utf-8").splitlines()) if LOG.exists() else baseline
    print(f"__NO_NEW_MESSAGES__ __TOTAL_LINES__={cur}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
