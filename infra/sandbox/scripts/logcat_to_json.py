#!/usr/bin/env python3
"""Convert raw logcat text to structured JSON for the dynamic engine.

Usage: python3 logcat_to_json.py <input.txt> <output.json>
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

_THREADTIME_RE = re.compile(
    r"(\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(\S+)\s*:\s*(.*)"
)


def parse_logcat(text: str) -> dict[str, Any]:
    """Parse logcat -v threadtime format into structured JSON."""
    entries: list[dict[str, Any]] = []
    line_num = 0

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        line_num += 1

        match = _THREADTIME_RE.match(line)
        if match:
            _, time_str, pid, tid, level, tag, message = match.groups()
            entries.append({
                "timestamp_ms": line_num,  # pseudo-timestamp from line order
                "level": level,
                "tag": tag,
                "pid": int(pid),
                "message": message,
            })
        else:
            entries.append({
                "timestamp_ms": line_num,
                "level": "I",
                "tag": "unknown",
                "pid": None,
                "message": line,
            })

    return {
        "version": "1.0",
        "entries": entries,
        "total_lines": line_num,
    }


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.txt> <output.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        text = f.read()

    result = parse_logcat(text)

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Converted {result['total_lines']} lines → {sys.argv[2]}")


if __name__ == "__main__":
    main()
