#!/usr/bin/env python3
"""Convert raw Frida JSON-lines output to structured FridaTrace JSON.

Usage: python3 frida_to_json.py <input.json> <output.json>

The Frida script emits one JSON object per line via send(). This script
collects them into the FridaTrace schema expected by the dynamic engine.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def convert_frida_output(raw_text: str) -> dict[str, Any]:
    """Parse Frida JSON-lines output into a FridaTrace dict."""
    entries: list[dict[str, Any]] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            # Frida send() wraps in {"type": "send", "payload": "..."}
            if isinstance(entry, dict) and "payload" in entry:
                payload = entry["payload"]
                if isinstance(payload, str):
                    entry = json.loads(payload)
                else:
                    entry = payload
            entries.append(entry)
        except (json.JSONDecodeError, TypeError):
            continue

    return {
        "version": "1.0",
        "apk_package": None,
        "total_hooks": len(entries),
        "entries": entries,
    }


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        raw = f.read()

    result = convert_frida_output(raw)

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Converted {result['total_hooks']} hooks → {sys.argv[2]}")


if __name__ == "__main__":
    main()
