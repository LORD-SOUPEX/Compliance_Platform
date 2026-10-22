"""Refuse pictographic emoji in tracked text files (docs and UI use SVG icons).

Portable replacement of the former PowerShell hook: runs with any Python 3.8+
on Windows, Linux and macOS. Usage: python scripts/check_emoji.py FILE...
"""

import re
import sys

# Pictographs and the emoji presentation selector. Arrows and box-drawing
# characters used in the documentation stay allowed.
# Built from code points so that the source stays ASCII whatever formatter runs on it.
EMOJI = re.compile(
    "["
    + chr(0x1F000)
    + "-"
    + chr(0x1FAFF)
    + chr(0x2600)
    + "-"
    + chr(0x26FF)
    + chr(0x2B50)
    + chr(0x2B55)
    + chr(0xFE0F)
    + "]"
)


def scan(path):
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except (UnicodeDecodeError, OSError):
        return []
    return [
        f"{path}:{number}:{match.start() + 1}: U+{ord(match.group()):04X}"
        for number, line in enumerate(lines, 1)
        for match in EMOJI.finditer(line)
    ]


def main(paths):
    problems = [problem for path in paths for problem in scan(path)]
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
