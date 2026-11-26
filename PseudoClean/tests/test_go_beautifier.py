"""Offline Go Beautifier Test Runner & Ground-Truth Comparator.

Runs `go_beautifier.py` against `testbin/golang/dump_go_idioms.c` (with
offline `.rodata` resolution from `testbin/golang/test_go_stripped`)
and prints a side-by-side summary vs `testbin/golang/go_idioms.go`.

Usage:
    python PseudoClean/tests/test_go_beautifier.py
"""

from __future__ import annotations

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_PKG)
for _p in (_HERE, _PKG):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import ida_stub
ida_stub.install()

import go_beautifier as GB


DUMP_PATH = os.path.join(_ROOT, "testbin", "golang", "dump_go_idioms.c")
GROUND_TRUTH_PATH = os.path.join(_ROOT, "testbin", "golang", "go_idioms.go")
ELF_PATH = os.path.join(_ROOT, "testbin", "golang", "test_go_stripped")


def split_dump_functions(dump_text: str) -> list[tuple[str, str]]:
    """Splits dump_go_idioms.c into [(func_header, func_code), ...]."""
    chunks = re.split(r'(?=^// === .+ ===)', dump_text, flags=re.MULTILINE)
    funcs = []
    for ch in chunks:
        ch = ch.strip()
        if not ch:
            continue
        m = re.match(r'^// === (.+?) ===', ch)
        name = m.group(1) if m else "unknown"
        funcs.append((name, ch))
    return funcs


def main() -> int:
    with open(DUMP_PATH, "r", encoding="utf-8") as f:
        dump_text = f.read()
    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
        gt_text = f.read()

    # Configure offline ELF .rodata resolver if supported
    if hasattr(GB, "set_offline_elf_path") and os.path.exists(ELF_PATH):
        GB.set_offline_elf_path(ELF_PATH)

    funcs = split_dump_functions(dump_text)
    print(f"Loaded {len(funcs)} functions from dump_go_idioms.c")
    print(f"Ground truth: {len(gt_text.splitlines())} lines in go_idioms.go")
    print("=" * 72)

    target_prefixes = (
        "main.idiomStringSlice",
        "main.idiomFileCLI @",
        "main.idiomControlFlow @",
        "main._ptr_XorProcessor.Process",
        "main.idiomDataStructures",
        "main.idiomConcurrency @",
        "main.idiomCryptoEncoding",
        "main.main",
    )

    for hdr, code in funcs:
        if not any(hdr.startswith(p) for p in target_prefixes):
            continue
        beautified = GB.beautify_go_pseudocode(code)
        raw_lines = len(code.splitlines())
        clean_lines = len(beautified.splitlines())
        print(f"\n>>> {hdr}  (raw: {raw_lines} lines -> clean: {clean_lines} lines)")
        print("-" * 72)
        print(beautified)

    return 0


if __name__ == "__main__":
    sys.exit(main())
