# Contributing to PseudoClean

Thank you for your interest in contributing to **PseudoClean**!

## Core Principles

1. **100% Deterministic & Offline** — No AI/LLMs, no telemetry, no network calls.
2. **Zero External Dependencies** — Use only the Python standard library and modules bundled with IDA Pro 9.4 (`idapython`, `ida_hexrays`, `ida_kernwin`, Qt via `ui/qt_binding.py`).
3. **General Rules Over Hardcoding** — Implement transformation rules based on general compiler/AST idioms (C, Go, Rust), never hardcode per-challenge logic or specific function names.

## Development Setup

```bash
git clone https://github.com/<USERNAME>/<REPO>.git
cd <REPO>
```

To test directly in IDA Pro from WSL, copy `./PseudoClean` into your IDA plugins directory (see the installation instructions in [README.md](README.md)).

## Running Tests

All changes **must** pass the offline test suite before opening a Pull Request:

```bash
python3 PseudoClean/tests/unit_tests.py
python3 PseudoClean/tests/test_go_beautifier.py
```

If you have IDA Pro 9.4 available, you can also run the full verification scripts:

```bash
./testbin/run_tests.sh units
./testbin/run_tests.sh install
```

## Adding Support for New Idioms / Languages

- **C pseudocode**: edit `PseudoClean/c_beautifier.py` (AST passes).
- **Go pseudocode**: edit `PseudoClean/go_beautifier.py` (demangler, `.rodata` resolver, statement folding) and test against `testbin/golang/dump_go_idioms.c`.
- **Rust pseudocode**: edit `PseudoClean/rust_beautifier.py`.
- **CTF Solver**: edit `PseudoClean/solver_generator.py`.
- Add at least one regression test in `PseudoClean/tests/unit_tests.py` for every bugfix or new idiom.

## Pull Request Workflow

1. Fork this repository and create a new branch (`git checkout -b feat/feature-name`).
2. Ensure all tests in `PseudoClean/tests/unit_tests.py` pass (`0 failure(s)`).
3. Commit your changes with a clear message and open a Pull Request against `main`.
