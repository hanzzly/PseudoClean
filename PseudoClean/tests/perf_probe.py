"""Performance / scale probe (runs inside IDA).

    idat.exe -A -S"...\\perf_probe.py" -L"<log>" testcases_perf.bin

Measures `analyzer.analyze_all` over the whole database and verifies the
properties that matter at scale:

  * every decompilable function is reported without an error;
  * the ctree reference is released per report (no ctree accumulation);
  * the pass is cancelled cleanly by a progress callback;
  * per-function time.
"""

from __future__ import annotations

import os
import sys
import time
import traceback

import ida_auto
import ida_hexrays
import idaapi
import idautils

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.environ.get("PSEUDOCLEAN_HOME"), os.path.dirname(_HERE),
           r"C:\Users\Public\pc_run\plug"):
    if _p and os.path.isfile(os.path.join(_p, "analyzer.py")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break

import analyzer
import ast_analyzer as A

FAILURES = []


def check(cond, label):
    print("  [%s] %s" % ("OK" if cond else "FAIL", label))
    if not cond:
        FAILURES.append(label)
    return bool(cond)


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("FATAL: no Hex-Rays")
        return 2

    funcs = [ea for ea in idautils.Functions() if A.is_decompilable(ea)]
    print("decompilable functions: %d" % len(funcs))
    check(len(funcs) > 500, "large corpus (%d functions)" % len(funcs))

    # ---- full pass ---------------------------------------------------
    t0 = time.time()
    reports = analyzer.analyze_all()
    elapsed = time.time() - t0
    per_func = (elapsed / len(reports)) if reports else 0.0
    print("analyze_all: %d report(s) in %.2f s (%.1f ms/function)"
          % (len(reports), elapsed, per_func * 1000))

    check(len(reports) == len(funcs),
          "one report per decompilable function (%d/%d)"
          % (len(reports), len(funcs)))
    errors = [r for r in reports if r.error]
    check(not errors, "no analysis errors (%d)" % len(errors))
    for r in errors[:5]:
        print("     error at %#x: %s" % (r.ea, r.error))

    leaked = [r for r in reports
              if r.profile is not None and r.profile.cfunc is not None]
    check(not leaked,
          "every report released its ctree (%d still held)" % len(leaked))

    total_sugg = sum(len(r.suggestions) for r in reports)
    print("suggestions: %d total (%.2f per function)"
          % (total_sugg, total_sugg / max(1, len(reports))))
    bad = 0
    for r in reports:
        for s in r.suggestions:
            if not s.suggested or not s.reason:
                bad += 1
    check(bad == 0, "every suggestion has a name and a reason (%d bad)" % bad)

    # ---- report generation over the whole set --------------------------
    t0 = time.time()
    text = analyzer.generate_readability_report(reports)
    print("report: %d bytes in %.2f s" % (len(text), time.time() - t0))
    check(len(text) > 1000, "report renders the whole database")

    # ---- cancellation -------------------------------------------------
    calls = []

    def progress(i, n):
        calls.append(i)
        return len(calls) < 3

    reports2 = analyzer.analyze_all(progress=progress)
    check(len(calls) == 3,
          "progress callback consulted until it cancelled (%d call(s))"
          % len(calls))
    check(len(reports2) <= 2,
          "progress callback cancels the pass (%d report(s))" % len(reports2))

    print("CHECKS: %d   FAILURES: %d"
          % (len(FAILURES) + 10, len(FAILURES)))
    return 0 if not FAILURES else 1


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    print("FATAL: perf probe crashed")
    _rc = 3

idaapi.qexit(_rc)
