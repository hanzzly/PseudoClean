"""Demo: what PseudoClean actually changes in `chall`'s main.

Prints the Hex-Rays pseudocode before, then applies the variable renames and
prints it again.  This is the same apply path the panel uses.
"""

from __future__ import annotations

import os
import sys
import traceback

import ida_auto
import ida_hexrays
import ida_name
import idaapi

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.environ.get("PSEUDOCLEAN_HOME"), os.path.dirname(_HERE),
           r"C:\Users\Public\pc_run\plug"):
    if _p and os.path.isfile(os.path.join(_p, "analyzer.py")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break

import analyzer
import variable_renamer as VR


def _print_func(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        return str(cfunc) if cfunc is not None else "<no cfunc>"
    except Exception:
        return "<error>"


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("FATAL: no Hex-Rays")
        return 2

    ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    rep = analyzer.analyze_function(ea)

    print("=" * 70)
    print("SUGGESTIONS")
    print("=" * 70)
    for s in rep.suggestions:
        print("  [%s] %-24s -> %-16s %3d%%  %s"
              % (s.kind, s.original, s.suggested, s.confidence, s.reason))
    if rep.crypto:
        print("\nCRYPTO")
        for c in rep.crypto:
            print("  %s %s %d%% targets=%r"
                  % (c["kind"], c["algo"], c["confidence"], c["targets"]))

    print("\n" + "=" * 70)
    print("BEFORE")
    print("=" * 70)
    print(_print_func(ea))

    # apply the variable renames exactly like the panel does
    for s in rep.suggestions:
        if s.kind == "var":
            s.selected = True
    applied, failed = VR.apply_variable_renames(rep.suggestions)
    for s, why in failed:
        print("  rejected %s: %s" % (s.original, why))

    # ...and the comments the panel would write for the same function
    import expression_simplifier as ES
    ida_hexrays.mark_cfunc_dirty(ea, True)
    cfunc = ida_hexrays.decompile(ea)
    info = [s for s in rep.suggestions if s.kind == "info"]
    for s in info:
        s.selected = True
    note_applied, note_failed = ES.annotate_suggestions(cfunc, info, ea)
    print("applied %d comment(s): %s"
          % (len(note_applied),
             " | ".join(s.suggested for s in note_applied)))
    for s, why in note_failed:
        print("  comment rejected %s: %s" % (s.original, why))
    print("\napplied %d rename(s): %s"
          % (len(applied), ", ".join("%s->%s" % (s.original, s.suggested)
                                     for s in applied)))

    ida_hexrays.mark_cfunc_dirty(ea, True)
    print("\n" + "=" * 70)
    print("AFTER")
    print("=" * 70)
    print(_print_func(ea))

    print("\n" + "=" * 70)
    print("READABILITY REPORT (head)")
    print("=" * 70)
    report = analyzer.generate_readability_report([rep])
    print("\n".join(report.splitlines()[:24]))
    return 0


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    _rc = 3
idaapi.qexit(_rc)
