"""Probe: what does PseudoClean actually suggest for the `chall` binary?"""

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


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("FATAL: no Hex-Rays")
        return 2

    ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    print("main ea = %#x" % ea)
    rep = analyzer.analyze_function(ea)
    print("name = %r  error = %r" % (rep.name, rep.error))

    print("\n-- all suggestions (%d) --" % len(rep.suggestions))
    for s in rep.suggestions:
        print("  kind=%-8s %-28s -> %-16s %3d%%  %s"
              % (s.kind, s.original, s.suggested, s.confidence, s.reason))

    print("\n-- crypto findings (%d) --" % len(rep.crypto or []))
    for c in rep.crypto or []:
        print("  %r" % (c,))

    print("\n-- control-flow summary --")
    print("  %r" % (rep.cf_summary,))

    print("\n-- readability report --")
    print(analyzer.generate_readability_report([rep]))
    return 0


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    _rc = 3
idaapi.qexit(_rc)
