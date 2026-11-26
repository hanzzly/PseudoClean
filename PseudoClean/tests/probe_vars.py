"""Probe: dump per-variable evidence for a function, to see what the profiler sees."""

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

import ast_analyzer as A

FIELDS = ("name", "width", "is_arg", "reads", "writes", "idx_reads",
          "idx_writes", "deref_reads", "deref_writes", "xor_self",
          "shift_uses", "call_args", "call_roles", "cmp_count",
          "loop_bound_cmp", "const_assigns", "mem_dest", "mem_src",
          "print_args", "fmt_arg", "index_uses", "callees", "return_uses")


def main():
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    cfunc = ida_hexrays.decompile(ea)
    prof = A.build_profile(ea, cfunc)
    print("loops=%r ifs=%r" % (getattr(prof, "loops", None),
                               getattr(prof, "ifs", None)))
    print("xor_assign_count = %r" % (getattr(prof, "xor_assign_count", None),))
    for v in prof.vars:
        bits = []
        for f in FIELDS:
            try:
                val = getattr(v, f)
            except Exception:
                continue
            if val not in (0, None, "", set(), False, []):
                bits.append("%s=%r" % (f, val))
        print("  " + ", ".join(bits))
    return 0


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    _rc = 3
idaapi.qexit(_rc)
