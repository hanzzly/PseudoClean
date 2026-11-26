"""Probe: which treeloc does an inline comment actually accept?

Dumps, for each XOR-with-constant expression, the expression address, the
nearest parent insn (op + ea) and the enclosing statement addresses, then
tries a comment on each candidate and reports which one renders inline.
"""

from __future__ import annotations

import os
import sys

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


def dump(ea):
    cfunc = ida_hexrays.decompile(ea)
    rows = []

    class W(ida_hexrays.ctree_parentee_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.stack = []

        def visit_insn(self, i):
            self.stack.append((i.opname, i.ea))
            return 0

        def leave_insn(self, i):
            self.stack.pop()
            return 0

        def visit_expr(self, e):
            try:
                if e.op == ida_hexrays.cot_xor and (
                        (e.x is not None and e.x.op == ida_hexrays.cot_num) or
                        (e.y is not None and e.y.op == ida_hexrays.cot_num)):
                    ins = self.parent_insn()
                    rows.append({
                        "expr_ea": e.ea,
                        "parent_insn": (ins.opname, ins.ea)
                        if ins is not None else None,
                        "stack": list(self.stack),
                    })
            except Exception:
                pass
            return 0

    W().apply_to(cfunc.body, None)
    return cfunc, rows


def try_comment(cfunc, ea, text):
    loc = ida_hexrays.treeloc_t()
    loc.ea = ea
    loc.itp = ida_hexrays.ITP_SEMI
    try:
        cfunc.set_user_cmt(loc, text)
        cfunc.save_user_cmts()
    except Exception as exc:
        return "save failed: %s" % exc
    cfunc2 = ida_hexrays.decompile(cfunc.entry_ea)
    out = str(cfunc2) if cfunc2 is not None else ""
    inline = text in out and "Orphan comments" not in out
    # cleanup
    try:
        cfunc2.set_user_cmt(loc, None)
        cfunc2.save_user_cmts()
    except Exception:
        pass
    return "inline" if inline else "orphan"


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        return 2
    ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    cfunc, rows = dump(ea)
    print("xor sites: %r" % (rows,))
    if not rows:
        return 0
    row = rows[0]
    cands = [("expr", row["expr_ea"])]
    for opname, iea in row["stack"]:
        cands.append(("%s@%#x" % (opname, iea), iea))
    for label, addr in cands:
        verdict = try_comment(cfunc, addr, "PC-PROBE-%#x" % addr)
        print("  treeloc %-24s ea=%#x -> %s" % (label, addr, verdict))
    return 0


try:
    _rc = main()
except Exception:
    import traceback
    traceback.print_exc()
    _rc = 3
idaapi.qexit(_rc)
