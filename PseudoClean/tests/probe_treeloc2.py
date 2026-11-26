"""Probe: find an inline-capable treeloc near a XOR check.

Measured facts so far (IDA 9.4):
  * treeloc on an insn address (if/block/for) -> "Orphan comments" block;
  * treeloc on a statement-level *expression* address -> inline.

This probe locates the `if` that owns the XOR check and tests the condition
expression and the first expression statement of its body.
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


def collect(ea):
    """[(xor_ea, if_ea, cond_ea, first_body_expr_ea)]"""
    cfunc = ida_hexrays.decompile(ea)
    rows = []
    if_list = []

    class W(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_insn(self, i):
            try:
                if i.op == ida_hexrays.cit_if:
                    cond = i.cif.expr
                    body_ea = 0
                    blk = i.cif.ithen
                    if blk is not None and blk.op == ida_hexrays.cit_block:
                        for sub in blk.cblock:
                            sub_ea = getattr(sub, "ea", 0)
                            if sub_ea:
                                body_ea = sub_ea
                                break
                    if_list.append((i.ea, cond.ea if cond else 0, body_ea))
            except Exception:
                pass
            return 0

        def visit_expr(self, e):
            try:
                if e.op == ida_hexrays.cot_xor:
                    for side in (e.x, e.y):
                        if side is not None and \
                                side.op == ida_hexrays.cot_num:
                            rows.append((e.ea, side.numval()))
            except Exception:
                pass
            return 0

    W().apply_to(cfunc.body, None)
    return cfunc, rows, if_list


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
    cfunc, xors, ifs = collect(ea)
    print("xor const sites: %r" % (xors,))
    print("if statements  : %r" % (ifs,))
    for if_ea, cond_ea, body_ea in ifs:
        for label, addr in (("cond", cond_ea), ("body", body_ea)):
            if not addr:
                continue
            print("  if@%#x %-4s -> %s"
                  % (if_ea, label, try_comment(cfunc, addr, "PC-%#x" % addr)))
    return 0


try:
    _rc = main()
except Exception:
    import traceback
    traceback.print_exc()
    _rc = 3
idaapi.qexit(_rc)