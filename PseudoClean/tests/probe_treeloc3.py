"""Probe: definitive map of inline-capable treelocs around each XOR check.

For every XOR-with-constant:
  * the innermost enclosing statement (from a manual insn stack),
  * every expression-statement address in the function and whether a treeloc
    on it renders inline,
so the anchor rule can be derived from measurement instead of guesswork.
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
    cfunc = ida_hexrays.decompile(ea)
    state = {"xor": [], "stmts": []}

    class W(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.stack = []

        def visit_insn(self, i):
            if i.op == ida_hexrays.cit_expr:
                state["stmts"].append((i.ea, i.opname))
            self.stack.append((i.opname, i.ea))
            return 0

        def leave_insn(self, i):
            self.stack.pop()
            return 0

        def visit_expr(self, e):
            try:
                if e.op == ida_hexrays.cot_xor:
                    for side in (e.x, e.y):
                        if side is not None and \
                                side.op == ida_hexrays.cot_num:
                            inner = self.stack[-1] if self.stack else None
                            state["xor"].append({
                                "xor_ea": e.ea,
                                "key": side.numval(),
                                "enclosing": inner,
                                "stack": list(self.stack),
                            })
            except Exception:
                pass
            return 0

    W().apply_to(cfunc.body, None)
    return cfunc, state


def render(cfunc, ea):
    text = "PC-%#x" % ea
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
    verdict = "inline" if (text in out
                          and "Orphan comments" not in out) else "orphan"
    try:
        cfunc2.set_user_cmt(loc, None)
        cfunc2.save_user_cmts()
    except Exception:
        pass
    return verdict


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        return 2
    ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    cfunc, state = collect(ea)

    print("== expression statements (inline-capable candidates) ==")
    for se, opname in state["stmts"]:
        print("  %#x %-8s -> %s" % (se, opname, render(cfunc, se)))

    print("== xor sites ==")
    for row in state["xor"]:
        print("  xor@%#x key=%#x enclosing=%r"
              % (row["xor_ea"], row["key"], row["enclosing"]))
        print("      stack: %r" % (row["stack"],))

    # candidate rule: the last expression statement before the enclosing
    # statement's address
    stmt_eas = [se for se, _ in state["stmts"]]
    for row in state["xor"]:
        encl = row["enclosing"][1] if row["enclosing"] else 0
        before = [se for se in stmt_eas if encl and se < encl]
        cand = max(before) if before else 0
        print("  xor@%#x rule-candidate anchor=%#x -> %s"
              % (row["xor_ea"], cand,
                 render(cfunc, cand) if cand else "n/a"))
    return 0


try:
    _rc = main()
except Exception:
    import traceback
    traceback.print_exc()
    _rc = 3
idaapi.qexit(_rc)
