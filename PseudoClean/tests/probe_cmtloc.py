"""Probe: where does a persistent comment actually render?

Compares the function-entry slot (which produced an "Orphan comments" block in
a live session) against the first statement inside the body.
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


def _body_items(cfunc, limit=6):
    """(ea, opname) for the first statements of the body."""
    out = []
    try:
        blk = cfunc.body
        if blk.op != ida_hexrays.cit_block or blk.cblock is None:
            return out
        for ins in blk.cblock:
            ea = getattr(ins, "ea", 0)
            name = getattr(ins, "opname", None) or str(ins.op)
            out.append((ea, name))
            if len(out) >= limit:
                break
    except Exception:
        traceback.print_exc()
    return out


def _pseudocode(cfunc):
    try:
        text = str(cfunc)
    except Exception:
        text = "<unprintable>"
    return text


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("FATAL: no Hex-Rays")
        return 2

    ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    print("func entry = %#x" % ea)

    # available treeloc types
    tps = {n: getattr(ida_hexrays, n) for n in dir(ida_hexrays)
           if n.startswith("ITP_")}
    print("ITP_* = %r" % (tps,))

    cfunc = ida_hexrays.decompile(ea)
    print("body items (ea, op): %r" % (_body_items(cfunc),))

    body_eas = [e for e, _ in _body_items(cfunc, 20)]
    first_body_ea = body_eas[0] if body_eas else None
    print("first body ea = %r" % (first_body_ea if first_body_ea is None
                                  else hex(first_body_ea),))

    marker = "PseudoClean: loops=1 ifs=4 switches=0 returns=2 (2 early)"

    # --- case A: at the function-entry slot (the reported behaviour) --------
    loc = ida_hexrays.treeloc_t()
    loc.ea = ea
    loc.itp = ida_hexrays.ITP_SEMI
    cfunc.set_user_cmt(loc, marker)
    try:
        cfunc.save_user_cmts()
    except Exception as exc:
        print("save_user_cmts A failed: %s" % exc)
    cfunc2 = ida_hexrays.decompile(ea)
    text = _pseudocode(cfunc2)
    print("\n=== A: comment at function entry ===")
    print("contains 'Orphan comments': %r" % ("Orphan comments" in text,))
    for line in text.splitlines():
        if "PseudoClean" in line or "Orphan" in line:
            print("   |%s" % line)

    # remove A again
    try:
        cfunc2.set_user_cmt(loc, None)
        cfunc2.save_user_cmts()
    except Exception as exc:
        print("cleanup A failed: %s" % exc)

    # --- case B: at the first statement of the body ------------------------
    if first_body_ea:
        loc2 = ida_hexrays.treeloc_t()
        loc2.ea = first_body_ea
        loc2.itp = ida_hexrays.ITP_SEMI
        cfunc3 = ida_hexrays.decompile(ea)
        cfunc3.set_user_cmt(loc2, marker)
        try:
            cfunc3.save_user_cmts()
        except Exception as exc:
            print("save_user_cmts B failed: %s" % exc)
        cfunc4 = ida_hexrays.decompile(ea)
        text2 = _pseudocode(cfunc4)
        print("\n=== B: comment at first body statement (%#x) ==="
              % first_body_ea)
        print("contains 'Orphan comments': %r"
              % ("Orphan comments" in text2,))
        for line in text2.splitlines():
            if "PseudoClean" in line or "Orphan" in line:
                print("   |%s" % line)
        # cleanup
        try:
            cfunc4.set_user_cmt(loc2, None)
            cfunc4.save_user_cmts()
        except Exception as exc:
            print("cleanup B failed: %s" % exc)
    return 0


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    _rc = 3
idaapi.qexit(_rc)
