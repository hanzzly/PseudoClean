"""Two-session restart test, phase 1 (runs inside IDA).

    idat.exe -A -S"...\\restart_phase1.py" -L"<log>" <binary>

Applies a variable rename, a function rename and a ctree comment, then exits
WITHOUT reverting anything.  Phase 2 (`restart_phase2.py`) runs in a second
IDA process against the same .i64 and verifies that both the applied changes
and the change history survived, and that `ChangeManager.revert_all()` then
removes them again.

Nothing is left behind when the pair of phases succeeds.
"""

from __future__ import annotations

import os
import sys
import traceback

import ida_auto
import ida_hexrays
import idaapi
import idautils

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.environ.get("PSEUDOCLEAN_HOME"),
           os.path.dirname(_HERE),
           r"C:\Users\Public\pc_run\plug"):
    if _p and os.path.isfile(os.path.join(_p, "analyzer.py")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break

import config
import analyzer
import ast_analyzer as A
import change_manager as CM
import expression_simplifier as ES
import function_renamer as FR
import variable_renamer as VR
import confidence as CONF

FAILURES = []


def check(cond, label):
    print("  [%s] %s" % ("OK" if cond else "FAIL", label))
    if not cond:
        FAILURES.append(label)
    return bool(cond)


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("FATAL: HexRays unavailable")
        return 2

    funcs = [ea for ea in idautils.Functions() if A.is_decompilable(ea)]
    check(bool(funcs), "phase1: decompilable functions present")
    if not funcs:
        return 1

    mgr = CM.ChangeManager()
    mgr.clear()

    # --- settings: written here, read back in phase 2 --------------------
    config.save_settings(min_confidence=61, debug=False, microcode=False)
    print("  saved settings: min_confidence=61")

    renamed_var = None
    renamed_func = None
    commented = None

    # --- variable rename -------------------------------------------------
    for ea in funcs:
        rep = analyzer.analyze_function(ea, want={"vars"})
        for s in rep.by_kind(CONF.Suggestion.KIND_VAR):
            s.selected = True
            applied, failed = VR.apply_variable_renames([s])
            if applied:
                mgr.record_suggestion(s, module="variable")
                renamed_var = (ea, s.original, s.suggested)
                break
        if renamed_var:
            break
    check(renamed_var is not None, "phase1: variable renamed")

    # --- function rename -------------------------------------------------
    for ea in funcs:
        sugg = FR.suggest_function_names(ea)
        for s in sugg:
            if not FR.is_auto_name(s.original):
                continue
            s.selected = True
            applied, failed = FR.apply_function_renames([s])
            if applied:
                mgr.record_suggestion(s, module="function")
                renamed_func = (ea, s.original, s.suggested)
                break
        if renamed_func:
            break
    check(renamed_func is not None, "phase1: function renamed")

    # --- comment ---------------------------------------------------------
    for ea in funcs:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            continue
        info = [s for s in ES.analyze_expressions(ea, cfunc)
                if s.kind in (CONF.Suggestion.KIND_INFO,
                              CONF.Suggestion.KIND_EXPR)]
        if not info:
            # same fallback as the panel: control-flow observations anchor
            # reliably, expression identities are already folded by Hex-Rays
            try:
                rep = analyzer.analyze_function(ea, want={"cf"})
            except Exception:
                continue
            info = [s for s in rep.showing()
                    if s.kind in (CONF.Suggestion.KIND_INFO,
                                  CONF.Suggestion.KIND_EXPR)
                    and s.ea not in (0, idaapi.BADADDR)]
        if not info:
            continue
        for s in info:
            s.selected = True
        applied, failed = ES.annotate_suggestions(cfunc, info, ea)
        if applied:
            for s in applied:
                mgr.record_suggestion(s, module="comment")
            commented = (ea, len(applied))
            break
    check(commented is not None, "phase1: comment annotated")

    stats = mgr.stats()
    print("  history: %d active, %d total" % (stats["active"], stats["total"]))
    check(stats["active"] >= 1, "phase1: history has active entries")

    # Persist the phase-1 expectations for phase 2 as plain lines in a file
    # next to the IDB (the file is removed by phase 2 when it succeeds).
    try:
        import ida_nalt
        path = ida_nalt.get_input_file_path() + ".restart_expect"
        with open(path, "w", encoding="utf-8") as fh:
            def rec(kind, item):
                if not item:
                    fh.write("%s none\n" % kind)
                elif kind == "comment":
                    fh.write("comment %d %d\n" % item)
                else:
                    fh.write("%s %d %s %s\n" % (kind, item[0], item[1],
                                                item[2]))
            rec("var", renamed_var)
            rec("func", renamed_func)
            rec("comment", commented)
            fh.write("settings 61\n")
        print("  expectations written to %s" % path)
    except Exception as exc:
        print("  could not write expectations: %s" % exc)
        return 1

    print("CHECKS: %d   FAILURES: %d" % (len(FAILURES) + 0, len(FAILURES)))
    return 0 if not FAILURES else 1


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    print("FATAL: phase1 crashed")
    _rc = 2

idaapi.qexit(_rc)
