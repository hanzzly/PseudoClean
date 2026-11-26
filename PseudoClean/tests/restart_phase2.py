"""Two-session restart test, phase 2 (runs inside IDA on the SAME .i64).

    idat.exe -A -S"...\\restart_phase2.py" -L"<log>" <binary>

Reads the expectations written by `restart_phase1.py`, then verifies, in a
fresh IDA process, that

  * the renamed variable/function are still renamed (applied state persisted),
  * the ctree comment is still there,
  * the change history reloaded from the netnode is complete,
  * `ChangeManager.revert_all()` restores every name and removes the comment,
  * the settings saved in phase 1 are still in the registry.
"""

from __future__ import annotations

import os
import sys
import traceback

import ida_auto
import ida_funcs
import ida_hexrays
import idaapi

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.environ.get("PSEUDOCLEAN_HOME"),
           os.path.dirname(_HERE),
           r"C:\Users\Public\pc_run\plug"):
    if _p and os.path.isfile(os.path.join(_p, "analyzer.py")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break

import config
import change_manager as CM

FAILURES = []


def check(cond, label):
    print("  [%s] %s" % ("OK" if cond else "FAIL", label))
    if not cond:
        FAILURES.append(label)
    return bool(cond)


def _skip(label, why):
    print("  [SKIP] %s (%s)" % (label, why))


def _read_expectations():
    try:
        import ida_nalt
        path = ida_nalt.get_input_file_path() + ".restart_expect"
    except Exception:
        return None, None
    expect = {"var": None, "func": None, "comment": None, "settings": None}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if not parts:
                    continue
                kind = parts[0]
                if kind in ("var", "func") and len(parts) == 4:
                    expect[kind] = (int(parts[1], 0), parts[2], parts[3])
                elif kind == "comment" and len(parts) == 3:
                    expect["comment"] = (int(parts[1], 0), int(parts[2]))
                elif kind == "settings" and len(parts) == 2:
                    expect["settings"] = int(parts[1])
    except Exception as exc:
        print("  could not read expectations: %s" % exc)
        return expect, None
    return expect, path


def _lvar_names(ea):
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        return set()
    try:
        return {lv.name for lv in cfunc.get_lvars()}
    except Exception:
        return set()


def _text(ea):
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        return ""
    printer = ida_hexrays.qstring_printer_t(cfunc, False)
    try:
        cfunc.print_func(printer)
    except Exception:
        return ""
    return printer.s or ""


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("FATAL: HexRays unavailable")
        return 2

    expect, path = _read_expectations()
    if not expect:
        print("FATAL: no expectations file")
        return 2
    print("expectations: %s" % expect)

    mgr = CM.ChangeManager()
    stats = mgr.stats()
    print("  reloaded history: %d total, %d active, %d reverted"
          % (stats["total"], stats["active"], stats["reverted"]))
    check(stats["total"] > 0, "history reloaded from the netnode after restart")
    check(stats["active"] > 0, "applied entries are still active")

    var = expect.get("var")
    if var:
        ea, old, new = var
        names = _lvar_names(ea)
        check(old not in names, "applied variable name survived the restart")
        check(new in names, "renamed lvar %r still present" % new)
    else:
        _skip("variable persistence", "phase 1 renamed no variable")

    func = expect.get("func")
    if func:
        ea, old, new = func
        cur = ida_funcs.get_func_name(ea) or ""
        check(cur == new, "applied function name survived the restart (%r)"
              % cur)
    else:
        _skip("function persistence", "phase 1 renamed no function")

    comment = expect.get("comment")
    if comment:
        ea, count = comment
        check("PseudoClean:" in _text(ea),
              "annotation survived the restart")
    else:
        _skip("comment persistence", "phase 1 annotated nothing")

    if expect.get("settings") is not None:
        old_min = config.MIN_CONFIDENCE_REVIEW
        data = config.load_settings(apply=True)
        check(data.get("min_confidence") == expect["settings"],
              "settings persisted across processes (%r)" % data.get(
                  "min_confidence"))
        config.MIN_CONFIDENCE_REVIEW = 40
        config.save_settings(min_confidence=old_min)

    # --- revert everything, in this fresh process ------------------------
    reverted, failed = mgr.revert_all()
    print("  revert_all: %d reverted, %d failed" % (reverted, len(failed)))
    check(reverted > 0, "revert_all acted on persisted entries")
    after = CM.ChangeManager().stats()
    check(after["active"] == 0,
          "no entry stays active after the revert (%d)" % after["active"])

    if var:
        ea, old, new = var
        names = _lvar_names(ea)
        check(old in names, "original variable name restored (%r)" % old)
        check(new not in names, "temporary variable name removed")
    if func:
        ea, old, new = func
        check(ida_funcs.get_func_name(ea) == old,
              "original function name restored")
    if comment:
        ea, count = comment
        check("PseudoClean:" not in _text(ea),
              "annotation removed after restart")

    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

    print("CHECKS: %d   FAILURES: %d" % (len(FAILURES) + 0, len(FAILURES)))
    return 0 if not FAILURES else 1


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    print("FATAL: phase2 crashed")
    _rc = 2

idaapi.qexit(_rc)
