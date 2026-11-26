"""PseudoClean end-to-end integration test (runs inside IDA).

    idat.exe -A -S"<path>\\integration_test.py" -L"<log>" <binary>

Exercises the whole pipeline against a real database:

  Phase A  profile + analyze every decompilable function
  Phase B  determinism: two independent runs yield identical suggestions
  Phase C  variable rename apply -> visible -> revert -> restored
  Phase D  function rename apply -> visible -> revert -> restored
  Phase E  persistent ctree comment annotation and removal
  Phase F  change history persistence across instances
  Phase G  readability report generation
  Phase H  safety: meaningful names and library functions are never touched

Exit code is 0 only when every executed check passed.
"""

from __future__ import annotations

import os
import re
import sys
import traceback

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import idaapi
import idautils

# ---------------------------------------------------------------------------
# make the package importable (tests/ lives inside the package)
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = [
    os.environ.get("PSEUDOCLEAN_HOME"),
    os.path.dirname(_HERE),                              # <pkg>/.. = pkg
    r"C:\Users\Public\pc_run\plug",
]
# Insert in reverse so the *first* existing candidate ends up first on the
# import path.  Only a directory that really contains the package is used.
for _p in reversed([p for p in _CANDIDATES if p]):
    if os.path.isfile(os.path.join(_p, "confidence.py")) and \
            os.path.isfile(os.path.join(_p, "analyzer.py")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
if not any(os.path.isfile(os.path.join(p, "analyzer.py"))
           for p in sys.path if isinstance(p, str)):
    print("FATAL: PseudoClean package not found on the import path")

import config
import analyzer
import ast_analyzer as A
import change_manager as CM
import expression_simplifier as ES
import function_renamer as FR
import variable_renamer as VR
import confidence as CONF

FAILURES = []
CHECKS = 0
SKIPPED = []
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def check(cond, label):
    global CHECKS
    CHECKS += 1
    if cond:
        print("  [OK]   %s" % label)
    else:
        print("  [FAIL] %s" % label)
        FAILURES.append(label)
    return bool(cond)


def skip(label, why):
    print("  [SKIP] %s (%s)" % (label, why))
    SKIPPED.append((label, why))


def _funcs():
    out = []
    for ea in idautils.Functions():
        if A.is_decompilable(ea):
            out.append(ea)
    return out


def _suggestion_key(s):
    return (s.kind, s.original, s.suggested, s.confidence, s.ea, s.func_ea)


def _well_formed(suggestions, where):
    ok = True
    for s in suggestions:
        ok &= check(0 <= s.confidence <= 100,
                    "%s: confidence in range (%r)" % (where, s.suggested))
        ok &= check(s.suggested != s.original,
                    "%s: suggestion changes something (%r)" % (where,
                                                               s.original))
        ok &= check(bool(s.reason), "%s: reason present" % where)
        if s.kind in (CONF.Suggestion.KIND_VAR, CONF.Suggestion.KIND_FUNC):
            ok &= check(bool(_IDENT_RE.match(s.suggested)),
                        "%s: %s suggestion is an identifier (%r)"
                        % (where, s.kind, s.suggested))
    return ok


def _print_func(ea):
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        return ""
    printer = ida_hexrays.qstring_printer_t(cfunc, False)
    try:
        cfunc.print_func(printer)
    except Exception:
        return ""
    return printer.s or ""


def _lvar_names(ea):
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        return set()
    try:
        return {lv.name for lv in cfunc.get_lvars()}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Phase A: analysis
# ---------------------------------------------------------------------------

def phase_analyze(funcs):
    print("\n== A. analysis ==")
    reports = []
    for ea in funcs:
        name = ida_funcs.get_func_name(ea) or ("%#x" % ea)
        try:
            rep = analyzer.analyze_function(ea)
        except Exception as exc:
            check(False, "analyze %#x (%s) raised %s" % (ea, name, exc))
            continue
        check(rep.error is None, "analyze %#x (%s)%s"
              % (ea, name, "" if rep.error is None else ": " + rep.error))
        _well_formed(rep.suggestions, name)
        reports.append(rep)
    n = sum(len(r.showing()) for r in reports)
    print("  -> %d function(s), %d suggestion(s)" % (len(reports), n))
    return reports


# ---------------------------------------------------------------------------
# Phase B: determinism
# ---------------------------------------------------------------------------

def phase_determinism(funcs):
    print("\n== B. determinism ==")
    # Hex-Rays persists lvar types on the FIRST build of a function, so the
    # second build can differ from the first (measured on testcases_O2/main:
    # `v38`->buf at 96% becomes `v27`->buf at 88% and one suggestion drops).
    # The analysis itself is a pure function of the decompiler state, so the
    # comparison is made in the settled state: warm each function with one
    # rebuild, then require two consecutive analyses to be identical.
    twice = 0
    settled = []
    for ea in funcs:
        try:
            ida_hexrays.mark_cfunc_dirty(ea, True)
            ida_hexrays.decompile(ea)
            first = [_suggestion_key(s) for s in
                     analyzer.analyze_function(ea).suggestions]
            second = [_suggestion_key(s) for s in
                      analyzer.analyze_function(ea).suggestions]
        except Exception as exc:
            check(False, "determinism %#x raised %s" % (ea, exc))
            continue
        if first != second:
            for a, b in zip(first, second):
                if a != b:
                    print("     first : %r" % (a,))
                    print("     second: %r" % (b,))
            if len(first) != len(second):
                print("     lengths differ: %d vs %d"
                      % (len(first), len(second)))
            settled.append(ea)
        check(first == second, "deterministic suggestions at %#x" % ea)
        twice += 1
    print("  -> %d function(s) analysed twice" % twice)
    if settled:
        skip("analysis is a pure function of the decompiler state",
             "%d function(s) were still unstable after a rebuild" % len(settled))
    else:
        check(True, "analysis is a pure function of the decompiler state")


# ---------------------------------------------------------------------------
# Phase C: variable rename round-trip
# ---------------------------------------------------------------------------

def _first_var_target(reports):
    for rep in reports:
        for s in rep.by_kind(CONF.Suggestion.KIND_VAR):
            if s.selected:
                return rep.ea, s
    return None, None


def phase_variable_roundtrip(reports):
    print("\n== C. variable rename round-trip ==")
    ea, s = _first_var_target(reports)
    if s is None:
        skip("variable rename round-trip", "no variable suggestions")
        return
    before = _lvar_names(ea)
    if s.original not in before:
        skip("variable rename round-trip",
             "%r not a live lvar (stale suggestion)" % s.original)
        return

    s.selected = True
    applied, failed = VR.apply_variable_renames([s])
    check(len(applied) == 1, "apply %r -> %r (%d failure(s))"
          % (s.original, s.suggested, len(failed)))

    after = _lvar_names(ea)
    check(s.suggested in after, "renamed lvar visible in pseudocode")
    check(s.original not in after, "old lvar name gone from pseudocode")
    text = _print_func(ea)
    check(s.suggested in text, "renamed lvar appears in printed text")

    # idempotence: applying again must fail cleanly, not duplicate
    again, failed_again = VR.apply_variable_renames([s])
    check(not again, "re-applying the same rename is a no-op")

    reverted, failure = VR.revert_variable_renames([s])
    check(len(reverted) == 1, "revert rename (%d failure(s))"
          % len(failure))
    restored = _lvar_names(ea)
    check(s.original in restored, "original lvar name restored")
    check(s.suggested not in restored, "temporary name removed")


# ---------------------------------------------------------------------------
# Phase D: function rename round-trip
# ---------------------------------------------------------------------------

def phase_function_roundtrip(reports):
    print("\n== D. function rename round-trip ==")
    target = None
    for rep in reports:
        for s in rep.by_kind(CONF.Suggestion.KIND_FUNC):
            if FR.is_auto_name(s.original):
                target = s
                break
        if target:
            break
    if target is None:
        skip("function rename round-trip",
             "no auto-named functions with a confident name")
        return

    target.selected = True
    applied, failed = FR.apply_function_renames([target])
    check(len(applied) == 1, "apply %r -> %r (%d failure(s))"
          % (target.original, target.suggested, len(failed)))
    check(ida_funcs.get_func_name(target.ea) == target.suggested,
          "renamed function visible in the symbol table")

    again, _ = FR.apply_function_renames([target])
    check(not again, "re-applying the same rename is a no-op")

    reverted, failure = FR.revert_function_renames([target])
    check(len(reverted) == 1, "revert function rename (%d failure(s))"
          % len(failure))
    check(ida_funcs.get_func_name(target.ea) == target.original,
          "original function name restored")


# ---------------------------------------------------------------------------
# Phase E: persistent comment annotation
# ---------------------------------------------------------------------------

def _annotatable_suggestions(ea):
    """The observations the panel would annotate for `ea`.

    `analyze_expressions` legitimately returns nothing on ordinary compiler
    output because Hex-Rays already folds those identities; the control-flow
    observations are the ones that reliably anchor, so they are used to
    exercise the same apply/revert path with real data.
    """
    try:
        rep = analyzer.analyze_function(ea, want={"cf"})
    except Exception:
        return []
    return [s for s in rep.showing()
            if s.kind in (CONF.Suggestion.KIND_INFO,
                          CONF.Suggestion.KIND_EXPR)
            and s.ea not in (0, idaapi.BADADDR)]


def phase_comment_annotation(funcs):
    print("\n== E. persistent ctree comments ==")
    for ea in funcs:
        try:
            cfunc = ida_hexrays.decompile(ea)
        except Exception:
            continue
        if cfunc is None:
            continue
        suggestions = ES.analyze_expressions(ea, cfunc)
        info = [s for s in suggestions
                if s.kind in (CONF.Suggestion.KIND_INFO,
                              CONF.Suggestion.KIND_EXPR)]
        if not info:
            # `analyze_expressions` finds nothing on ordinary compiler output
            # (Hex-Rays already folds those identities).  Use the
            # control-flow observations the panel also annotates, so the
            # apply/revert path is still exercised against real data.
            info = _annotatable_suggestions(ea)
        if not info:
            continue                      # nothing to annotate here
        for s in info:
            s.selected = True

        applied, failed = ES.annotate_suggestions(cfunc, info, ea)
        if not applied:
            check(not failed,
                  "annotation failed with a reason (%d failure(s))"
                  % len(failed))
            continue
        check(len(applied) >= 1, "annotated %d item(s) at %#x"
              % (len(applied), ea))
        ida_hexrays.mark_cfunc_dirty(ea, True)
        text = _print_func(ea)
        check("PseudoClean:" in text, "annotation survives re-decompilation")
        # A comment anchored on the function-entry address renders as an
        # "Orphan comments" block after the function (measured in a live
        # session), so PseudoClean moves it to the first body statement.
        check("Orphan comments" not in text,
              "annotation renders inside the function, not as orphan comments")
        removed = ES.remove_pseudoclean_comments(ea)
        check(removed >= 1, "removed %d annotation(s)" % removed)
        text = _print_func(ea)
        check("PseudoClean:" not in text, "annotation removed from output")
        return
    skip("persistent ctree comments", "no annotatable expression found")


# ---------------------------------------------------------------------------
# Phase F: history persistence
# ---------------------------------------------------------------------------

def phase_history(funcs):
    print("\n== F. change history persistence ==")
    if not funcs:
        skip("change history", "no functions")
        return
    ea = funcs[0]
    mgr = CM.ChangeManager()
    before = len(mgr.entries)
    entry = mgr.record("var", ea, "tmp1", "history_probe", 90,
                       "integration test", module="test")
    fresh = CM.ChangeManager()             # reload from the netnode
    check(len(fresh.entries) == before + 1,
          "history entry persisted (%d -> %d)" % (before,
                                                  len(fresh.entries)))
    check(any(e["id"] == entry["id"] for e in fresh.entries),
          "persisted entry keeps its id")
    fresh.mark_reverted(entry["id"])
    check(any(e["id"] == entry["id"] and e["reverted"]
              for e in CM.ChangeManager().entries),
          "reverted flag persisted")
    fresh.clear()
    check(len(CM.ChangeManager().entries) == 0, "history cleared")


# ---------------------------------------------------------------------------
# Phase G: report
# ---------------------------------------------------------------------------

def phase_report(reports):
    print("\n== G. readability report ==")
    text = analyzer.generate_readability_report(reports)
    check("# PseudoClean readability report" in text, "report has a header")
    check("Suggestions generated" in text, "report has a summary line")
    check(len(text) > 80, "report has content (%d bytes)" % len(text))
    print("  -> %d bytes of markdown" % len(text))


# ---------------------------------------------------------------------------
# Phase H: safety
# ---------------------------------------------------------------------------

def phase_safety(reports):
    print("\n== H. safety invariants ==")
    bad_meaningful = []
    bad_library = []
    for rep in reports:
        old = rep.name or ""
        if not old:
            continue
        if not FR.is_auto_name(old):
            for s in rep.by_kind(CONF.Suggestion.KIND_FUNC):
                bad_meaningful.append((old, s.suggested))
        try:
            f = ida_funcs.get_func(rep.ea)
            if f is not None and (f.flags & ida_funcs.FUNC_LIB):
                for s in rep.suggestions:
                    bad_library.append((old, s.suggested))
        except Exception:
            pass
    check(not bad_meaningful, "no suggestions for meaningful names (%s)"
          % (bad_meaningful[:3] or "none"))
    check(not bad_library, "no suggestions inside library functions (%s)"
          % (bad_library[:3] or "none"))
    for s in [s for rep in reports
              for s in rep.by_kind(CONF.Suggestion.KIND_FUNC)]:
        check(FR.is_auto_name(s.original),
              "function suggestion only on auto name (%r)" % s.original)


# ---------------------------------------------------------------------------
# Phase I: settings persistence
# ---------------------------------------------------------------------------

def phase_settings():
    print("\n== I. settings persistence ==")
    saved = (config.MIN_CONFIDENCE_REVIEW, config.LOG_DEBUG,
             config.MICROCODE_SIMPLIFIER)
    try:
        ok = config.save_settings(min_confidence=57, debug=True,
                                  microcode=True)
        check(ok, "settings written to the IDA registry")
        # simulate a fresh session: reset to defaults, then reload
        config.MIN_CONFIDENCE_REVIEW = 40
        config.LOG_DEBUG = False
        config.MICROCODE_SIMPLIFIER = False
        data = config.load_settings(apply=True)
        check(data.get("min_confidence") == 57,
              "min_confidence persisted (%r)" % data.get("min_confidence"))
        check(config.MIN_CONFIDENCE_REVIEW == 57,
              "min_confidence applied to the module")
        check(config.LOG_DEBUG is True, "debug flag applied")
        check(config.MICROCODE_SIMPLIFIER is True, "microcode flag applied")
    finally:
        config.save_settings(min_confidence=saved[0], debug=saved[1],
                              microcode=saved[2])
        config.MIN_CONFIDENCE_REVIEW = saved[0]
        config.LOG_DEBUG = saved[1]
        config.MICROCODE_SIMPLIFIER = saved[2]


# ---------------------------------------------------------------------------
# Phase J: report path includes control flow
# ---------------------------------------------------------------------------

def phase_report_path(funcs):
    print("\n== J. report path (analyze_all -> report) ==")
    reports = analyzer.analyze_all(limit=min(60, len(funcs)))
    check(bool(reports), "analyze_all returned reports")
    text = analyzer.generate_readability_report(reports)
    has_cf = any(r.cf_summary is not None for r in reports)
    if has_cf:
        check("## Control-flow notes" in text,
              "report contains control-flow rows")
        check("_Control-flow analysis was not enabled" not in text,
              "report does not claim control flow was skipped")
    else:
        skip("report control-flow rows", "no function produced a summary")
    check("## Top suggestions" in text or len(text) < 400,
          "report renders its sections")


# ---------------------------------------------------------------------------
# Phase K: microcode identity equivalence
# ---------------------------------------------------------------------------

def _microcode_mov_texts(ea, limit=400):
    """Return the printed text of ``m_mov`` instructions for `ea`.

    IMPORTANT: the strings are materialized *inside* the function, before the
    ``mba_t`` is released.  Returning live ``minsn_t`` proxies crashes IDA:
    the operands live in storage owned by the ``mba_t``, so once it is
    garbage-collected the SWIG proxies dangle (observed as a hard crash of a
    headless session in phase K).
    """
    out = []
    try:
        ranges = ida_hexrays.decomp_ranges_t(ea)
        hf = ida_hexrays.hexrays_failure_t()
        retlist = ida_hexrays.mlist_t()
        mba = ida_hexrays.gen_microcode(
            ranges, hf, retlist, ida_hexrays.DECOMP_NO_WAIT,
            ida_hexrays.MMAT_GENERATED)
    except Exception:
        return out
    if mba is None:
        return out
    try:
        blk = mba.blocks
        guard = 0
        while blk is not None and guard < 10000 and len(out) < limit:
            guard += 1
            ins = blk.head
            hops = 0
            while ins is not None and hops < 10000 and len(out) < limit:
                hops += 1
                if ins.opcode == ida_hexrays.m_mov:
                    try:
                        out.append((ins.dstr(),
                                    ins.l.dstr() if ins.l is not None else "",
                                    ins.d.dstr() if ins.d is not None else ""))
                    except Exception:
                        pass
                ins = ins.next
            blk = blk.nextb
    except Exception:
        pass
    return out


def phase_microcode_operand_order(funcs):
    print("\n== K. microcode operand semantics ==")
    movs = []
    for ea in funcs[:40]:
        movs.extend(_microcode_mov_texts(ea))
        if len(movs) >= 20:
            break
    if not movs:
        skip("microcode operand order", "no m_mov generated")
    else:
        bad = 0
        for text, l_txt, d_txt in movs[:20]:
            # IDA prints m_mov as "mov <l>, <d>" (l is the source operand)
            if not text.startswith("mov "):
                bad += 1
                continue
            if not (l_txt and d_txt and l_txt in text and d_txt in text):
                bad += 1
                continue
            if text.index(l_txt) > text.index(d_txt):
                bad += 1
        check(bad == 0, "printed mov order matches l=source, d=destination")
        print("  -> %d real m_mov instructions inspected" % len(movs[:20]))

    # the rewrite helpers must preserve semantics end to end
    sample = [ea for ea in funcs[:20]]
    baseline = {ea: _print_func(ea) for ea in sample}
    installed = ES.install_microcode_simplifier()
    check(installed, "microcode simplifier installs")
    check(ES.microcode_simplifier_active(), "microcode simplifier is active")
    for ea in sample:
        ida_hexrays.mark_cfunc_dirty(ea, True)
    after = {ea: _print_func(ea) for ea in sample}
    changed = [ea for ea in sample if baseline[ea] != after[ea]]
    check(not changed,
          "microcode rewrites preserve program text (%d differ)"
          % len(changed))
    stats = ES.microcode_stats()
    total = sum(v for v in stats.values() if isinstance(v, int))
    print("  -> microcode rewrites: %d %s" % (total, stats))
    check(ES.remove_microcode_simplifier(), "microcode simplifier removes")
    check(not ES.microcode_simplifier_active(),
          "microcode simplifier is inactive after removal")


# ---------------------------------------------------------------------------
# Phase L: comment revert bookkeeping
# ---------------------------------------------------------------------------

def phase_comment_revert(funcs):
    print("\n== L. comment revert bookkeeping ==")
    mgr = CM.ChangeManager()
    mgr.clear()
    annotated = False
    for ea in funcs:
        try:
            cfunc = ida_hexrays.decompile(ea)
        except Exception:
            continue
        if cfunc is None:
            continue
        sugg = [s for s in ES.analyze_expressions(ea, cfunc)
                if s.kind in (CONF.Suggestion.KIND_INFO,
                              CONF.Suggestion.KIND_EXPR)]
        if not sugg:
            sugg = _annotatable_suggestions(ea)
        if not sugg:
            continue
        for s in sugg:
            s.selected = True
        applied, failed = ES.annotate_suggestions(cfunc, sugg, ea)
        if not applied:
            continue
        for s in applied:
            # mimic the panel: record before it becomes revertible
            mgr.record_suggestion(s, module="comment")
        check(mgr.stats()["active"] >= 1,
              "comment entries recorded as active (%d)"
              % mgr.stats()["active"])
        annotated = True
        break
    if not annotated:
        skip("comment revert bookkeeping", "no annotatable expression found")
        return

    reverted, failed = mgr.revert_all()
    check(reverted >= 1, "revert_all removed %d comment(s)" % reverted)
    check(mgr.stats()["active"] == 0,
          "no comment entry stays active after revert (%d failure(s))"
          % len(failed))
    check(all(e["reverted"] for e in mgr.entries),
          "every comment entry is marked reverted")
    ida_hexrays.mark_cfunc_dirty(ea, True)
    check("PseudoClean:" not in _print_func(ea),
          "annotation really left the pseudocode")

    # a restart must not resurrect a pending revert
    fresh = CM.ChangeManager()
    check(fresh.stats()["active"] == 0,
          "revert state persists across an instance reload")
    fresh.clear()


# ---------------------------------------------------------------------------
# Phase M: library functions are out of scope
# ---------------------------------------------------------------------------

def phase_library(funcs):
    print("\n== M. library functions ==")
    lib = []
    for ea in idautils.Functions():
        try:
            f = ida_funcs.get_func(ea)
        except Exception:
            continue
        if f is not None and (f.flags & ida_funcs.FUNC_LIB):
            lib.append(ea)
    print("  -> %d FUNC_LIB function(s) in this database" % len(lib))

    temporary = None
    if not lib:
        # IDA 9.4 in batch mode applies no library signatures, so a static
        # glibc build still reports zero FUNC_LIB functions (measured: 0 of
        # 1161).  Set the real flag on one function to exercise the same code
        # path, then put the database back exactly as it was.
        if not funcs:
            skip("library-function exclusion", "no functions to tag")
            return
        temporary = funcs[-1]
        try:
            f = ida_funcs.get_func(temporary)
            original = f.flags
            ida_funcs.set_func_flags(temporary, original | ida_funcs.FUNC_LIB)
            now = ida_funcs.get_func(temporary)
            if now is None or not (now.flags & ida_funcs.FUNC_LIB):
                skip("library-function exclusion",
                     "could not set FUNC_LIB on %#x" % temporary)
                return
        except Exception as exc:
            skip("library-function exclusion",
                 "could not set FUNC_LIB: %s" % exc)
            return
        lib = [temporary]
        print("  -> no FUNC_LIB present; tagged %#x temporarily" % temporary)

    try:
        for ea in lib[:20]:
            check(A.is_library_function(ea), "FUNC_LIB detected at %#x" % ea)
            check(not A.is_decompilable(ea, skip_library=True),
                  "bulk pass skips %#x" % ea)
            check(FR.suggest_function_names(ea) == [],
                  "no function rename for %#x" % ea)
        skipped = analyzer.analyze_all(limit=len(funcs))
        names = {r.ea for r in skipped}
        check(not (names & set(lib)),
              "analyze_all never reports a library body")
    finally:
        if temporary is not None:
            try:
                ida_funcs.set_func_flags(temporary, original)
                back = ida_funcs.get_func(temporary)
                check(back is not None and
                      not (back.flags & ida_funcs.FUNC_LIB),
                      "FUNC_LIB flag restored on %#x" % temporary)
            except Exception as exc:
                check(False, "could not restore FUNC_LIB: %s" % exc)


# ---------------------------------------------------------------------------
# Phase N: background analysis pattern (thread + execute_sync)
# ---------------------------------------------------------------------------

def phase_background(funcs):
    print("\n== N. background analysis (thread + execute_sync) ==")
    import threading
    if not ida_kernwin.is_idaq():
        # Headless idat has no UI message loop: `execute_sync` from a worker
        # thread would block forever (verified: the call never returns and
        # `done.wait()` times out).  Skip instead of hanging the runner.
        skip("background analysis",
             "headless idat: no UI loop to service execute_sync "
             "(is_idaq() is False); the real panel runs inside ida (GUI)")
        return
    if not funcs:
        skip("background analysis", "no functions")
        return
    target = funcs[0]
    result = {}
    done = threading.Event()

    def worker():
        rep = ida_kernwin.execute_sync(
            lambda: analyzer.analyze_function(target, want={"vars", "cf"}),
            ida_kernwin.MFF_READ)
        result["rep"] = rep
        done.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    # keep the main thread responsive while the worker is in execute_sync
    finished = done.wait(timeout=120)
    check(finished, "worker analysis completed")
    rep = result.get("rep")
    check(rep is not None and rep.error is None,
          "execute_sync(MFF_READ) produced a report")
    if rep is not None:
        check(rep.ea == target, "report belongs to the requested function")
        check(rep.profile is not None and rep.profile.cfunc is None,
              "analyzer released the ctree reference")

    # cancellation is honoured by analyze_all's progress callback
    calls = []

    def progress(i, n):
        calls.append(i)
        return len(calls) < 3          # cancel on the third tick

    reports = analyzer.analyze_all(limit=10, progress=progress)
    check(len(calls) == 3,
          "progress callback was consulted until it cancelled (%d call(s))"
          % len(calls))
    check(len(reports) <= 2,
          "progress callback cancels the bulk pass (%d report(s))"
          % len(reports))


# ---------------------------------------------------------------------------
# Phase O: GUI smoke test (only when a Qt binding exists)
# ---------------------------------------------------------------------------

def phase_gui():
    print("\n== O. panel smoke test ==")
    try:
        import ui.qt_binding as QB
        if not QB.available():
            skip("panel smoke test", "no Qt binding in this IDA build")
            return
        name = QB.binding_name()
        print("  -> Qt binding: %s" % name)
        import plugin
        panel = plugin.get_panel()
        check(panel is not None, "panel instance created")
        panel.Show()
        check(panel._table is not None, "review table built (%s)" % name)
        check(panel._qt_widget is not None, "form converted to a %s widget"
              % name)
        check(panel.progress.isVisible() is False,
              "progress bar hidden while idle")
        check(panel.btn_cancel.isVisible() is False,
              "cancel button hidden while idle")
        panel.Close()
    except Exception as exc:
        check(False, "panel smoke test raised %s" % exc)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("FATAL: Hex-Rays unavailable")
        return 2

    funcs = _funcs()
    try:
        import ida_nalt
        _path = ida_nalt.get_input_file_path() or "?"
    except Exception:
        _path = "?"
    print("binary   : %s" % _path)
    print("functions: %d decompilable" % len(funcs))
    check(bool(funcs), "database has decompilable functions")

    reports = phase_analyze(funcs)
    phase_determinism(funcs)
    phase_variable_roundtrip(reports)
    phase_function_roundtrip(reports)
    phase_comment_annotation(funcs)
    phase_history(funcs)
    phase_report(reports)
    phase_safety(reports)
    phase_settings()
    phase_report_path(funcs)
    phase_microcode_operand_order(funcs)
    phase_comment_revert(funcs)
    phase_library(funcs)
    phase_background(funcs)
    phase_gui()

    print("\n" + "=" * 64)
    print("CHECKS: %d   FAILURES: %d   SKIPPED: %d"
          % (CHECKS, len(FAILURES), len(SKIPPED)))
    for item in SKIPPED:
        print("  SKIPPED: %s (%s)" % item)
    for item in FAILURES:
        print("  FAILED : %s" % item)
    print("=" * 64)
    return 0 if not FAILURES else 1


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    print("FATAL: unhandled exception in integration test")
    _rc = 2

idaapi.qexit(_rc)
