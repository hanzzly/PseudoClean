"""Orchestration layer: runs every analyzer for one function or all functions.

This is the single entry point the UI talks to.
"""

from __future__ import annotations

import traceback

import ida_funcs
import ida_hexrays
import idautils

import ast_analyzer as A
import control_flow as CF
import crypto_detector as C
import expression_simplifier as ES
import function_renamer as FR
import microcode_analyzer as MC
import variable_renamer as VR
import api_recognizer as API
import config
import logging_util as L
from confidence import Suggestion


#: Modules the readability report renders.  Kept as a module constant so the
#: UI report path and `analyze_function` cannot drift apart.
DEFAULT_WANT = frozenset(("vars", "func", "crypto", "cf"))


class FunctionReport:
    """Bundle of everything PseudoClean knows about one function."""

    def __init__(self, ea: int):
        self.ea = ea
        self.name = ""
        self.profile = None
        self.suggestions = []
        self.crypto = []
        self.cf_summary = None
        self.facts = {}
        self.error = None

    def by_kind(self, kind):
        return [s for s in self.suggestions if s.kind == kind]

    def showing(self):
        """Suggestions above the review threshold."""
        return [s for s in self.suggestions
                if s.confidence >= config.MIN_CONFIDENCE_REVIEW]


# ---------------------------------------------------------------------------
# Single function
# ---------------------------------------------------------------------------

def analyze_function(ea: int, want=None) -> FunctionReport:
    """Analyze one function.  `want` optionally restricts the modules:
    a set drawn from {"vars","func","expr","cf","crypto"}.
    """
    want = want or {"vars", "func", "expr", "cf", "crypto"}
    rep = FunctionReport(ea)
    try:
        rep.name = ida_funcs.get_func_name(ea) or ""
    except Exception:
        rep.name = ""

    cfunc = None
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as exc:
        rep.error = "decompile failed: %s" % exc
        return rep
    if cfunc is None:
        rep.error = "decompile failed (no cfunc)"
        return rep

    try:
        rep.profile = A.build_profile(ea, cfunc)
    except Exception as exc:
        rep.error = "profile failed: %s" % exc
        L.debug(traceback.format_exc())
        return rep

    # crypto findings feed the function renamer
    if "crypto" in want:
        try:
            rep.crypto = C.analyze_function(rep.profile)
        except Exception as exc:
            L.debug("crypto analysis failed at %#x: %s" % (ea, exc))

    # A detected pattern is worth a comment *only* when it says something
    # the reader cannot see at a glance.  The generated note explains the
    # key schedule and where the check lives, so it is annotated at the
    # pattern site; the raw counters are not.
    for f in rep.crypto:
        note = f.get("note")
        if not note:
            continue
        rep.suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "%s %s" % (f.get("algo", "?"), f.get("kind", "?")),
            note,
            int(f.get("confidence", 0)),
            "crypto pattern (%s)" % f.get("algo", "?"),
            ea=int(f.get("key_ea") or 0) or ea,
            func_ea=ea))

    # variable naming
    if "vars" in want:
        try:
            rep.suggestions.extend(
                VR.suggest_variable_names(ea, cfunc, rep.profile))
        except Exception as exc:
            L.debug("variable naming failed at %#x: %s" % (ea, exc))

    # function naming
    if "func" in want:
        try:
            rep.suggestions.extend(
                FR.suggest_function_names(ea, cfunc, rep.profile, rep.crypto))
        except Exception as exc:
            L.debug("function naming failed at %#x: %s" % (ea, exc))

    # expression analysis (informational)
    if "expr" in want:
        try:
            rep.suggestions.extend(
                ES.analyze_expressions(ea, cfunc, rep.profile))
        except Exception as exc:
            L.debug("expression analysis failed at %#x: %s" % (ea, exc))

    # control flow (informational)
    if "cf" in want:
        try:
            cf_sugg, summary = CF.analyze_control_flow(ea, cfunc, rep.profile)
            rep.suggestions.extend(cf_sugg)
            rep.cf_summary = summary
        except Exception as exc:
            L.debug("control flow failed at %#x: %s" % (ea, exc))

    # identity facts for the report
    try:
        rep.facts = API.readability_facts(ea, rep.profile)
    except Exception as exc:
        L.debug("facts failed at %#x: %s" % (ea, exc))

    # filter out noise
    rep.suggestions = [s for s in rep.suggestions
                       if s.confidence >= config.MIN_CONFIDENCE_REVIEW]
    rep.crypto = [f for f in rep.crypto
                  if int(f.get("confidence", 0)) >= config.MIN_CONFIDENCE_REVIEW]
    rep.suggestions.sort(key=lambda s: -s.confidence)
    # Release the ctree: a FuncProfile holds a strong reference to the
    # cfunc, and keeping every ctree alive makes analyze_all() memory-heavy.
    # Everything the report needs has already been copied into `rep`.
    if rep.profile is not None:
        rep.profile.cfunc = None
    return rep


# ---------------------------------------------------------------------------
# All functions
# ---------------------------------------------------------------------------

def iter_decompilable_functions():
    """Yield (ea, name) for every function the decompiler can handle."""
    for ea in idautils.Functions():
        if ida_funcs.get_func(ea) is None:
            continue
        yield ea, ida_funcs.get_func_name(ea) or ""


def analyze_all(want=None, progress=None, limit=None, skip_library=True):
    """Analyze every function.  Returns list[FunctionReport].

    The default ``want`` matches what the readability report renders
    (variables, functions, crypto and control flow), so the UI report path
    and a direct ``analyze_function`` call produce the same sections.
    "expr" is intentionally excluded: expression analysis is informational
    and comparatively expensive for a whole-database pass.
    """
    if want is None:
        want = DEFAULT_WANT
    reports = []
    funcs = [ea for ea, _ in iter_decompilable_functions()]
    if limit:
        funcs = funcs[:limit]
    total = len(funcs)
    for i, ea in enumerate(funcs):
        if progress is not None:
            if not progress(i, total):
                break
        if skip_library and not A.is_decompilable(ea, skip_library=True):
            continue
        try:
            rep = analyze_function(ea, want=want)
            reports.append(rep)
        except Exception as exc:
            L.debug("analyze_all failure at %#x: %s" % (ea, exc))
    return reports


# ---------------------------------------------------------------------------
# Readability report
# ---------------------------------------------------------------------------

def generate_readability_report(reports):
    """Render a Markdown readability report from a list of FunctionReports."""
    lines = []
    lines.append("# PseudoClean readability report")
    lines.append("")
    n_funcs = len(reports)
    total_sugg = sum(len(r.showing()) for r in reports)
    errs = sum(1 for r in reports if r.error)
    lines.append("- Functions analyzed: **%d**" % n_funcs)
    lines.append("- Suggestions generated: **%d**" % total_sugg)
    for kind in ("var", "func", "info"):
        n = sum(1 for r in reports for s in r.showing() if s.kind == kind)
        if n:
            lines.append("- %s suggestions: **%d**"
                         % ({"var": "Variable", "func": "Function",
                             "info": "Information"}[kind], n))
    if errs:
        lines.append("- Function-level errors: **%d**" % errs)
    lines.append("")

    # crypto summary table
    crypto_rows = [(r.ea, r.name, r.crypto) for r in reports if r.crypto]
    if crypto_rows:
        lines.append("## Crypto / bitwise findings")
        lines.append("")
        lines.append("| Address | Function | Pattern | Confidence | Detail |")
        lines.append("|---|---|---|---|---|")
        for ea, name, findings in crypto_rows:
            for f in findings:
                lines.append("| `%#x` | `%s` | %s | %d%% | %s |"
                             % (ea, name, f.get("algo", "?"),
                                f.get("confidence", 0),
                                f.get("detail", "").replace("|", "/")))
        lines.append("")

    # top suggestions
    all_sugg = []
    for r in reports:
        for s in r.showing():
            all_sugg.append((r, s))
    all_sugg.sort(key=lambda t: -t[1].confidence)
    if all_sugg:
        lines.append("## Top suggestions")
        lines.append("")
        lines.append("| Function | Kind | Original | Suggested | Conf | Reason |")
        lines.append("|---|---|---|---|---|---|")
        for r, s in all_sugg[:40]:
            lines.append("| `%s` | %s | `%s` | `%s` | %d%% | %s |"
                         % (r.name or ("%#x" % r.ea), s.kind,
                            s.original.replace("|", "/"),
                            s.suggested.replace("|", "/"),
                            s.confidence,
                            s.reason.replace("|", "/")))
        lines.append("")

    # control-flow notes
    cf_rows = [r for r in reports if r.cf_summary is not None]
    if cf_rows:
        lines.append("## Control-flow notes")
        lines.append("")
        lines.append("| Function | Shape | Max if depth | Switch cases |")
        lines.append("|---|---|---|---|")
        for r in cf_rows:
            w = r.cf_summary
            cases = ",".join(str(n) for n in w.switch_cases[:5]) or "-"
            lines.append("| `%s` | loops=%d ifs=%d rets=%d | %d | %s |"
                         % (r.name or ("%#x" % r.ea), w.loop_count,
                            w.if_count, len(w.return_positions),
                            w.max_depth, cases))
        lines.append("")
    elif reports:
        lines.append("## Control-flow notes")
        lines.append("")
        lines.append("_Control-flow analysis was not enabled for this pass._")
        lines.append("")

    # microcode statistics (read-only probe; failures are non-fatal)
    mc_rows = []
    for r in reports[:200]:
        try:
            facts = MC.microcode_facts(r.ea)
        except Exception:
            facts = None
        if facts and facts.get("total"):
            mc_rows.append((r, facts))
    if mc_rows:
        lines.append("## Microcode profile (MMAT_GENERATED)")
        lines.append("")
        lines.append("| Function | Instructions | Dominant ops |")
        lines.append("|---|---|---|")
        for r, facts in mc_rows[:40]:
            lines.append("| `%s` | %d | %s |"
                         % (r.name or ("%#x" % r.ea), facts["total"],
                            ", ".join(facts["top_instructions"][:3])
                            .replace("|", "/")))
        lines.append("")

    if errs:
        lines.append("## Functions that could not be analyzed")
        lines.append("")
        for r in reports:
            if r.error:
                lines.append("- `%#x` `%s`: %s" % (r.ea, r.name, r.error))
        lines.append("")

    return "\n".join(lines)
