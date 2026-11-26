"""PseudoClean main dockable panel.

Dockable via ida_kernwin.PluginForm; hosts the review table and action
buttons.  Whole-database analysis runs on a worker thread and marshals every
database access back to IDA's main thread with
``ida_kernwin.execute_sync(..., MFF_READ)``; UI updates are queued with
``execute_ui_requests``.  The progress bar and the Cancel button work while
the analysis runs, and a decompiled ``cfunc`` is released by the analyzer
after each function.
"""

from __future__ import annotations

import threading
import traceback

import ida_kernwin
import ida_hexrays
import ida_funcs
import idautils
import idaapi

import analyzer
import ast_analyzer as A
import c_beautifier
import change_manager as CM
import logging_util as L
import solver_generator
from confidence import Suggestion
from ui.qt_binding import qt, form_to_widget
from ui.review_table import ReviewTable
from ui.settings import SettingsDialog
from ui.syntax_highlighter import setup_highlighter


class PseudoCleanPanel(ida_kernwin.PluginForm):
    """Dockable panel exposing the PseudoClean workflow."""

    def __init__(self, title="PseudoClean"):
        ida_kernwin.PluginForm.__init__(self)
        self.title = title
        self.change_mgr = CM.ChangeManager()
        self._pending_suggestions = []
        self._qt_widget = None
        self._table = None
        self._thread = None
        self._cancel = False
        self._job = None           # dict: want, label, done, total, reports
        self._on_done = None

    # -- PluginForm lifecycle --------------------------------------
    def OnCreate(self, form):
        try:
            self._qt_widget = form_to_widget(form)
            self._build_ui()
        except Exception as exc:
            L.warn("panel init failed: %s\n%s" % (exc, traceback.format_exc()))

    def OnClose(self, form):
        self._cancel = True
        self._qt_widget = None
        self._table = None

    def Show(self):
        return ida_kernwin.PluginForm.Show(
            self, self.title,
            options=(ida_kernwin.PluginForm.WOPN_TAB |
                     ida_kernwin.PluginForm.WCLS_CLOSE_LATER))

    def Close(self):
        self._cancel = True
        try:
            ida_kernwin.PluginForm.Close(self,
                                          ida_kernwin.PluginForm.WCLS_SAVE)
        except Exception:
            pass

    # -- UI construction -------------------------------------------
    def _build_ui(self):
        _name, QtCore, QtGui, QtWidgets = qt()
        self._QtWidgets = QtWidgets
        self._QtCore = QtCore
        self._QtGui = QtGui

        root = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(root)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- action buttons (two rows) ----------------------------
        row1 = QtWidgets.QHBoxLayout()
        self.btn_analyze = QtWidgets.QPushButton("Analyze Function")
        self.btn_analyze_all = QtWidgets.QPushButton("Analyze All")
        self.btn_vars = QtWidgets.QPushButton("Suggest Var Names")
        self.btn_funcs = QtWidgets.QPushButton("Suggest Func Names")
        for b in (self.btn_analyze, self.btn_analyze_all,
                  self.btn_vars, self.btn_funcs):
            row1.addWidget(b)
        layout.addLayout(row1)

        row2 = QtWidgets.QHBoxLayout()
        self.btn_simplify = QtWidgets.QPushButton("Simplify Expressions")
        self.btn_obfuscation = QtWidgets.QPushButton("Detect Obfuscation")
        self.btn_report = QtWidgets.QPushButton("Readability Report")
        for b in (self.btn_simplify, self.btn_obfuscation,
                  self.btn_report):
            row2.addWidget(b)
        layout.addLayout(row2)

        row3 = QtWidgets.QHBoxLayout()
        self.btn_apply = QtWidgets.QPushButton("Apply Selected")
        self.btn_apply.setStyleSheet("font-weight: bold;")
        self.btn_revert = QtWidgets.QPushButton("Revert Plugin Changes")
        self.btn_select_all = QtWidgets.QPushButton("Select All")
        self.btn_select_none = QtWidgets.QPushButton("Select None")
        self.btn_settings = QtWidgets.QPushButton("Settings…")
        for b in (self.btn_apply, self.btn_revert, self.btn_select_all,
                  self.btn_select_none, self.btn_settings):
            row3.addWidget(b)
        layout.addLayout(row3)

        # --- review table ----------------------------------------
        self._table = ReviewTable()
        layout.addWidget(self._table.widget, 1)

        # --- progress + cancel -----------------------------------
        prog_row = QtWidgets.QHBoxLayout()
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        self.btn_cancel = QtWidgets.QPushButton("Cancel")
        self.btn_cancel.setVisible(False)
        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.btn_cancel)
        layout.addLayout(prog_row)

        # --- status bar ------------------------------------------
        self.status = QtWidgets.QLabel("Ready.")
        layout.addWidget(self.status)

        # --- signal wiring ---------------------------------------
        self.btn_analyze.clicked.connect(self.on_analyze_function)
        self.btn_analyze_all.clicked.connect(self.on_analyze_all)
        self.btn_vars.clicked.connect(self.on_suggest_vars)
        self.btn_funcs.clicked.connect(self.on_suggest_funcs)
        self.btn_simplify.clicked.connect(self.on_simplify)
        self.btn_obfuscation.clicked.connect(self.on_obfuscation)
        self.btn_report.clicked.connect(self.on_report)
        self.btn_apply.clicked.connect(self.on_apply)
        self.btn_revert.clicked.connect(self.on_revert)
        self.btn_select_all.clicked.connect(lambda: self._table.set_all(True))
        self.btn_select_none.clicked.connect(lambda: self._table.set_all(False))
        self.btn_settings.clicked.connect(self.on_settings)
        self.btn_cancel.clicked.connect(self.on_cancel)

        # --- tabs ------------------------------------------------
        self.tabs = QtWidgets.QTabWidget()

        # Tab 1: Review & Suggestions
        tab_review = QtWidgets.QWidget()
        tab_review.setLayout(layout)
        self.tabs.addTab(tab_review, "Review & Suggestions")

        # Tab 2: Clean C & CTF Solver
        tab_ctf = QtWidgets.QWidget()
        ctf_layout = QtWidgets.QVBoxLayout(tab_ctf)
        ctf_layout.setContentsMargins(6, 6, 6, 6)

        ctf_btn_row = QtWidgets.QHBoxLayout()
        self.btn_beautify = QtWidgets.QPushButton("Beautify Pseudocode")
        self.btn_beautify.setStyleSheet("font-weight: bold;")
        self.btn_gen_solver = QtWidgets.QPushButton("Generate Z3 Solver")
        self.btn_copy_code = QtWidgets.QPushButton("Copy Text")
        ctf_btn_row.addWidget(self.btn_beautify)
        ctf_btn_row.addWidget(self.btn_gen_solver)
        ctf_btn_row.addWidget(self.btn_copy_code)
        ctf_layout.addLayout(ctf_btn_row)

        self.code_viewer = QtWidgets.QPlainTextEdit()
        font = QtGui.QFont("Consolas", 10)
        font.setStyleHint(QtGui.QFont.Monospace)
        self.code_viewer.setFont(font)
        self.code_viewer.setStyleSheet(
            "QPlainTextEdit { background-color: #1e1e1e; color: #d4d4d4; "
            "selection-background-color: #264f78; font-family: Consolas, monospace; font-size: 10pt; }"
        )
        self.code_viewer.setPlaceholderText(
            "// Clean C code or Z3 solver will appear here.\n"
            "// Click 'Beautify Pseudocode' or 'Generate Z3 Solver' for the function under cursor."
        )
        self._highlighter = setup_highlighter(self.code_viewer)
        ctf_layout.addWidget(self.code_viewer, 1)

        self.tabs.addTab(tab_ctf, "Clean C & CTF Solver")

        self.btn_beautify.clicked.connect(self.on_beautify)
        self.btn_gen_solver.clicked.connect(self.on_gen_solver)
        self.btn_copy_code.clicked.connect(self.on_copy_code)

        lay = QtWidgets.QVBoxLayout(self._qt_widget)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.tabs)
        self._qt_widget.setLayout(lay)

    # -- helpers ---------------------------------------------------
    def _set_status(self, msg):
        try:
            self.status.setText(msg)
        except Exception:
            L.log(msg)

    def _current_func_ea(self):
        """EA of the function under the pseudocode cursor."""
        try:
            widget = ida_kernwin.get_current_widget()
            if widget is not None:
                vdui = ida_hexrays.get_widget_vdui(widget)
                if vdui is not None and vdui.cfunc is not None:
                    return vdui.cfunc.entry_ea
        except Exception:
            pass
        # fall back to the disassembly cursor
        try:
            ea = ida_kernwin.get_screen_ea()
            return ida_funcs.get_func_start(ea) or idaapi.BADADDR
        except Exception:
            return idaapi.BADADDR

    # -- background analysis ---------------------------------------
    @staticmethod
    def _analyze_one(ea, want):
        """Runs on the main thread through execute_sync."""
        try:
            return analyzer.analyze_function(ea, want=want)
        except Exception as exc:
            L.debug("analysis failed at %#x: %s" % (ea, exc))
            return None

    def _start_background(self, want, label, on_done):
        if self._thread is not None and self._thread.is_alive():
            self._set_status("An analysis is already running; cancel it first.")
            return False
        funcs = []
        try:
            for ea in idautils.Functions():
                if A.is_decompilable(ea, skip_library=True):
                    funcs.append(ea)
        except Exception as exc:
            self._set_status("Could not list functions: %s" % exc)
            return False
        self._cancel = False
        self._on_done = on_done
        self._job = {"want": want, "label": label, "done": 0,
                     "total": len(funcs), "reports": []}
        self.progress.setRange(0, max(1, len(funcs)))
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.btn_cancel.setVisible(True)
        self.btn_cancel.setEnabled(True)
        self._set_busy(True)
        self._set_status("%s: 0/%d functions…" % (label, len(funcs)))

        if not ida_kernwin.is_idaq():
            # No UI message loop (idat -A / scripted use): a worker thread
            # could never be serviced through execute_sync and would hang
            # forever.  Run the same pass inline — there is no UI to keep
            # responsive in that mode anyway.
            reports = []
            for i, ea in enumerate(funcs):
                rep = self._analyze_one(ea, want)
                if rep is not None:
                    reports.append(rep)
                self._on_progress(i, rep)
            self._on_finished(reports)
            return True

        self._thread = threading.Thread(target=self._worker,
                                        args=(want, funcs), daemon=True)
        self._thread.start()
        return True

    def _worker(self, want, funcs):
        """Worker thread: decompile only inside execute_sync, UI via requests.

        `execute_sync` returns an ``int`` (it marshals the callable's result
        through IDA's request queue), so the report is collected through a
        holder instead of the return value.
        """
        reports = []
        for i, ea in enumerate(funcs):
            if self._cancel:
                break
            box = []

            def _job(ea=ea, box=box):
                box.append(self._analyze_one(ea, want))
                return 0

            ida_kernwin.execute_sync(_job, ida_kernwin.MFF_READ)
            rep = box[0] if box else None
            if rep is not None:
                reports.append(rep)
            ida_kernwin.execute_ui_requests(
                [lambda i=i, rep=rep: self._on_progress(i, rep)])
        ida_kernwin.execute_ui_requests([lambda: self._on_finished(reports)])

    def _on_progress(self, i, rep):
        job = self._job
        if job is None:
            return
        job["done"] = i + 1
        self.progress.setValue(i + 1)
        if (i + 1) % 25 == 0 or rep is not None:
            self._set_status("%s: %d/%d functions"
                             % (job["label"], i + 1, job["total"]))

    def _on_finished(self, reports):
        job = self._job
        cancelled = self._cancel
        self._job = None
        self._cancel = False
        self.progress.setVisible(False)
        self.btn_cancel.setVisible(False)
        self._set_busy(False)
        if job is None:
            return
        if cancelled:
            self._set_status("Cancelled: %d/%d functions analyzed."
                             % (len(reports), job["total"]))
        else:
            self._set_status("%s finished: %d function(s)."
                             % (job["label"], len(reports)))
        on_done = self._on_done
        self._on_done = None
        if on_done is not None:
            try:
                on_done(reports)
            except Exception as exc:
                L.warn("analysis completion failed: %s\n%s"
                       % (exc, traceback.format_exc()))

    def _set_busy(self, busy):
        for b in (self.btn_analyze, self.btn_analyze_all, self.btn_vars,
                  self.btn_funcs, self.btn_simplify, self.btn_obfuscation,
                  self.btn_report):
            b.setEnabled(not busy)

    def on_cancel(self):
        if self._thread is None or not self._thread.is_alive():
            return
        self._cancel = True
        self.btn_cancel.setEnabled(False)
        self._set_status("Cancelling after the current function…")

    # -- actions ---------------------------------------------------
    def on_analyze_function(self):
        ea = self._current_func_ea()
        if ea in (0, idaapi.BADADDR):
            self._set_status("No function under cursor.")
            return
        self._set_status("Analyzing %#x…" % ea)
        try:
            rep = analyzer.analyze_function(ea)
        except Exception as exc:
            self._set_status("Analysis failed: %s" % exc)
            L.debug(traceback.format_exc())
            return
        self._load_report(rep)
        n = len(rep.showing())
        self._set_status("Analyzed `%s`: %d suggestion(s)" % (rep.name, n))

    def on_analyze_all(self):
        self._start_background({"vars", "func", "crypto", "cf"},
                               "Analyze all",
                               self._show_reports)

    def _show_reports(self, reports):
        all_sugg = []
        for r in reports:
            all_sugg.extend(r.showing())
        all_sugg.sort(key=lambda s: -s.confidence)
        self._pending_suggestions = all_sugg
        self._table.set_suggestions(all_sugg)
        self._set_status("Analyzed %d functions: %d suggestion(s)"
                         % (len(reports), len(all_sugg)))

    def _load_report(self, rep):
        sugg = list(rep.showing())
        self._pending_suggestions = sugg
        self._table.set_suggestions(sugg)

    def on_suggest_vars(self):
        ea = self._current_func_ea()
        if ea in (0, idaapi.BADADDR):
            self._set_status("No function under cursor.")
            return
        try:
            rep = analyzer.analyze_function(ea, want={"vars"})
        except Exception as exc:
            self._set_status("Failed: %s" % exc)
            return
        self._load_report(rep)
        self._set_status("%d variable suggestion(s) for `%s`"
                         % (len(rep.showing()), rep.name))

    def on_suggest_funcs(self):
        self._start_background({"func", "crypto"}, "Function naming",
                               self._show_function_names)

    def _show_function_names(self, reports):
        sugg = []
        for r in reports:
            sugg.extend(s for s in r.showing()
                        if s.kind == Suggestion.KIND_FUNC)
        sugg.sort(key=lambda s: -s.confidence)
        self._pending_suggestions = sugg
        self._table.set_suggestions(sugg)
        self._set_status("%d function suggestion(s)"
                         % len(sugg))

    def on_simplify(self):
        ea = self._current_func_ea()
        if ea in (0, idaapi.BADADDR):
            self._set_status("No function under cursor.")
            return
        try:
            rep = analyzer.analyze_function(ea, want={"expr"})
        except Exception as exc:
            self._set_status("Failed: %s" % exc)
            return
        self._load_report(rep)
        self._set_status("%d expression observation(s) for `%s`"
                         % (len(rep.showing()), rep.name))

    def on_obfuscation(self):
        ea = self._current_func_ea()
        if ea in (0, idaapi.BADADDR):
            self._set_status("No function under cursor.")
            return
        try:
            rep = analyzer.analyze_function(ea, want={"crypto", "cf"})
        except Exception as exc:
            self._set_status("Failed: %s" % exc)
            return
        rows = []
        for f in rep.crypto:
            rows.append(Suggestion(
                Suggestion.KIND_INFO, rep.name or ("%#x" % ea),
                "%s: %s" % (f.get("algo", "?"), f.get("kind", "?")),
                f.get("confidence", 0), f.get("detail", ""),
                ea=ea, func_ea=ea))
        rows.extend(rep.showing())
        self._pending_suggestions = rows
        self._table.set_suggestions(rows)
        self._set_status("%d obfuscation/crypto indicator(s)" % len(rows))

    def on_report(self):
        self._start_background({"vars", "func", "crypto", "cf"},
                               "Readability report",
                               self._save_report)

    def _save_report(self, reports):
        QtWidgets = self._QtWidgets
        try:
            text = analyzer.generate_readability_report(reports)
        except Exception as exc:
            self._set_status("Report failed: %s" % exc)
            L.debug(traceback.format_exc())
            return

        import ida_diskio
        import os
        try:
            default_dir = ida_diskio.get_user_idadir()
        except Exception:
            default_dir = os.path.expanduser("~")
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self._qt_widget, "Save readability report",
            os.path.join(default_dir, "pseudoclean_report.md"),
            "Markdown (*.md);;Text (*.txt);;All files (*)")
        if not path:
            self._set_status("Report cancelled.")
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self._set_status("Report saved to %s" % path)
        except Exception as exc:
            self._set_status("Failed to write report: %s" % exc)

    # -- Clean C & CTF Solver actions -----------------------------
    def on_beautify(self):
        ea = self._current_func_ea()
        if ea == idaapi.BADADDR:
            self._set_status("No function selected.")
            return
        self._set_status("Beautifying pseudocode for %#x..." % ea)
        try:
            clean_code = c_beautifier.beautify_function(ea)
            self.code_viewer.setPlainText(clean_code)
            self._set_status("Beautified function %#x successfully." % ea)
        except Exception as exc:
            self._set_status("Beautify failed: %s" % exc)

    def on_gen_solver(self):
        ea = self._current_func_ea()
        if ea == idaapi.BADADDR:
            self._set_status("No function selected.")
            return
        self._set_status("Generating Z3 solver for %#x..." % ea)
        try:
            solver_code = solver_generator.generate_solver_for_function(ea)
            self.code_viewer.setPlainText(solver_code)
            self._set_status("Generated Z3 solver for function %#x." % ea)
        except Exception as exc:
            self._set_status("Solver generation failed: %s" % exc)

    def on_copy_code(self):
        text = self.code_viewer.toPlainText()
        if not text:
            self._set_status("Nothing to copy.")
            return
        try:
            cb = self._QtWidgets.QApplication.clipboard()
            if cb:
                cb.setText(text)
                self._set_status("Copied to clipboard.")
            else:
                self._set_status("Clipboard unavailable.")
        except Exception as exc:
            self._set_status("Copy failed: %s" % exc)

    # -- apply / revert --------------------------------------------
    def on_apply(self):
        QtWidgets = self._QtWidgets
        selected = self._table.selected()
        if not selected:
            self._set_status("Nothing selected.")
            return
        conf = QtWidgets.QMessageBox.StandardButton
        resp = QtWidgets.QMessageBox.question(
            self._qt_widget, "Apply selected changes",
            "Apply %d selected change(s)?" % len(selected))
        if resp != conf.Yes:
            return

        applied, failed = self._apply(selected)
        self._set_status("Applied %d change(s); %d failure(s)"
                         % (len(applied), len(failed)))
        for s, err in failed[:5]:
            L.warn("apply failed for %r -> %r: %s"
                   % (s.original, s.suggested, err))
        # refresh table (keep only unapplied/failed)
        remaining = [s for s in self._table.suggestions()
                     if s not in applied]
        self._table.set_suggestions(remaining)
        self._pending_suggestions = remaining

        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

    def _apply(self, suggestions):
        """Apply a mixed list of var/func/comment suggestions."""
        applied, failed = [], []
        var_s = [s for s in suggestions if s.kind == Suggestion.KIND_VAR]
        func_s = [s for s in suggestions if s.kind == Suggestion.KIND_FUNC]
        info_s = [s for s in suggestions if s.kind in (
            Suggestion.KIND_INFO, Suggestion.KIND_EXPR)]

        # --- variable renames ------------------------------------
        if var_s:
            import variable_renamer as VR
            a, f = VR.apply_variable_renames(var_s)
            for s in a:
                self.change_mgr.record_suggestion(s, module="variable")
            applied.extend(a)
            failed.extend(f)

        # --- function renames ------------------------------------
        if func_s:
            import function_renamer as FR
            a, f = FR.apply_function_renames(func_s)
            for s in a:
                self.change_mgr.record_suggestion(s, module="function")
            applied.extend(a)
            failed.extend(f)

        # --- expression annotations -------------------------------
        if info_s:
            import expression_simplifier as ES
            by_func = {}
            for s in info_s:
                by_func.setdefault(s.func_ea, []).append(s)
            for fea, items in by_func.items():
                try:
                    cfunc = ida_hexrays.decompile(fea)
                except Exception as exc:
                    for s in items:
                        failed.append((s, "decompile failed: %s" % exc))
                    continue
                if cfunc is None:
                    for s in items:
                        failed.append((s, "no cfunc"))
                    continue
                a, f = ES.annotate_suggestions(cfunc, items, fea)
                for s in a:
                    self.change_mgr.record_suggestion(s, module="comment")
                applied.extend(a)
                failed.extend(f)

        return applied, failed

    def on_revert(self):
        QtWidgets = self._QtWidgets
        conf = QtWidgets.QMessageBox.StandardButton
        stats = self.change_mgr.stats()
        if stats["active"] == 0:
            self._set_status("No plugin changes to revert.")
            return
        resp = QtWidgets.QMessageBox.question(
            self._qt_widget, "Revert plugin changes",
            "Revert all %d active change(s)?\n"
            "(comments created by PseudoClean are removed too)"
            % stats["active"])
        if resp != conf.Yes:
            return

        reverted, failed = self.change_mgr.revert_all()

        # refresh each touched function's decompilation cache
        for e in self.change_mgr.entries:
            try:
                ida_hexrays.mark_cfunc_dirty(e["func_ea"], True)
            except Exception:
                pass
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

        self._set_status("Reverted %d change(s); %d failure(s)"
                         % (reverted, len(failed)))
        self._table.clear()

    def on_settings(self):
        dlg = SettingsDialog(self._qt_widget)
        if dlg.exec_():
            self._set_status("Settings updated.")
