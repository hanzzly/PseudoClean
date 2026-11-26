"""Syntax highlighter for C and Python pseudocode / solver viewer.

Applies clean syntax highlighting to QPlainTextEdit in both dark and light modes
without external dependencies.
"""

from __future__ import annotations

import re


def setup_highlighter(text_edit):
    """Attaches a syntax highlighter to a QTextEdit or QPlainTextEdit if Qt is available."""
    try:
        from ui.qt_binding import qt, available
        if not available():
            return None
        _name, QtCore, QtGui, QtWidgets = qt()
    except Exception:
        return None

    class CodeHighlighter(QtGui.QSyntaxHighlighter):
        def __init__(self, parent_doc):
            super().__init__(parent_doc)
            self._rules = []

            def _fmt(color_hex, bold=False, italic=False):
                f = QtGui.QTextCharFormat()
                f.setForeground(QtGui.QColor(color_hex))
                if bold:
                    f.setFontWeight(QtGui.QFont.Bold)
                if italic:
                    f.setFontItalic(True)
                return f

            # Formats (VS Code dark theme inspired)
            fmt_keyword = _fmt("#569CD6", bold=True)
            fmt_type = _fmt("#4EC9B0", bold=True)
            fmt_string = _fmt("#CE9178")
            fmt_number = _fmt("#B5CEA8")
            fmt_comment = _fmt("#6A9955", italic=True)
            fmt_fn = _fmt("#DCDCAA")
            fmt_preprocessor = _fmt("#C586C0")

            # Keywords
            keywords = [
                r"\bif\b", r"\belse\b", r"\bfor\b", r"\bwhile\b", r"\bdo\b",
                r"\breturn\b", r"\bbreak\b", r"\bcontinue\b", r"\bswitch\b",
                r"\bcase\b", r"\bdefault\b", r"\bextern\b", r"\bstatic\b",
                r"\bconst\b", r"\bdef\b", r"\bfrom\b", r"\bimport\b",
                r"\bas\b", r"\btry\b", r"\bexcept\b", r"\bclass\b",
                r"\bNone\b", r"\bTrue\b", r"\bFalse\b", r"\band\b", r"\bor\b", r"\bnot\b"
            ]
            for kw in keywords:
                self._rules.append((re.compile(kw), fmt_keyword))

            # Types
            types = [
                r"\bint\b", r"\bchar\b", r"\bvoid\b", r"\bsize_t\b",
                r"\buint8_t\b", r"\buint16_t\b", r"\buint32_t\b", r"\buint64_t\b",
                r"\bint8_t\b", r"\bint16_t\b", r"\bint32_t\b", r"\bint64_t\b",
                r"\bunsigned\b", r"\bsigned\b", r"\bstruct\b", r"\benum\b",
                r"\bBitVec\b", r"\bBitVecVal\b", r"\bSolver\b"
            ]
            for tp in types:
                self._rules.append((re.compile(tp), fmt_type))

            # Preprocessor
            self._rules.append((re.compile(r"^\s*#\s*[a-zA-Z_]+\b"), fmt_preprocessor))

            # Function calls
            self._rules.append((re.compile(r"\b([a-zA-Z_0-9]+)(?=\s*\()"), fmt_fn))

            # Numbers (hex and dec)
            self._rules.append((re.compile(r"\b0x[0-9a-fA-F]+\b"), fmt_number))
            self._rules.append((re.compile(r"\b\d+\b"), fmt_number))

            # Strings
            self._rules.append((re.compile(r'"[^"\\]*(\\.[^"\\]*)*"'), fmt_string))
            self._rules.append((re.compile(r"'[^'\\]*(\\.[^'\\]*)*'"), fmt_string))

            # Line comments (// and #)
            self._rules.append((re.compile(r"//[^\n]*"), fmt_comment))
            self._rules.append((re.compile(r"#[^\n]*"), fmt_comment))

        def highlightBlock(self, text):
            for pattern, fmt in self._rules:
                for match in pattern.finditer(text):
                    start = match.start()
                    length = match.end() - start
                    self.setFormat(start, length, fmt)

    try:
        doc = text_edit.document()
        return CodeHighlighter(doc)
    except Exception:
        return None
