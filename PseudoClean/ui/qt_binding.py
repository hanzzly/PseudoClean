"""Single Qt binding resolver shared by every PseudoClean UI module.

IDA 9.4 hosts its Qt UI with PySide6 (shiboken6) and ships the full PySide6
package next to its Python SDK, while still exposing the legacy PyQt5 names
for `PluginForm`.  Mixing bindings in one process is fatal, so every module
imports Qt through this file and the binding is chosen once, in a fixed
order, for the whole session.

Verified against `ida_kernwin.py` (IDA 9.4):
    * ``PluginForm.FormToPyQtWidget``  -> converts through shiboken6 (PySide6)
    * ``PluginForm.FormToPySideWidget`` -> converts through SIP (PyQt5)
The names are historical; `form_to_widget()` below therefore probes both and
keeps whichever result belongs to the loaded binding.

Outside IDA (unit tests) Qt is unavailable and `available()` is False; UI
code must not be touched in that case.
"""

from __future__ import annotations

_BINDING = None       # (name, QtCore, QtGui, QtWidgets)
_ERROR = None

#: Binding preference order.  PySide6 is IDA 9.x's real UI binding.
_ORDER = ("PySide6", "PyQt5")


def _load():
    global _BINDING, _ERROR
    if _BINDING is not None or _ERROR is not None:
        return _BINDING
    errors = []
    for name in _ORDER:
        try:
            if name == "PySide6":
                from PySide6 import QtCore, QtGui, QtWidgets  # type: ignore
            else:
                from PyQt5 import QtCore, QtGui, QtWidgets  # type: ignore
            _BINDING = (name, QtCore, QtGui, QtWidgets)
            return _BINDING
        except Exception as exc:
            errors.append("%s: %s" % (name, exc))
    _ERROR = "; ".join(errors)
    return None


def qt():
    """Return (name, QtCore, QtGui, QtWidgets); raises when unavailable."""
    b = _load()
    if b is None:
        raise RuntimeError("No usable Qt binding found: %s" % _ERROR)
    return b


def available():
    return _load() is not None


def binding_name():
    b = _load()
    return b[0] if b else None


def form_to_widget(form):
    """Convert an IDA ``PluginForm`` into a QWidget of the loaded binding.

    The conversion helper whose output is an instance of the loaded
    ``QtWidgets.QWidget`` wins; the other is a no-op for this process.  This
    keeps the panel working on IDA builds that wire the legacy PyQt5 names to
    a PySide6 conversion (9.4) and on builds that do not.
    """
    import ida_kernwin
    _name, _QtCore, _QtGui, QtWidgets = qt()

    candidates = []
    if binding_name() == "PySide6":
        candidates = ["FormToPyQtWidget", "FormToPySideWidget"]
    else:
        candidates = ["FormToPySideWidget", "FormToPyQtWidget"]

    last_err = None
    for cand in candidates:
        conv = getattr(ida_kernwin.PluginForm, cand, None)
        if conv is None:
            continue
        try:
            widget = conv(form)
        except Exception as exc:
            last_err = exc
            continue
        if isinstance(widget, QtWidgets.QWidget):
            return widget
    raise RuntimeError("could not convert the IDA form to a %s widget: %s"
                       % (binding_name(), last_err))
