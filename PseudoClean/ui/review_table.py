"""Review table widget: shows suggestions with confidence and reason.

Qt is imported through `ui.qt_binding` so every PseudoClean module uses the
same binding as `ida_kernwin.PluginForm` in the running IDA build.
"""

from __future__ import annotations

from ui.qt_binding import qt
from confidence import GRADE_HIGH, GRADE_MEDIUM, GRADE_LOW


# -- grade colours ----------------------------------------------------------

_GRADE_COLORS = {
    GRADE_HIGH: "#1b5e20",
    GRADE_MEDIUM: "#e65100",
    GRADE_LOW: "#616161",
}


class ReviewTable(object):
    """A QTableWidget wrapper bound to a list of Suggestion objects."""

    COLUMNS = ("Apply", "Function", "Kind", "Original", "Suggested",
               "Confidence", "Reason")

    def __init__(self):
        _name, QtCore, QtGui, QtWidgets = qt()
        self._QtCore = QtCore
        self._QtGui = QtGui
        self._QtWidgets = QtWidgets

        self.widget = QtWidgets.QTableWidget(0, len(self.COLUMNS))
        self.widget.setHorizontalHeaderLabels(list(self.COLUMNS))
        self.widget.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.widget.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.widget.setAlternatingRowColors(True)
        self.widget.verticalHeader().setVisible(False)

        hdr = self.widget.horizontalHeader()
        hdr.setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(
            5, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(
            6, QtWidgets.QHeaderView.ResizeMode.Stretch)

        self._suggestions = []

    # -- population ------------------------------------------------
    def set_suggestions(self, suggestions):
        self._suggestions = list(suggestions)
        self.refresh()

    def refresh(self):
        QtCore = self._QtCore
        QtGui = self._QtGui
        QtWidgets = self._QtWidgets

        self.widget.setRowCount(len(self._suggestions))
        for row, s in enumerate(self._suggestions):
            # checkbox
            item = QtWidgets.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemFlag.ItemIsUserCheckable |
                          QtCore.Qt.ItemFlag.ItemIsEnabled)
            state = QtCore.Qt.CheckState.Checked if s.selected \
                else QtCore.Qt.CheckState.Unchecked
            item.setCheckState(state)
            item.setData(QtCore.Qt.ItemDataRole.UserRole, row)
            self.widget.setItem(row, 0, item)

            func_name = s.func_ea and ("%#x" % s.func_ea) or "-"
            cells = [
                (1, func_name),
                (2, s.kind),
                (3, s.original),
                (4, s.suggested),
                (5, "%d%% %s" % (s.confidence, s.grade)),
                (6, s.reason),
            ]
            for col, text in cells:
                it = QtWidgets.QTableWidgetItem(str(text))
                if col == 5:
                    color = _GRADE_COLORS.get(s.grade)
                    if color:
                        it.setForeground(QtGui.QBrush(QtGui.QColor(color)))
                if col == 3:
                    it.setToolTip(s.original)
                self.widget.setItem(row, col, it)

        self.widget.resizeColumnsToContents()
        try:
            self.widget.horizontalHeader().setSectionResizeMode(
                6, QtWidgets.QHeaderView.ResizeMode.Stretch)
        except Exception:
            pass

    # -- selection state -------------------------------------------
    def sync_selection(self):
        """Copy checkbox state back into the Suggestion objects."""
        QtCore = self._QtCore
        for row, s in enumerate(self._suggestions):
            item = self.widget.item(row, 0)
            if item is None:
                continue
            s.selected = (item.checkState() == QtCore.Qt.CheckState.Checked)
        return self._suggestions

    def selected(self):
        self.sync_selection()
        return [s for s in self._suggestions if s.selected]

    def suggestions(self):
        return list(self._suggestions)

    def set_all(self, state: bool):
        QtCore = self._QtCore
        target = QtCore.Qt.CheckState.Checked if state else \
            QtCore.Qt.CheckState.Unchecked
        for row in range(self.widget.rowCount()):
            item = self.widget.item(row, 0)
            if item is not None:
                item.setCheckState(target)

    def selected_rows(self):
        """Return indices of currently highlighted rows."""
        return sorted({idx.row() for idx in
                       self.widget.selectionModel().selectedRows()})

    def selected_suggestions_by_highlight(self):
        return [self._suggestions[i] for i in self.selected_rows()
                if 0 <= i < len(self._suggestions)]

    def clear(self):
        self._suggestions = []
        self.widget.setRowCount(0)
