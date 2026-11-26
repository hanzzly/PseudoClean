"""Settings dialog for PseudoClean.

Exposes only knobs that actually change behaviour.  Automatic application of
suggestions is deliberately not offered: every change must be reviewed and
applied explicitly by the user.
"""

from __future__ import annotations

import config
from ui.qt_binding import qt


class SettingsDialog(object):
    """Small modal dialog exposing the tunable knobs."""

    def __init__(self, parent=None):
        _name, QtCore, QtGui, QtWidgets = qt()
        self._QtWidgets = QtWidgets

        self.dlg = QtWidgets.QDialog(parent)
        self.dlg.setWindowTitle("PseudoClean settings")
        layout = QtWidgets.QVBoxLayout(self.dlg)

        # min confidence
        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel("Minimum confidence to display:"))
        self.min_conf = QtWidgets.QSpinBox()
        self.min_conf.setRange(0, 100)
        self.min_conf.setValue(config.MIN_CONFIDENCE_REVIEW)
        row.addWidget(self.min_conf)
        layout.addLayout(row)

        # debug logging
        self.debug = QtWidgets.QCheckBox("Verbose debug logging")
        self.debug.setChecked(config.LOG_DEBUG)
        layout.addWidget(self.debug)

        # microcode simplifier (off by default)
        from expression_simplifier import microcode_simplifier_active
        self.micro = QtWidgets.QCheckBox(
            "Enable microcode algebraic simplifier hook "
            "(Hex-Rays usually does this already)")
        self.micro.setChecked(microcode_simplifier_active())
        layout.addWidget(self.micro)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.dlg.accept)
        buttons.rejected.connect(self.dlg.reject)
        layout.addWidget(buttons)

    def exec_(self):
        QtWidgets = self._QtWidgets
        if self.dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return False

        config.MIN_CONFIDENCE_REVIEW = self.min_conf.value()
        config.LOG_DEBUG = self.debug.isChecked()

        import expression_simplifier as ES
        if self.micro.isChecked() and not ES.microcode_simplifier_active():
            ES.install_microcode_simplifier()
        elif not self.micro.isChecked() and ES.microcode_simplifier_active():
            ES.remove_microcode_simplifier()

        config.save_settings(
            min_confidence=config.MIN_CONFIDENCE_REVIEW,
            debug=config.LOG_DEBUG,
            microcode=ES.microcode_simplifier_active())
        return True
