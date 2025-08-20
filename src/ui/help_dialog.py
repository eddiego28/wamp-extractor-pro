from __future__ import annotations
from PyQt6 import QtWidgets, QtGui, QtCore
import os

class HelpDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, help_text: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Ayuda - WAMP Extractor Pro")
        self.resize(800, 600)

        te = QtWidgets.QTextEdit()
        te.setReadOnly(True)
        te.setPlainText(help_text)

        btn = QtWidgets.QPushButton("Cerrar")
        btn.clicked.connect(self.accept)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(te)
        layout.addWidget(btn)
