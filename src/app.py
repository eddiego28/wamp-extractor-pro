from __future__ import annotations
from PyQt6 import QtWidgets
from .ui.main_window import MainWindow

class Controller:
    def __init__(self) -> None:
        self.app = QtWidgets.QApplication([])
        self.win = MainWindow()

    def run(self) -> int:
        self.win.show()
        return self.app.exec()
