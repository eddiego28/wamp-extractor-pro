from __future__ import annotations
from PyQt6 import QtWidgets, QtGui, QtCore

class FiltersDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Filtros (tshark)")
        self.setMinimumWidth(500)

        self.ip_any = QtWidgets.QLineEdit()
        self.ip_src = QtWidgets.QLineEdit()
        self.ip_dst = QtWidgets.QLineEdit()
        self.port_any = QtWidgets.QLineEdit()
        self.port_src = QtWidgets.QLineEdit()
        self.port_dst = QtWidgets.QLineEdit()

        self.direction = QtWidgets.QComboBox()
        self.direction.addItems(["both","client_to_server","server_to_client"])  # masked/unmasked

        self.op_text = QtWidgets.QCheckBox("Texto (opcode 1)"); self.op_text.setChecked(True)
        self.op_bin  = QtWidgets.QCheckBox("Binario (opcode 2)")

        self.extra = QtWidgets.QLineEdit()
        self.extra.setPlaceholderText("Filtro Wireshark adicional (opcional)")

        form = QtWidgets.QFormLayout()
        form.addRow("IP cualquiera:", self.ip_any)
        form.addRow("IP src:", self.ip_src)
        form.addRow("IP dst:", self.ip_dst)
        form.addRow("Puerto cualquiera:", self.port_any)
        form.addRow("Puerto src:", self.port_src)
        form.addRow("Puerto dst:", self.port_dst)
        form.addRow("Dirección:", self.direction)
        form.addRow(self.op_text, self.op_bin)
        form.addRow("Display filter extra:", self.extra)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        main = QtWidgets.QVBoxLayout(self)
        main.addLayout(form)
        main.addWidget(btns)

    def get_values(self):
        return {
            'ip_any': self.ip_any.text().strip() or None,
            'ip_src': self.ip_src.text().strip() or None,
            'ip_dst': self.ip_dst.text().strip() or None,
            'port_any': self.port_any.text().strip() or None,
            'port_src': self.port_src.text().strip() or None,
            'port_dst': self.port_dst.text().strip() or None,
            'direction': self.direction.currentText(),
            'opcode_text': self.op_text.isChecked(),
            'opcode_binary': self.op_bin.isChecked(),
            'extra': self.extra.text().strip() or None,
        }

    def set_values(self, values: dict):
        self.ip_any.setText(values.get('ip_any') or "")
        self.ip_src.setText(values.get('ip_src') or "")
        self.ip_dst.setText(values.get('ip_dst') or "")
        self.port_any.setText(values.get('port_any') or "")
        self.port_src.setText(values.get('port_src') or "")
        self.port_dst.setText(values.get('port_dst') or "")
        d = values.get('direction') or 'both'
        idx = self.direction.findText(d)
        self.direction.setCurrentIndex(idx if idx>=0 else 0)
        self.op_text.setChecked(values.get('opcode_text', True))
        self.op_bin.setChecked(values.get('opcode_binary', False))
        self.extra.setText(values.get('extra') or "")
