from __future__ import annotations
from typing import Any, Dict, List, Optional
from PyQt6 import QtWidgets, QtGui, QtCore
import os, json, traceback

from ..core.pcap_parser import build_display_filter, run_tshark_json, extract_frames
from ..core.exporters import to_excel, to_ndjson
from ..core.wamp_parser import normalize_wamp
from .filters_dialog import FiltersDialog
from .help_dialog import HelpDialog

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WAMP Extractor Pro")
        self.resize(1200, 700)
        self.current_pcap: Optional[str] = None
        self.records: List[Dict[str, Any]] = []
        self.frames: List[Dict[str, Any]] = []
        self.filtered_frames: List[Dict[str, Any]] = []
        self.topics: List[str] = []
        self.realms: List[str] = []
        self.filters_state: Dict[str, Any] = {
            'ip_any': None, 'ip_src': None, 'ip_dst': None,
            'port_any': None, 'port_src': None, 'port_dst': None,
            'direction': 'both', 'opcode_text': True, 'opcode_binary': False,
            'extra': None
        }

        self._build_ui()

    # ---------------- UI ----------------
    def _build_ui(self):
        # Toolbar-like Menus
        menubar = self.menuBar()
        m_file = menubar.addMenu("&Archivo")
        act_open = QtGui.QAction("Cargar PCAP/PCAPNG…", self); act_open.triggered.connect(self.on_open)
        m_file.addAction(act_open)
        m_file.addSeparator()
        act_exit = QtGui.QAction("Salir", self); act_exit.triggered.connect(self.close)
        m_file.addAction(act_exit)

        m_filters = menubar.addMenu("&Filtros")
        act_cfg = QtGui.QAction("Configurar…", self); act_cfg.triggered.connect(self.on_filters)
        m_filters.addAction(act_cfg)

        m_export = menubar.addMenu("&Exportar")
        act_xlsx = QtGui.QAction("A Excel (.xlsx)…", self); act_xlsx.triggered.connect(self.on_export_xlsx)
        act_ndj  = QtGui.QAction("A NDJSON (.json)…", self); act_ndj.triggered.connect(self.on_export_ndjson)
        m_export.addAction(act_xlsx); m_export.addAction(act_ndj)

        m_help = menubar.addMenu("&Ayuda")
        act_help = QtGui.QAction("Ver ayuda", self); act_help.triggered.connect(self.on_help)
        m_help.addAction(act_help)

        # Top filter bar (post-filters)
        top = QtWidgets.QWidget()
        top_layout = QtWidgets.QHBoxLayout(top)
        self.cmb_code = QtWidgets.QComboBox()
        self.cmb_code.addItems(["(Todos)", "HELLO", "WELCOME", "PUBLISH", "EVENT", "SUBSCRIBE", "RESULT"])
        self.le_topic = QtWidgets.QLineEdit(); self.le_topic.setPlaceholderText("filtrar topic contiene…")
        self.le_substr = QtWidgets.QLineEdit(); self.le_substr.setPlaceholderText("filtrar payload contiene…")
        btn_apply = QtWidgets.QPushButton("Aplicar filtros"); btn_apply.clicked.connect(self.apply_post_filters)
        self.btn_process = QtWidgets.QPushButton("Procesar"); self.btn_process.clicked.connect(self.process_current)
        top_layout.addWidget(QtWidgets.QLabel("Código:")); top_layout.addWidget(self.cmb_code)
        top_layout.addWidget(QtWidgets.QLabel("Topic:")); top_layout.addWidget(self.le_topic, 1)
        top_layout.addWidget(QtWidgets.QLabel("Texto:")); top_layout.addWidget(self.le_substr, 1)
        top_layout.addWidget(btn_apply); top_layout.addWidget(self.btn_process)

        # Table
        self.table = QtWidgets.QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "#", "Hora", "Epoch", "Código", "Topic", "Realm", "Root", "Resumen"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)

        # Log
        self.log = QtWidgets.QPlainTextEdit(); self.log.setReadOnly(True)
        self.log.setMaximumHeight(120)

        # Central layout
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.addWidget(top)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.log)
        self.setCentralWidget(central)

        self.statusBar().showMessage("Listo.")

    # ---------------- actions ----------------
    def on_open(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Abrir captura", "", "Capturas (*.pcap *.pcapng)")
        if not path: return
        self.current_pcap = path
        self.statusBar().showMessage(f"Archivo: {os.path.basename(path)} — listo para procesar.")

    def on_filters(self):
        dlg = FiltersDialog(self)
        dlg.set_values(self.filters_state)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            self.filters_state = dlg.get_values()

    def on_export_xlsx(self):
        if not self.filtered_frames:
            QtWidgets.QMessageBox.warning(self, "Exportar", "No hay datos filtrados para exportar.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Guardar Excel", "mensajes.xlsx", "Excel (*.xlsx)")
        if not path: return
        try:
            to_excel(self.filtered_frames, path, self.topics, self.realms)
            self.statusBar().showMessage(f"Excel guardado: {path}")
        except Exception as ex:
            QtWidgets.QMessageBox.critical(self, "Error", str(ex))

    def on_export_ndjson(self):
        if not self.filtered_frames:
            QtWidgets.QMessageBox.warning(self, "Exportar", "No hay datos filtrados para exportar.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Guardar NDJSON", "mensajes.json", "JSON (*.json)")
        if not path: return
        try:
            from . import main_window  # no-op against pyflakes
            from ..core.exporters import to_ndjson
            to_ndjson(self.filtered_frames, path)
            self.statusBar().showMessage(f"NDJSON guardado: {path}")
        except Exception as ex:
            QtWidgets.QMessageBox.critical(self, "Error", str(ex))

    def on_help(self):
        help_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "HELP.md"))
        text = "(Ayuda no encontrada)"
        try:
            with open(help_path, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception:
            pass
        dlg = HelpDialog(self, text)
        dlg.exec()

    # ---------------- processing ----------------
    def process_current(self):
        if not self.current_pcap:
            QtWidgets.QMessageBox.warning(self, "Procesar", "Primero carga un archivo PCAP/PCAPNG.")
            return
        try:
            filt = build_display_filter(**self.filters_state)
            self.log.appendPlainText(f"Display filter: {filt}")
            records = run_tshark_json(self.current_pcap, filt)
            self.records = records
            frames = extract_frames(records)
            self.frames = frames
            # build topics/realms
            topics = set(); realms = set()
            for fr in frames:
                pt = fr.get('payload_text')
                n = normalize_wamp(pt or "") if isinstance(pt, str) else None
                if n:
                    if n['topic']: topics.add(n['topic'])
                    if n['realm']: realms.add(n['realm'])
            self.topics = sorted(topics)
            self.realms = sorted(realms)
            self.apply_post_filters()
        except Exception as ex:
            tb = traceback.format_exc()
            self.log.appendPlainText(tb)
            QtWidgets.QMessageBox.critical(self, "Error", str(ex))

    def apply_post_filters(self):
        code_filter = self.cmb_code.currentText()
        topic_sub = self.le_topic.text().strip().lower()
        substr = self.le_substr.text().strip().lower()

        res = []
        for fr in self.frames:
            pt = fr.get('payload_text')
            if not isinstance(pt, str):
                continue
            n = normalize_wamp(pt)
            if not n: 
                continue
            # code filter
            if code_filter != "(Todos)" and n['code_name'] != code_filter:
                continue
            # topic substring
            if topic_sub and not ((n.get('topic') or '') and topic_sub in n['topic'].lower()):
                continue
            # payload substring
            if substr and substr not in (pt.lower()):
                continue
            # keep
            res.append({
                **fr,
                'norm': n,
            })
        self.filtered_frames = res
        self.populate_table()

    def populate_table(self):
        self.table.setRowCount(0)
        for i, fr in enumerate(self.filtered_frames, start=1):
            n = fr['norm']
            epoch = fr.get('epoch')
            time_str = None
            if isinstance(epoch, (int, float)):
                import datetime
                dt = datetime.datetime.utcfromtimestamp(float(epoch))
                time_str = dt.strftime('%H:%M:%S.') + f"{int(dt.microsecond/1000):03d}"
            summary = None
            content = n.get('content')
            if isinstance(content, dict) and n.get('root_key'):
                # print just first-level keys under root
                rk = n['root_key']
                inner = content.get(rk, {}) if isinstance(content.get(rk), dict) else content
                if isinstance(inner, dict):
                    summary = ", ".join([f"{k}={v}" for k, v in list(inner.items())[:5]])
            elif isinstance(content, list):
                summary = f"args[{len(content)}]"
            else:
                summary = ""

            row = self.table.rowCount()
            self.table.insertRow(row)
            def setc(c, val):
                item = QtWidgets.QTableWidgetItem("" if val is None else str(val))
                self.table.setItem(row, c, item)
            setc(0, i)
            setc(1, time_str)
            setc(2, epoch)
            setc(3, f"{n['code']} {n['code_name']}")
            setc(4, n.get('topic'))
            setc(5, n.get('realm'))
            setc(6, n.get('root_key'))
            setc(7, summary)

        self.statusBar().showMessage(f"{len(self.filtered_frames)} mensaje(s) listados. Topics únicos: {len(self.topics)}. Realms únicos: {len(self.realms)}.")
