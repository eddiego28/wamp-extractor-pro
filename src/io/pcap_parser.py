# src/io/pcap_parser.py
from __future__ import annotations

import re
import json
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ..core.wamp_parser import WampParser


class PcapParser:
    """
    Extrae mensajes WAMP de un PCAP/PCAPNG con WebSocket:
      - Reensambla frames (opcode=1 y continuaciones opcode=0) por tcp.stream.
      - Desenmascara con masking_key y descomprime si procede.
      - Detecta el array WAMP y lo pasa a WampParser.
    Devuelve filas listas para mostrar/exportar (tiempo, topic, root_key, etc.).
    """

    # Campos que pedimos a tshark
    _FIELDS = [
        "frame.number",
        "frame.time_epoch",
        "tcp.stream",
        "websocket.opcode",
        "websocket.fin",
        "websocket.mask",
        "websocket.masking_key",
        "websocket.payload",
        "websocket.payload.text",
    ]

    _HEX_RX = re.compile(r"^(?:[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})*)?$")

    @staticmethod
    def _run_tshark(pcap_path: str) -> List[str]:
        cmd = [
            "tshark",
            "-r",
            pcap_path,
            "-o",
            "tcp.desegment_tcp_streams:true",
            "-Y",
            "websocket && (websocket.opcode==1 || websocket.opcode==0)",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "header=n",
        ]
        for f in PcapParser._FIELDS:
            cmd += ["-e", f]

        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode != 0:
            raise RuntimeError(
                f"tshark falló ({out.returncode}). "
                f"¿Está instalado y en PATH?\nSTDERR:\n{out.stderr}"
            )
        # una línea por frame
        return out.stdout.splitlines()

    @staticmethod
    def _hex_to_bytes(hex_str: str) -> Optional[bytes]:
        if hex_str is None:
            return b""
        s = hex_str.strip()
        if not s:
            return b""
        if not PcapParser._HEX_RX.match(s):
            return None
        s = s.replace(":", "")
        if not s:
            return b""
        return bytes.fromhex(s)

    @staticmethod
    def _unmask(payload: bytearray, mkey_hex: str) -> bytearray:
        if not mkey_hex:
            return payload
        k = bytes.fromhex(mkey_hex.replace(":", ""))
        if len(k) != 4:
            return payload
        for i in range(len(payload)):
            payload[i] ^= k[i % 4]
        return payload

    @staticmethod
    def _maybe_inflate(data: bytes) -> bytes:
        if not data:
            return data
        # Intento DEFLATE "raw" con cola zlib vacía (muy típico en permessage-deflate)
        try:
            import zlib

            return zlib.decompress(data + b"\x00\x00\xff\xff", -zlib.MAX_WBITS)
        except Exception:
            return data

    @staticmethod
    def _first_json_array(s: str) -> Optional[str]:
        """Devuelve el primer array JSON balanceado (p.ej. [16,...]) o None."""
        if not s:
            return None
        start = s.find("[")
        if start < 0:
            return None
        depth = 0
        for i in range(start, len(s)):
            ch = s[i]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return s[start : i + 1]
        return None

    @classmethod
    def _parse_lines(cls, lines: List[str]) -> List[Tuple[float, str]]:
        """
        Reensambla mensajes por stream a partir del TSV de tshark.
        Devuelve lista de (epoch, ws_text) por mensaje completo.
        """
        # Formato: 8 campos (puede venir vacío el último)
        # frame, epoch, stream, opcode, fin, mask, mkey, payload_hex, payload_text
        out: List[Tuple[float, str]] = []
        buffers: Dict[str, bytearray] = {}  # por tcp.stream

        for ln in lines:
            # Asegura 9 columnas; si faltan, completa con ""
            cols = ln.split("\t")
            cols += [""] * (len(cls._FIELDS) - len(cols))

            frame = cols[0]
            epoch_s = cols[1]
            stream = cols[2]
            opcode_s = cols[3]
            fin_s = cols[4]
            mask_s = cols[5]
            mkey = cols[6]
            payload_hex = cols[7]
            payload_text = cols[8]

            # Preferimos el texto directo si viene; si no, reconstruimos de hex
            epoch = float(epoch_s) if epoch_s else 0.0
            opcode = int(opcode_s) if opcode_s.isdigit() else -1
            fin = fin_s == "1" or fin_s == "True"
            masked = mask_s == "1" or mask_s == "True"

            # buffer por stream
            if stream not in buffers:
                buffers[stream] = bytearray()

            # Si tshark ya nos da texto y el frame es independiente (opcode=1 y fin=1)
            # podemos emitir directamente sin reconstrucción:
            if payload_text and opcode == 1 and fin:
                # Puede venir comillas extrañas; no tocar, es el texto tal cual
                out.append((epoch, payload_text))
                buffers[stream].clear()
                continue

            # Si no hay texto, pero hay hex -> acumulamos
            b = cls._hex_to_bytes(payload_hex)
            if b is None:
                # línea rara: ignora
                continue

            if masked and b:
                b = cls._unmask(bytearray(b), mkey)

            if opcode == 1:  # inicio de mensaje de texto
                buffers[stream].clear()
            if opcode in (0, 1) and b:
                buffers[stream].extend(b)

            if fin and opcode in (0, 1):
                data = bytes(buffers[stream])
                data = cls._maybe_inflate(data)
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    text = ""
                if text:
                    out.append((epoch, text))
                buffers[stream].clear()

        return out

    @classmethod
    def extract_records(cls, pcap_path: str) -> List[Dict[str, Any]]:
        """
        Devuelve registros normalizados (aptos para tabla/Excel) desde un pcap/pcapng.
        Cada registro contiene: time, epoch, code, topic, root_key, content_json, raw_json
        """
        lines = cls._run_tshark(pcap_path)
        messages = cls._parse_lines(lines)

        rows: List[Dict[str, Any]] = []
        for epoch, text in messages:
            # Asegura que le pasamos a WampParser el array WAMP
            arr_text = text if text.strip().startswith("[") else (cls._first_json_array(text) or "")
            if not arr_text:
                continue
            rec = WampParser.extract_from_ws_text(arr_text)
            if not rec:
                continue
            row = WampParser.record_to_row(rec, epoch=epoch)
            rows.append(row)
        return rows

    # Alias convenientes para el resto de la app
    @classmethod
    def parse(cls, pcap_path: str) -> List[Dict[str, Any]]:
        return cls.extract_records(pcap_path)

    @classmethod
    def parse_to_rows(cls, pcap_path: str) -> List[Dict[str, Any]]:
        return cls.extract_records(pcap_path)
