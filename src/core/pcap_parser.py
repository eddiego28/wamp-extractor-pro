from __future__ import annotations
import json
import subprocess
import shutil
from typing import Any, Dict, Iterable, List, Optional, Tuple

def ensure_tshark() -> None:
    if not shutil.which("tshark"):
        raise RuntimeError("'tshark' no está en PATH. Instala Wireshark/Tshark y reinicia la terminal.")

def build_display_filter(
    ip_any: Optional[str] = None,
    ip_src: Optional[str] = None,
    ip_dst: Optional[str] = None,
    port_any: Optional[str] = None,
    port_src: Optional[str] = None,
    port_dst: Optional[str] = None,
    direction: str = "both",   # 'client_to_server' (masked), 'server_to_client' (unmasked), 'both'
    opcode_text: bool = True,
    opcode_binary: bool = False,
    time_from: Optional[str] = None,   # form: '2025-08-20 16:27:00'
    time_to: Optional[str] = None,
    extra: Optional[str] = None,
) -> str:
    parts: List[str] = ["websocket", "(websocket.opcode==1 || websocket.opcode==0)" ]
    # include binary if requested
    if opcode_binary:
        parts[-1] = "(websocket.opcode==1 || websocket.opcode==0 || websocket.opcode==2)"

    if ip_any:
        parts.append(f"ip.addr == {ip_any}")
    if ip_src:
        parts.append(f"ip.src == {ip_src}")
    if ip_dst:
        parts.append(f"ip.dst == {ip_dst}")
    if port_any:
        parts.append(f"tcp.port == {port_any}")
    if port_src:
        parts.append(f"tcp.srcport == {port_src}")
    if port_dst:
        parts.append(f"tcp.dstport == {port_dst}")
    if direction == "client_to_server":
        parts.append("websocket.mask == 1")
    elif direction == "server_to_client":
        parts.append("websocket.mask == 0")
    # Time range: Wireshark uses frame.time; display filter exact syntax can vary per locale; keep optional via extra if needed.
    # Users can pass a full custom filter in 'extra' if necessary.
    if extra:
        parts.append(f"({extra})")
    return " && ".join(parts)

def run_tshark_json(pcap_path: str, display_filter: str) -> List[Dict[str, Any]]:
    ensure_tshark()
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-o", "tcp.desegment_tcp_streams:true",
        "-Y", display_filter,
        "-T", "json",
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"tshark error: {res.stderr.decode(errors='ignore')}")
    try:
        data = json.loads(res.stdout.decode('utf-8', errors='ignore') or '[]')
        if isinstance(data, list):
            return data
        return []
    except Exception as ex:
        raise RuntimeError(f"No se pudo parsear JSON desde tshark: {ex}")

def extract_frames(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rec in records:
        layers = rec.get('_source', {}).get('layers', {})
        frame = layers.get('frame', {})
        tcp = layers.get('tcp', {})
        ws = layers.get('websocket', {})
        time_epoch = frame.get('frame.time_epoch')
        num = frame.get('frame.number')
        # payload text may be nested
        payload_text = None
        ws_payload = ws.get('websocket.payload', {})
        if isinstance(ws_payload, dict):
            payload_text = ws_payload.get('websocket.payload.text')
        if payload_text is None:
            payload_text = ws.get('websocket.payload.text')
        # Normalize list values from Wireshark JSON (sometimes arrays)
        if isinstance(payload_text, list) and payload_text:
            payload_text = payload_text[0]
        if isinstance(time_epoch, list): time_epoch = time_epoch[0]
        if isinstance(num, list): num = num[0]
        out.append({
            'frame_number': int(num) if num else None,
            'epoch': float(time_epoch) if time_epoch else None,
            'payload_text': payload_text,
        })
    return out
