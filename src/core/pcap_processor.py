import json
import shutil
import subprocess
from typing import List, Dict, Any, Optional
from .wamp_parser import parse_wamp_text, WampState, to_msg
from .model import WampMessage

def find_tshark() -> str:
    exe = shutil.which("tshark")
    if not exe:
        raise RuntimeError("No se encontró 'tshark'. Instala Wireshark o añade 'tshark' al PATH.")
    return exe

def _get_layer_value(layers: Dict[str, Any], path: List[str]) -> Optional[Any]:
    node: Any = layers
    for key in path:
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return None
    return node

def process_pcap(path: str) -> List[WampMessage]:
    exe = find_tshark()
    # Extraemos a JSON solo lo relevante
    cmd = [
        exe, "-r", path,
        "-o", "tcp.desegment_tcp_streams:true",
        "-Y", "websocket && websocket.payload.text",
        "-T", "json",
        "-J", "frame,tcp,ip,websocket"
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark error: {proc.stderr.strip()}")
    try:
        frames = json.loads(proc.stdout)
    except Exception as e:
        raise RuntimeError("No se pudo parsear la salida JSON de tshark") from e

    state = WampState()
    out: List[WampMessage] = []
    for it in frames:
        layers = it.get('_source', {}).get('layers', {})
        # epoch
        epoch_s = _get_layer_value(layers, ['frame', 'frame.time_epoch'])
        try:
            epoch = float(epoch_s) if epoch_s is not None else 0.0
        except Exception:
            epoch = 0.0
        # stream
        stream = _get_layer_value(layers, ['tcp', 'tcp.stream']) or "0"
        if isinstance(stream, list):
            stream = stream[0]
        stream = str(stream)
        # src/dst
        src = _get_layer_value(layers, ['ip', 'ip.src'])
        dst = _get_layer_value(layers, ['ip', 'ip.dst'])
        # payload text
        ws = layers.get('websocket', {})
        payload_node = ws.get('websocket.payload', {})
        # Algunas versiones de tshark exponen directamente 'websocket.payload.text'
        ptxt = None
        if isinstance(payload_node, dict) and 'websocket.payload.text' in payload_node:
            ptxt = payload_node['websocket.payload.text']
        elif 'websocket.payload.text' in ws:
            ptxt = ws['websocket.payload.text']
        # Normalizar a string
        if isinstance(ptxt, list):
            payload_text = "".join(ptxt)
        else:
            payload_text = ptxt
        if not payload_text:
            # ignorar si no hay texto
            continue
        # parsea WAMP
        arr = parse_wamp_text(payload_text)
        if not arr:
            continue
        msg = to_msg(arr, epoch, stream, src, dst, state)
        if msg:
            out.append(msg)
    return out
