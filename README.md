# WAMP Extractor Pro

Aplicación de escritorio (PyQt6) para extraer, explorar y exportar mensajes **WAMP** desde capturas **PCAP/PCAPNG** usando `tshark` (Wireshark).

## Características
- Filtros avanzados antes de procesar: IP/puerto, dirección (cliente→servidor, servidor→cliente), opcode (texto/binario), rango temporal (display filter), etc.
- Filtros en la aplicación: por código WAMP (HELLO/WELCOME/PUBLISH/EVENT/…), por topic, por substring del payload.
- Reconstrucción robusta de WebSocket: reensamblado TCP, desenmascarado, inflado (permessage-deflate).
- Detección de marcos **WAMP**: `[code, …]` con soporte de `args/kwargs` y normalización.
- Exportación a **Excel** (xlsx) y **NDJSON**.
- Resumen de **Realms** y **Topics** detectados.
- UI profesional con barra de herramientas, estado, diálogo de filtros y ayuda integrada.

## Requisitos
- Python 3.10+
- `tshark` accesible en el PATH (Wireshark/CLI).

## Instalación
```bash
pip install -r requirements.txt
```

## Ejecución
```bash
python -m src.main
```

## Consejos de filtrado
Los filtros previos (display filter de Wireshark) reducen el tamaño antes de parsear.
- IP de router WAMP: `ip.addr == 192.168.1.10`
- Puerto: `tcp.port == 8080`
- Dirección:
  - Cliente→Servidor (frames **masked**): `websocket.mask == 1`
  - Servidor→Cliente (frames **unmasked**): `websocket.mask == 0`
- Solo texto (JSON): `websocket.opcode == 1`

La aplicación compone todo eso automáticamente a partir del diálogo **Filtros**.

## Exportación a Excel
- Hora en `HH:MM:SS.mmm` con `epoch` disponible.
- Columnas aplanadas de JSON (hasta profundidad razonable).

## Limitaciones conocidas
- Si el servidor usa binario/MsgPack (opcode 2), esta versión se centra en JSON. Puedes activarlo en Filtros → incluir opcode 2; el contenido se intentará decodificar a texto si es UTF-8.
- Para TLS (wss://), necesitarás descifrado en Wireshark (`ssl.keylog_file`) para que `websocket.payload.text` sea visible.

