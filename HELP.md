# Ayuda rápida

## Flujo típico
1. **Archivo → Abrir PCAP/PCAPNG** y elige un `.pcap` o `.pcapng`.
2. Pulsa **Procesar** (botón de la barra o `F5`).  
   Esto lanzará `tshark` y extraerá `websocket.payload.text`.
3. Verás los mensajes en la tabla. Opcionalmente, filtra por **topic**.
4. **Exportar → NDJSON** o **Exportar → Excel** para guardar resultados.

## Columnas principales (tabla)
- **Hora (local)**: `YYYY-MM-DD HH:MM:SS.mmm`
- **Tipo**: nombre de mensaje WAMP (p. ej. EVENT, PUBLISH, HELLO...)
- **Realm**: determinado a partir de HELLO/WELCOME del mismo stream.
- **Topic**: tema (si aplica).
- **SubId / PubId**: `subscription` / `publication` (si aplica).
- **Args / Kwargs**: arrays/dicts (JSON).

## Excel
- Hoja **Messages** con columnas base + campos aplanados (de `kwargs` o del primer dict en `args`).
- Hojas por **topic** (hasta 20) con los mismos campos.
- Hojas **Topics**, **Subscriptions** y **Summary**.

## Notas
- Si la compresión *permessage-deflate* está activa, Wireshark de-normalmente muestra el texto en `websocket.payload.text` ya desmascarado y descomprimido; por eso usamos esa ruta.
- Este extractor funciona **offline** con capturas; no se conecta al router.
- Si no aparecen mensajes:
  - Verifica que tu captura contenga **WebSocket** y `websocket.payload.text`.
  - Revisa que `tshark` esté en PATH.
  - Prueba con el filtro *puerto* correcto al capturar (p. ej. `tcp.port == 60001`).

## Atajos
- **F5** Procesar
- **Ctrl+E** Exportar NDJSON
- **Ctrl+Shift+E** Exportar Excel
- **F1** Ayuda
