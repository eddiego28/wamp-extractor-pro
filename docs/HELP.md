# Ayuda rápida

**Flujo básico**  
1. `Archivo → Cargar PCAP/PCAPNG…`  
2. `Filtros → Configurar…`: pon IP/puertos del router WAMP si quieres limitar el tráfico.  
3. Pulsa **Procesar**. Verás los mensajes en la tabla (código WAMP, topic, hora, contenido, etc).  
4. `Exportar → A Excel` o `Exportar → NDJSON`.

**Filtros (pre)** — se aplican en *tshark* (más rápidos):
- **IP src/dst** o **IP cualquiera** (addr).  
- **Puerto src/dst** o **Puerto cualquiera**.  
- **Dirección**: cliente→servidor (masked), servidor→cliente (unmasked) o ambos.  
- **Opcode**: texto(1), binario(2).  
- **Rango temporal**: `frame.time >=/<=` (se traduce a display filter).  
- **Display filter extra**: cualquier expresión Wireshark adicional.

**Filtros (post)** — se aplican en la app:
- **Código WAMP** (HELLO, PUBLISH, EVENT, …).  
- **Topic** contiene …  
- **Payload contiene …**

**Códigos WAMP comunes**
- 1 HELLO, 2 WELCOME, 16 PUBLISH, 17 PUBLISHED, 32 SUBSCRIBE, 33 SUBSCRIBED, 36 EVENT, 48 CALL, 50 RESULT.

**Excel**
- La hoja **Messages** contiene los mensajes con JSON aplanado.  
- La hoja **Summary** lista topics y realms únicos.

**Problemas habituales**
- *“No hay mensajes”*: revisa filtros previos (quizá demasiado restrictivos); prueba sin IP/puerto.
- *Binario/MsgPack*: esta herramienta asume JSON. Si tu payload no es texto, habilita opcode 2 y “forzar decodificación UTF-8”.
- *wss (TLS)*: necesitas descifrado en Wireshark para que `websocket.payload.text` sea visible.

