# NetLogic Signal

Herramienta de auditoría de equipos Windows, de **NetLogic**. Un solo script, de **solo lectura**
(no instala ni cambia nada), que revisa a fondo el estado de una PC y **compara contra la corrida
anterior** — te dice qué cambió desde la última vez, no solo "cómo está hoy". Pensada para el
mantenimiento preventivo recurrente de PyMEs, no para una auditoría de seguridad única.

## Uso

### Método 1 — PowerShell (recomendado: no hay que descargar ni copiar nada a mano)

```powershell
irm https://raw.githubusercontent.com/Xelt3r/netlogic-signal-public/main/Invoke-NetLogicSignal.ps1 | iex
```

Corré esto en PowerShell **como Administrador** (clic derecho → Ejecutar como administrador, o
Windows+X → "Terminal de Windows (administrador)") para cobertura completa — sin admin, la
herramienta sigue funcionando pero algunos datos (BitLocker, TPM, exclusiones de Defender,
políticas de cuenta) quedan sin medir.

Te va a preguntar interactivamente: nombre de la empresa, tu nombre, y qué tipo de revisión
querés (Completa / Hardware / Inventario / Rendimiento / Seguridad).

### Método 2 — Manual (descargar y ejecutar)

Bajá el archivo y hacé doble clic — se auto-eleva a administrador y abre el mismo menú que el
Método 1. Es un único archivo (el motor completo va embebido adentro, no hace falta ningún `.zip`
ni instalar nada más):

**[⬇ Descargar NetLogicSignal.bat](https://github.com/Xelt3r/netlogic-signal-public/raw/main/NetLogicSignal.bat)**

## Qué audita

### Licencias
- Windows: estado de activación, canal, clave parcial, clave OEM del firmware, servidor KMS.
- **Office**: versión, canal (retail/OEM/KMS/MAK/suscripción), estado, servidor KMS, fin de soporte.
- **Rastros de activadores no oficiales** (Ohook, KMS_VL_ALL, MAS Online KMS) — firmas tomadas del
  propio código fuente de cada activador.
- Microsoft 365 por usuario (licencias del usuario auditado).

### Sistema operativo y parches
- Versión, build, arquitectura, fecha de instalación, tiempo encendido.
- **Fin de soporte de Windows** por build y edición (incluye LTSC/LTSB/IoT, y evidencia de
  Windows 10 ESU).
- Último parche instalado, cantidad total, estado del servicio de Windows Update.
- Reinicio pendiente · políticas/pausas de Windows Update / WSUS.

### Software
- Software instalado (nunca con `Win32_Product`, que fuerza reparaciones de MSI).
- Software sin soporte (SQL Server viejo, Office viejo, etc.).
- **Herramientas de acceso remoto instaladas** (AnyDesk, TeamViewer, RustDesk, ScreenConnect, VNC,
  agentes RMM…) y **corriendo en este momento** (incluidas copias portables nunca instaladas).
- **Sesiones RDP conectadas ahora · logons RDP** (desde Internet o no).
- **UltraViewer con clave fija** (acceso desatendido) — se lee de su propio log de conexiones.
- Navegadores, extensiones, tamaño de PST/OST de Outlook, cuentas de OneDrive/Drive.
- Programas de inicio, tareas no-Microsoft, servicios de terceros.
- **Autoruns con patrón de malware** — cada línea y cada ruta juzgadas por quién puede escribir esa
  carpeta (no solo "está en el registro de inicio").
- Winlogon modificado, hijack de accesibilidad (sticky keys).

### Antivirus
- Productos registrados, activo/actualizado.
- **Defender**: antigüedad real de firmas, PUA, exclusiones, historial de amenazas (últimos 90
  días, con si la acción funcionó), reglas ASR, manipulación (tamper protection).

### Cuentas y accesos
- Política de contraseñas, bloqueo, historial, complejidad.
- Usuarios locales, administradores, invitado, cuentas sin contraseña.
- **¿El usuario diario es administrador?** (vs. el técnico que elevó para la auditoría).
- Último logon (cuentas inactivas) · cuenta Administrador integrada habilitada.
- **PIN de Windows Hello** (vencimiento, longitud).
- Bloqueo de pantalla por inactividad · LAPS · permisos de carpetas compartidas (Everyone).

### Configuración de seguridad (hardening)
- BitLocker (estado, %, clave de recuperación), TPM, Secure Boot, firewall por perfil, RDP.
- RDP con NLA y su puerto · SMBv1 · firma SMB.
- UAC · protección LSA · WDigest · Credential Guard/VBS.
- LLMNR/NetBIOS · logging de PowerShell · Autorun.
- Control de USB (bloqueo/solo lectura) + historial · políticas de almacenamiento removible.
- Autologin.

### Red
- Adaptadores (IP, MAC), DNS, gateway, DHCP.
- Puertos escuchando con su proceso.
- Proxy · Wi-Fi guardado (nunca la clave) · archivo hosts · VPN.

### Hardware y salud
- Fabricante, modelo, SKU, serie, placa, CPU (zócalo/soldado), RAM (módulos, posiciones vacías,
  soldada/en zócalo) — validado contra **1.424 equipos reales** públicos.
- BIOS, tipo de chasis (notebook/desktop).
- Salud real de disco (desgaste, temperatura, errores vía SMART).
- Batería (capacidad de diseño vs. actual).
- Monitores, impresoras, periféricos.

### Logs y eventos
- Política de auditoría, log de seguridad (tamaño/modo).
- Pantallas azules, cortes de luz, errores de disco, logons fallidos, bloqueos, log borrado.
- Instalaciones de software con qué usuario las hizo.
- Sincronización horaria.

### Protección de datos / backup
- Software/tareas de backup, sincronización a la nube, discos de red/removibles, uso de disco,
  puntos de restauración.
- Último backup exitoso · certificados por vencer.

### Rendimiento
- RAM/memoria comprometida/archivo de paginación, procesos top en RAM/CPU, actividad de disco,
  espacio libre en cada unidad.
- Índice de estabilidad, cuelgues/cierres por programa, avisos de poca memoria/disco lleno,
  tiempos de arranque.

## Comparación entre corridas (lo que hace a esto "Signal")

```powershell
.\Invoke-NetLogicSignal.ps1 -Compare -Baseline "revision-anterior.json" -Current "revision-nueva.json"
```

Es un **veredicto comparativo**, no solo un diff de datos — te dice explícitamente qué **mejoró**,
qué **empeoró** y qué **sigue igual** respecto a la última vez:
- **Resuelto**: hallazgos que estaban y ya no están (algo se arregló).
- **Nuevo**: hallazgos que no estaban antes (algo empezó a andar mal, o se detectó algo que no se
  veía antes).
- **Persiste**: hallazgos que siguen iguales en ambas corridas (sigue siendo un problema sin tocar).
- **Reclasificado**: el mismo problema real, pero el diagnóstico cambió porque la herramienta mejoró
  de versión entre ambas corridas (no confundir "diagnóstico más preciso" con "cambio real en la PC").

Además: software agregado/quitado/cambiado de versión, administradores agregados/quitados, señales
de reimagen o cambio de hardware, tendencias numéricas (RAM, estabilidad, batería, espacio libre) y
parches nuevos desde la última vez. No necesita una "lista de software autorizado" — lo nuevo/
quitado contra la propia corrida anterior de esa PC ES la señal.

## Qué NO hace (a propósito)

- **No instala ni actualiza nada** — es de solo lectura por diseño. No es un reemplazo de
  Windows Update, PDQ ni NinjaOne.
- **No es antivirus ni EDR** — audita si tenés uno activo y actualizado, no reemplaza ninguno.
- **No tiene agente permanente con alertas en tiempo real** — es una foto periódica con diff, no
  vigilancia 24/7. Para alertas en tiempo real existen herramientas dedicadas (Level.io, Action1,
  NinjaOne) — esta herramienta no compite con eso, resuelve algo distinto: una auditoría a fondo,
  con hallazgos en español y mapeo a normas de compliance (p. ej. OEA/AFIP), que esas herramientas
  comerciales no ofrecen.
- **No monitorea routers/switches/impresoras** — solo la PC Windows donde corre.

## Hacia dónde va

Decidido y realista con la misma arquitectura (leer → hallazgos → comparar), sin agente permanente:
- Instalación de actualizaciones de Windows pendientes en lote (disparado de forma local en cada
  equipo, nunca por llamada remota directa — así lo exige la propia documentación de Microsoft).
- Push de scripts/instaladores puntuales a varios equipos.
- **Módulo liviano de red por SNMP** (routers, switches, impresoras) — la adición de más valor, hoy
  100% ausente.
- Evidencia de restauración de backup probada (hoy solo se detecta que existe un backup, no si
  alguna vez se probó restaurarlo) — pedido explícito de varias aseguradoras cyber consultadas.
- MFA — gap real tanto para aseguradoras como para CIS Controls v8 IG1, pero vive en el proveedor
  de identidad (Entra ID/AD), no en el endpoint — se evalúa aparte.

Descartado a propósito (no tiene sentido para un operador técnico, no una empresa de 50 personas):
alertas 24/7 con agente siempre encendido, plataforma propia de tickets, portal de autogestión
para el cliente, deployment de software a escala con anillos de rollout.

## Privacidad

**Nunca se sube información de clientes a este repositorio.** Los JSON/CSV que genera cada corrida
quedan en la carpeta de cada cliente, nunca en git. El motor es genérico: no tiene nombres de
empresas ni de personas hardcodeados.
