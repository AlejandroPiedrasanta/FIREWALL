# MiniWall

Firewall y monitor de red **minimalista para Windows**, inspirado en GlassWire.
Es un único `MiniWall.exe` portable (~10 MB): no necesita instalación, no usa
servicios en la nube y guarda todos sus datos en tu equipo.

**Descarga:** [`dist/MiniWall.exe`](dist/MiniWall.exe) (Windows 10/11 de 64 bits).

> Al ser un ejecutable sin firma digital, Windows SmartScreen puede avisar la
> primera vez: pulsa *Más información → Ejecutar de todas formas*. MiniWall pide
> permisos de administrador porque los necesita para gestionar el Firewall de
> Windows y medir el tráfico de cada app.

## Funciones

| Función de GlassWire | En MiniWall |
|---|---|
| Monitorización visual de la red | Gráfico en vivo de descarga/subida (1 muestra por segundo) y lista de apps conectadas ahora mismo. |
| Monitor de uso de ancho de banda | Pestaña **Uso**: día, semana o mes con barras, apps, hosts y países que más consumen. |
| Historial de gráficos más extenso | Historial de 7 a 365 días (configurable). |
| Máquina del tiempo de red | Elige cualquier día pasado y haz clic en el gráfico para ver qué apps usaron la red en esa hora. |
| Perfiles de firewall | Perfiles con nombre (Normal, Wi‑Fi pública, Juegos…); cada uno con sus propias apps bloqueadas. |
| Solicitar conexión y bloqueo | Tres modos: **Monitorizar**, **Preguntar** (las apps nuevas se bloquean hasta que las permitas) y **Bloquear todo**. Con **Bloqueo estricto** la pregunta persiste: toda conexión de salida se bloquea por defecto en el Firewall de Windows, así que cada programa nuevo queda bloqueado y te pide permiso **aunque reinicies o aunque MiniWall esté cerrado**. |
| Seguridad en Internet | Alertas cuando una app se conecta por primera vez o cuando su ejecutable cambia. |
| Alertas discretas | Notificaciones de Windows desde la bandeja, configurables por tipo y con modo silencio. |
| Mapa interactivo del mundo | Mapa con los países a los que te conectas; clic en un país para filtrar sus hosts y conexiones. |
| ¿Quién está conectado a tu red? | Dispositivos de tu red local (leídos de forma pasiva de la caché ARP), con aviso de dispositivos nuevos y nombres personalizados. |
| Detección de gemelos malvados | Recuerda el punto de acceso (BSSID) y la seguridad de cada red Wi‑Fi y avisa si cambian. |
| Protección de la privacidad | Avisa cuando una app empieza a usar la cámara o el micrófono, con historial de accesos. |
| Detección de conexión RDP | Alerta ante conexiones de Escritorio remoto entrantes y permite bloquear RDP con un clic. |
| Monitorización de recursos de hardware | Pestaña **Sistema**: CPU, memoria, discos y adaptadores de red. |
| Temas y apariencias oscuras | 5 temas: Oscuro, Claro, Medianoche, Grafito y Bosque. |
| Minigráfico | Ventana pequeña siempre visible con el tráfico en vivo (doble clic para volver). |

Extra:

- **Instalación en el equipo**: desde Ajustes → *Instalar ahora* (o el menú de la
  bandeja) MiniWall se copia a `Archivos de programa`, crea accesos directos, se
  registra en *Agregar o quitar programas* y arranca con Windows en segundo plano
  para seguir vigilando y preguntando por programas nuevos.
- **Bloqueo estricto** (control máximo): bloqueo de salida por defecto que
  **permanece tras reiniciar y aunque MiniWall esté cerrado**. Las apps que ya
  usabas se permiten solas al activarlo; solo se pregunta por las nuevas.
- **Protección reforzada (guardián)**: reactiva el Firewall de Windows si algo lo
  apaga y reaplica tus reglas cada pocos segundos.
- **Bloqueos permanentes**: cada bloqueo es una regla del Firewall de Windows, así
  que se mantiene aunque reinicies o cierres la app.
- Visibilidad total de procesos (privilegio de depuración), lista de **puertos
  abiertos a la red** por app y velocidad actual en el icono de la bandeja.
- Interfaz **"liquid glass"** (cristal esmerilado translúcido) con 5 temas.

### Detección de amenazas y control maestro

Pestaña **Amenazas**: análisis heurístico en tiempo real de cada programa con
actividad de red. No es un antivirus con firmas, pero marca en **rojo** las
señales que suelen delatar malware o programas no deseados:

- Ejecutable **sin firma digital** válida (Authenticode).
- Ubicado en carpetas **temporales o de descargas**.
- Que **se hace pasar por un proceso de Windows** (p. ej. `svchost.exe` fuera de
  System32) — señal clásica de malware.
- **Servicios ocultos / puertas traseras**: programas que **escuchan** conexiones
  entrantes accesibles desde la red (`0.0.0.0`), e indicios de **Tor** (.onion).
- Conexiones a **muchos países** distintos (posible baliza / botnet).

El **control maestro** te deja marcar con un clic qué programas **no deberían
tener acceso**: se bloquean en el Firewall de Windows y quedan resaltados en rojo
en toda la app. Botón **"Bloquear todo lo peligroso"** para cortar de golpe lo
marcado como peligro.

El gráfico y las conexiones se actualizan en **tiempo real preciso** (la tasa se
normaliza por el tiempo transcurrido real y las conexiones se refrescan cada
segundo).

### Modo simple, pop-up de permiso y Adobe

- **Modo simple** (icono ✨ arriba a la derecha, o en Ajustes y la bandeja):
  interfaz ultra sencilla con **solo Firewall y Amenazas**; oculta todo lo demás.
  Se puede volver al modo completo cuando quieras.
- **Pop-up de permiso dentro de la app** (no una notificación de Windows): en
  modo *Preguntar*, cuando un programa nuevo intenta conectarse, MiniWall trae la
  ventana al frente y muestra un cuadro **¿Permitir la conexión?** con Permitir /
  Bloquear, el riesgo del programa y el motivo. La decisión se guarda como regla
  del Firewall de Windows, así que **se mantiene aunque reinicies**.
- **Botón "Restaurar (permitir todo)"** en el panel del firewall: quita todos los
  bloqueos y vuelve a permitir todas las conexiones de una vez.
- **Detección de Adobe**: MiniWall reconoce los programas de Adobe (Acrobat,
  Creative Cloud, telemetría, licencias…) cuando se conectan, los marca con una
  etiqueta **Adobe** y te **avisa**. Puedes desactivar el aviso en Ajustes.
- Más **privilegios**: además de administrador, MiniWall activa los privilegios
  del sistema disponibles (depuración, copia, etc.) para tener visibilidad total
  de los procesos.

### Instalador más potente y "Preguntar" por defecto

- El modo **Preguntar antes de conectar** viene **activado de fábrica**: MiniWall
  actúa como filtro principal y, ante cualquier programa nuevo que intente usar
  Internet, lo identifica (nombre, ruta, firma, riesgo) y muestra el **pop-up**
  para permitir o bloquear. La decisión se guarda como regla del Firewall de
  Windows (persiste tras reiniciar).
- El **bloqueo es exacto por programa** (por ruta del ejecutable): bloquear una
  app nunca afecta a las conexiones de otra.
- El **instalador** comprueba e instala el runtime **WebView2** si falta (para que
  la interfaz se vea siempre), además de crear accesos directos, registrar la
  desinstalación y configurar el arranque con Windows.
- Para un bloqueo **antes de conectar** al 100 %, activa además el **Bloqueo
  estricto** (deniega la salida por defecto y permite solo lo que apruebes).

**No incluido** (a propósito, para mantenerlo minimalista y sin exponer nada a
la red): la monitorización remota de servidores y la consola de administración
multi‑equipo. La interfaz solo escucha en `127.0.0.1` y exige un token aleatorio
generado en cada inicio.

## Cómo funciona

- **Bloqueo:** crea reglas en el Firewall de Windows con el prefijo
  `MiniWall - …` (entrada y salida por ejecutable). Solo toca sus propias reglas.
  El modo *Bloquear todo* cambia la directiva predeterminada a bloquear el
  tráfico saliente; al cerrar MiniWall se restaura para no dejarte sin conexión.
- **Tráfico por app:** sesión ETW en tiempo real del proveedor
  `Microsoft-Windows-Kernel-Network`. Los totales del equipo se leen de los
  contadores de los adaptadores físicos.
- **Conexiones:** `GetExtendedTcpTable` / `GetExtendedUdpTable` con el proceso propietario.
- **País de cada IP:** base de datos incrustada y sin conexión
  ([ip-location-db](https://github.com/sapics/ip-location-db), CC0).
- **Mapa:** [Natural Earth](https://www.naturalearthdata.com/) (dominio público).
- **Interfaz:** HTML/CSS/JS incrustado y mostrado con Microsoft Edge WebView2
  (preinstalado en Windows 10/11). Si falta, se abre en tu navegador.
- **Datos:** `%APPDATA%\MiniWall` (`config.json`, `history.json`, `alerts.json`, `miniwall.log`).

Antes de borrar MiniWall puedes usar **Ajustes → Quitar todas las reglas de
MiniWall** para dejar el Firewall de Windows como estaba. Si lo instalaste,
**Ajustes → Desinstalar** (o *Agregar o quitar programas*) revierte todo: quita
las reglas, el bloqueo estricto, los accesos directos y el arranque automático.

> **Nota sobre el bloqueo estricto:** mientras esté activo, el Firewall de Windows
> bloquea por defecto toda conexión de salida. Esto es lo que hace que la pregunta
> "¿permitir?" siga funcionando tras reiniciar aunque MiniWall aún no haya
> arrancado. Si quieres volver a la conexión libre, desactívalo en Ajustes o usa
> *Quitar todas las reglas*. Se añaden reglas base para DNS, DHCP y NTP para que el
> equipo siga funcionando.

## Compilar

Requiere [Go](https://go.dev/dl/) 1.26 o superior. Se puede compilar desde
Windows, Linux o macOS (compilación cruzada, sin CGO):

```sh
# Linux / macOS
./build.sh

# Windows (PowerShell)
.\build.ps1
```

El resultado queda en `dist/MiniWall.exe`. El archivo de recursos
(`rsrc_windows_amd64.syso`: icono, manifiesto y versión) ya está generado; los
scripts lo regeneran con [go-winres](https://github.com/tc-hib/go-winres) a
partir de `winres/`.

Cada push a GitHub compila el `.exe` con GitHub Actions
(`.github/workflows/build.yml`) y, al publicar una etiqueta `v*`, lo adjunta a
una release.

### Estructura

```
main.go       ventana, bandeja del sistema, instancia única
engine.go     ciclo de monitorización, alertas, modo Preguntar, perfiles
api.go        servidor local de la interfaz y acciones
etw.go        tráfico por proceso (ETW)
procs.go      conexiones TCP/UDP, procesos e iconos
system.go     interfaces, CPU/RAM/discos, Wi‑Fi, ARP, cámara/micrófono, RDP
firewall.go   reglas del Firewall de Windows (netsh) e inicio automático
store.go      configuración e historial (portátil, con pruebas)
geoip.go      IP → país
ui/           interfaz
tools/        generadores de los datos de GeoIP, mapa e icono
```

Pruebas de la parte portátil: `go test ./...`
