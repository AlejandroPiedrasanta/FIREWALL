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
