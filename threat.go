//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
)

// Análisis heurístico de amenazas. MiniWall NO es un antivirus con firmas, pero
// detecta señales que suelen delatar a programas maliciosos o no deseados:
//
//   - ejecutable sin firma digital válida (Authenticode),
//   - ubicado en carpetas temporales / de descargas (típico de malware),
//   - que se hace pasar por un proceso de Windows (nombre de sistema fuera de
//     System32),
//   - que abre un puerto a la escucha accesible desde la red ("servicio oculto"
//     o puerta trasera),
//   - indicios de Tor / servicios ocultos (.onion),
//   - que se conecta a muchos países distintos (posible baliza / botnet).
//
// Cada señal suma puntos; el total decide el nivel: ok / sospechoso / peligro.

const (
	riskOK     = 0
	riskWarn   = 1 // sospechoso
	riskDanger = 2 // peligro
)

// Nombres de procesos críticos de Windows: si aparecen FUERA de System32 es una
// señal clásica de suplantación (malware disfrazado).
var systemProcessNames = map[string]bool{
	"svchost.exe": true, "lsass.exe": true, "csrss.exe": true, "services.exe": true,
	"winlogon.exe": true, "wininit.exe": true, "smss.exe": true, "explorer.exe": true,
	"taskhostw.exe": true, "dllhost.exe": true, "conhost.exe": true, "spoolsv.exe": true,
	"lsm.exe": true, "fontdrvhost.exe": true, "ctfmon.exe": true, "sihost.exe": true,
}

// Puertos remotos asociados a herramientas de ataque o C2 conocidas.
var badRemotePorts = map[uint16]string{
	4444: "Metasploit", 5555: "acceso remoto", 1337: "puerta trasera", 31337: "puerta trasera",
	6667: "IRC (botnet)", 6697: "IRC (botnet)", 9001: "Tor", 9030: "Tor", 9050: "Tor", 9150: "Tor",
}

func lowerBase(path string) string { return strings.ToLower(filepath.Base(path)) }

// suspiciousLocation indica si el ejecutable está en una ubicación poco habitual
// para software legítimo instalado.
func suspiciousLocation(path string) (bool, string) {
	p := strings.ToLower(path)
	markers := []struct{ sub, why string }{
		{`\appdata\local\temp\`, "carpeta temporal"},
		{`\windows\temp\`, "carpeta temporal de Windows"},
		{`\downloads\`, "carpeta de descargas"},
		{`\$recycle.bin\`, "papelera de reciclaje"},
		{`\temp\`, "carpeta temporal"},
	}
	for _, m := range markers {
		if strings.Contains(p, m.sub) {
			return true, m.why
		}
	}
	return false, ""
}

// masquerades detecta un ejecutable con nombre de proceso del sistema situado
// fuera de las carpetas de Windows (fuerte indicio de malware).
func masquerades(path string) bool {
	base := lowerBase(path)
	if path == "" || !systemProcessNames[base] {
		return false
	}
	p := strings.ToLower(path)
	if base == "explorer.exe" {
		return !strings.HasSuffix(p, `\windows\explorer.exe`)
	}
	legit := strings.Contains(p, `\windows\system32\`) ||
		strings.Contains(p, `\windows\syswow64\`) ||
		strings.Contains(p, `\windows\winsxs\`)
	return !legit
}

// ---------------------------------------------------------------------------
// Comprobación de firma digital (Authenticode) vía PowerShell, en segundo plano.
// ---------------------------------------------------------------------------

type sigCache struct {
	mu sync.Mutex
	m  map[string]int // ruta (minúsculas) → -1 desconocido, 0 sin firma, 1 firmado
}

var signatures = &sigCache{m: map[string]int{}}

func (s *sigCache) get(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[strings.ToLower(path)]
	if !ok {
		return -1
	}
	return v
}

func (s *sigCache) set(path string, v int) {
	s.mu.Lock()
	s.m[strings.ToLower(path)] = v
	s.mu.Unlock()
}

// checkSignature consulta el estado de firma de un ejecutable. "Valid" = firmado
// y de confianza; cualquier otra cosa se considera sin firma válida.
func checkSignature(path string) int {
	if path == "" {
		return -1
	}
	ps := fmt.Sprintf(`(Get-AuthenticodeSignature -LiteralPath %s).Status`, psQuote(path))
	out, err := runHidden(`powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command ` + psQuote(ps))
	if err != nil {
		return -1
	}
	if strings.Contains(strings.TrimSpace(out), "Valid") {
		return 1
	}
	return 0
}

// sigWorker resuelve firmas pendientes sin bloquear el ciclo principal.
func (a *App) sigWorker() {
	for path := range a.sigQueue {
		st := checkSignature(path)
		signatures.set(path, st)
		a.mu.Lock()
		delete(a.sigPending, strings.ToLower(path))
		a.mu.Unlock()
	}
}

func (a *App) requestSignature(path string) {
	if path == "" || signatures.get(path) != -1 {
		return
	}
	lp := strings.ToLower(path)
	if a.sigPending[lp] {
		return
	}
	a.sigPending[lp] = true
	select {
	case a.sigQueue <- path:
	default:
		delete(a.sigPending, lp)
	}
}

// ---------------------------------------------------------------------------
// Cálculo del riesgo de una app (se llama con a.mu bloqueado).
// ---------------------------------------------------------------------------

func (a *App) computeRisk(la *liveApp) {
	score := 0
	var reasons []string
	add := func(pts int, why string) { score += pts; reasons = append(reasons, why) }

	la.Signed = -1
	if la.Path != "" {
		a.requestSignature(la.Path)
		la.Signed = signatures.get(la.Path)
	}

	sys := la.Path != "" && isSystemPath(la.Path)
	// Suplantar un proceso del sistema es, por sí solo, señal de peligro.
	if masquerades(la.Path) {
		add(4, "Se hace pasar por un proceso de Windows fuera de System32")
	}
	// Las señales débiles suman; ninguna basta por sí sola para no molestar con
	// software legítimo sin firma o que abre puertos (p. ej. juegos, Spotify).
	if la.Signed == 0 && !sys && la.Path != "" {
		add(1, "Ejecutable sin firma digital válida")
	}
	if bad, why := suspiciousLocation(la.Path); bad {
		add(2, "Se ejecuta desde una "+why)
	}
	if la.Exposed {
		add(1, fmt.Sprintf("Abre %d puerto(s) a la escucha accesibles desde la red", la.Listen))
	}
	if la.Tor {
		add(3, "Indicios de Tor / servicio oculto (.onion)")
	}
	if n := len(la.countries); n >= 8 {
		add(1, fmt.Sprintf("Se conecta a %d países distintos", n))
	}
	// Un servicio a la escucha SIN firma y fuera del sistema huele a puerta trasera.
	if la.Exposed && la.Signed == 0 && !sys {
		add(2, "Posible servicio oculto o puerta trasera (escucha sin firmar)")
	}

	lvl := riskOK
	if score >= 4 {
		lvl = riskDanger
	} else if score >= 2 {
		lvl = riskWarn
	}
	la.Risk, la.Reasons = lvl, reasons
}

// torRemote indica si una conexión remota apunta a la red Tor.
func torRemote(ap netip.AddrPort) bool {
	_, ok := map[uint16]bool{9001: true, 9030: true, 9050: true, 9150: true, 9051: true}[ap.Port()]
	return ok
}
