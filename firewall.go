//go:build windows

package main

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	unicode16 "unicode/utf16"
)

// Control del Firewall de Windows mediante netsh. MiniWall solo crea, y solo
// borra, reglas con el prefijo "MiniWall - ".

const rulePrefix = "MiniWall - "

func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 32 {
			return -1
		}
		return r
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func ruleName(key, path, dir string) string {
	h := fnv.New32a()
	h.Write([]byte(key))
	base := cleanName(filepath.Base(path))
	return fmt.Sprintf("%s%s [%08x] (%s)", rulePrefix, base, h.Sum32(), dir)
}

func netsh(args string) error {
	out, err := runHidden("netsh " + args)
	if err == nil {
		return nil
	}
	// Reintento único por si fue un fallo transitorio del servicio de firewall.
	out2, err2 := runHidden("netsh " + args)
	if err2 == nil {
		return nil
	}
	_ = out
	return fmt.Errorf("%s", strings.TrimSpace(out2))
}

// netshDelete borra una regla ignorando el caso "no existe" (no es un error real).
func netshDelete(name string) {
	out, _ := runHidden(fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, name))
	_ = out // borrar algo inexistente no es un error que debamos propagar
}

func validProgram(path string) bool {
	if path == "" || strings.ContainsAny(path, "\"\r\n") || !filepath.IsAbs(path) {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// fwBlockApp crea reglas de bloqueo de entrada y salida para el ejecutable.
func fwBlockApp(key, path string) error {
	if !validProgram(path) {
		return fmt.Errorf("ruta no válida: %s", path)
	}
	for _, dir := range []string{"out", "in"} {
		name := ruleName(key, path, dir)
		netshDelete(name)
		if err := netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=%s action=block program="%s" enable=yes profile=any`, name, dir, path)); err != nil {
			return err
		}
	}
	return nil
}

func fwUnblockApp(key, path string) error {
	for _, dir := range []string{"out", "in"} {
		netshDelete(ruleName(key, path, dir))
	}
	return nil
}

// allowRuleName identifica una regla de PERMISO (modo estricto).
func allowRuleName(key, path, dir string) string {
	h := fnv.New32a()
	h.Write([]byte(key))
	base := cleanName(filepath.Base(path))
	return fmt.Sprintf("%sPermitir %s [%08x] (%s)", rulePrefix, base, h.Sum32(), dir)
}

// fwAllowApp crea reglas de permiso explícito para una app. Son necesarias en
// modo estricto (bloqueo de salida por defecto) para que la app siga conectando.
func fwAllowApp(key, path string) error {
	if !validProgram(path) {
		return fmt.Errorf("ruta no válida: %s", path)
	}
	for _, dir := range []string{"out", "in"} {
		name := allowRuleName(key, path, dir)
		netshDelete(name)
		if err := netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=%s action=allow program="%s" enable=yes profile=any`, name, dir, path)); err != nil {
			return err
		}
	}
	return nil
}

func fwUnallowApp(key, path string) error {
	for _, dir := range []string{"out", "in"} {
		netshDelete(allowRuleName(key, path, dir))
	}
	return nil
}

// fwBlockAll cambia la directiva predeterminada de todos los perfiles.
func fwBlockAll(on bool) error {
	pol := "blockinbound,allowoutbound"
	if on {
		pol = "blockinbound,blockoutbound"
	}
	return netsh("advfirewall set allprofiles firewallpolicy " + pol)
}

// fwStrictOutbound activa/desactiva el bloqueo de salida POR DEFECTO. A
// diferencia del modo "Bloquear todo", esta directiva permanece en el Firewall
// de Windows tras reiniciar y aunque MiniWall no se esté ejecutando: cualquier
// programa sin una regla de permiso explícita queda bloqueado al salir. Es la
// base del modo "Preguntar" persistente (pide permiso antes de dejar conectar).
func fwStrictOutbound(on bool) error {
	pol := "blockinbound,allowoutbound"
	if on {
		pol = "blockinbound,blockoutbound"
	}
	if err := netsh("advfirewall set allprofiles firewallpolicy " + pol); err != nil {
		return err
	}
	return fwBaseline(on)
}

const baselineTag = rulePrefix + "Base: "

// fwBaseline crea (o elimina) reglas de permiso imprescindibles para que el
// equipo siga funcionando con el bloqueo de salida por defecto: DNS, DHCP, NTP
// y el propio MiniWall. Sin ellas, Windows se quedaría sin resolución de
// nombres y la red dejaría de funcionar por completo.
func fwBaseline(on bool) error {
	rules := []struct{ name, args string }{
		{"DNS UDP", `dir=out action=allow protocol=UDP remoteport=53`},
		{"DNS TCP", `dir=out action=allow protocol=TCP remoteport=53`},
		{"DHCP", `dir=out action=allow protocol=UDP remoteport=67,68`},
		{"NTP", `dir=out action=allow protocol=UDP remoteport=123`},
	}
	for _, r := range rules {
		full := baselineTag + r.name
		netshDelete(full)
		if on {
			if err := netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" %s enable=yes profile=any`, full, r.args)); err != nil {
				return err
			}
		}
	}
	// MiniWall siempre puede conectar (resolución inversa de nombres).
	self := baselineTag + "MiniWall"
	netshDelete(self)
	if on {
		if exe, err := os.Executable(); err == nil {
			_ = netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=out action=allow program="%s" enable=yes profile=any`, self, exe))
		}
	}
	return nil
}

func fwEnable() error { return netsh("advfirewall set allprofiles state on") }

// fwIsOn indica si el Firewall de Windows está activo en todos los perfiles.
func fwIsOn() bool {
	out, err := runHidden("netsh advfirewall show allprofiles state")
	if err != nil {
		return true
	}
	low := strings.ToLower(out)
	// "OFF"/"Desactivado" aparece cuando algún perfil está apagado.
	return !strings.Contains(low, "off") && !strings.Contains(low, "desactiv")
}

const rdpRule = rulePrefix + "Bloquear Escritorio remoto (entrada)"

func fwBlockRDP(on bool, port int) error {
	netshDelete(rdpRule)
	if !on {
		return nil
	}
	return netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=block protocol=TCP localport=%d enable=yes profile=any`, rdpRule, port))
}

// ---------------------------------------------------------------------------
// Inicio automático con Windows (tarea programada con privilegios elevados,
// necesaria porque MiniWall requiere permisos de administrador).
// ---------------------------------------------------------------------------

const taskName = "MiniWall"

func setAutostart(on bool, dir string) error {
	if !on {
		_, err := runHidden(`schtasks /delete /tn "` + taskName + `" /f`)
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Inicia MiniWall al iniciar sesión</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEscape(exe) + `</Command><Arguments>--minimized</Arguments></Exec></Actions>
</Task>`
	return writeTaskXML(xml, dir)
}

// writeTaskXML registra la tarea programada a partir de un XML (UTF-16 LE con
// BOM, como exige schtasks).
func writeTaskXML(xml, dir string) error {
	u := unicode16.Encode([]rune(xml))
	b := make([]byte, 2+len(u)*2)
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u {
		b[2+i*2] = byte(c)
		b[3+i*2] = byte(c >> 8)
	}
	if dir == "" {
		dir = os.TempDir()
	}
	f := filepath.Join(dir, "autostart.xml")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	_, err := runHidden(`schtasks /create /tn "` + taskName + `" /xml "` + f + `" /f`)
	return err
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func isSystemPath(path string) bool {
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(win)+`\`)
}
