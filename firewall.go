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
	_, err := runHidden("netsh " + args)
	return err
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
		_ = netsh(fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, name))
		if err := netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=%s action=block program="%s" enable=yes profile=any`, name, dir, path)); err != nil {
			return err
		}
	}
	return nil
}

func fwUnblockApp(key, path string) error {
	var last error
	for _, dir := range []string{"out", "in"} {
		name := ruleName(key, path, dir)
		if err := netsh(fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, name)); err != nil {
			last = err
		}
	}
	return last
}

// fwBlockAll cambia la directiva predeterminada de todos los perfiles.
func fwBlockAll(on bool) error {
	pol := "blockinbound,allowoutbound"
	if on {
		pol = "blockinbound,blockoutbound"
	}
	return netsh("advfirewall set allprofiles firewallpolicy " + pol)
}

func fwEnable() error { return netsh("advfirewall set allprofiles state on") }

const rdpRule = rulePrefix + "Bloquear Escritorio remoto (entrada)"

func fwBlockRDP(on bool, port int) error {
	_ = netsh(fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, rdpRule))
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
	// schtasks espera el XML en UTF-16 LE con BOM.
	u := unicode16.Encode([]rune(xml))
	b := make([]byte, 2+len(u)*2)
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u {
		b[2+i*2] = byte(c)
		b[3+i*2] = byte(c >> 8)
	}
	f := filepath.Join(dir, "autostart.xml")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	_, err = runHidden(`schtasks /create /tn "` + taskName + `" /xml "` + f + `" /f`)
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
