//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Instalación de MiniWall en el equipo: copia el ejecutable a Archivos de
// programa, crea accesos directos, lo registra en «Agregar o quitar programas»
// y lo configura para arrancar con Windows. Todo es reversible desde la propia
// app (Ajustes → Desinstalar) o desde Configuración de Windows.

const uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\MiniWall`

func installDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "MiniWall")
}

func installedExe() string { return filepath.Join(installDir(), "MiniWall.exe") }

// isInstalledCopy indica si este proceso se está ejecutando desde la carpeta de
// instalación (y no desde la descarga).
func isInstalledCopy() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return strings.EqualFold(exe, installedExe())
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

// installApp copia el ejecutable y deja MiniWall instalado y en marcha.
func installApp(a *App) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := installDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("no se pudo crear %s: %w", dir, err)
	}
	dst := installedExe()
	if !strings.EqualFold(exe, dst) {
		if err := copyFile(exe, dst); err != nil {
			return fmt.Errorf("no se pudo copiar el programa: %w", err)
		}
	}

	// Accesos directos en el menú Inicio y el escritorio.
	createShortcut(filepath.Join(programsDir(), "MiniWall.lnk"), dst, "")
	if d := desktopDir(); d != "" {
		createShortcut(filepath.Join(d, "MiniWall.lnk"), dst, "")
	}

	registerUninstall(dst)
	if err := setAutostartExe(true, dst, a.dir); err != nil {
		return fmt.Errorf("no se pudo configurar el arranque con Windows: %w", err)
	}

	if a != nil {
		a.mu.Lock()
		a.cfg.Installed = true
		a.cfg.Autostart = true
		a.cfgDirty = true
		a.mu.Unlock()
		a.saveConfig()
	}
	return nil
}

// uninstallApp revierte la instalación: quita reglas, accesos directos, arranque
// y el registro, y programa el borrado de la carpeta de instalación.
func uninstallApp(a *App) {
	if a != nil {
		a.ClearAll()
		if a.cfg.StrictBlock {
			fwStrictOutbound(false)
		}
	}
	setAutostart(false, "")
	os.Remove(filepath.Join(programsDir(), "MiniWall.lnk"))
	if d := desktopDir(); d != "" {
		os.Remove(filepath.Join(d, "MiniWall.lnk"))
	}
	registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey)
	// La carpeta no puede borrarse mientras el .exe está en uso: se borra al salir.
	scheduleSelfDelete()
}

func programsDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	d := filepath.Join(base, `Microsoft\Windows\Start Menu\Programs`)
	return d
}

func desktopDir() string {
	if p := os.Getenv("PUBLIC"); p != "" {
		return filepath.Join(p, "Desktop")
	}
	if u := os.Getenv("USERPROFILE"); u != "" {
		return filepath.Join(u, "Desktop")
	}
	return ""
}

// createShortcut crea un .lnk con WScript.Shell (sin añadir dependencias COM).
func createShortcut(lnk, target, args string) {
	ps := fmt.Sprintf(`$s=(New-Object -ComObject WScript.Shell).CreateShortcut(%q);$s.TargetPath=%q;$s.Arguments=%q;$s.WorkingDirectory=%q;$s.IconLocation=%q;$s.Description='MiniWall - firewall y monitor de red';$s.Save()`,
		lnk, target, args, filepath.Dir(target), target)
	runHidden(`powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command ` + psQuote(ps))
}

func psQuote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

func registerUninstall(exe string) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	k.SetStringValue("DisplayName", "MiniWall — firewall y monitor de red")
	k.SetStringValue("DisplayVersion", version)
	k.SetStringValue("Publisher", "MiniWall")
	k.SetStringValue("DisplayIcon", exe)
	k.SetStringValue("InstallLocation", filepath.Dir(exe))
	k.SetStringValue("UninstallString", fmt.Sprintf(`"%s" --uninstall`, exe))
	k.SetDWordValue("NoModify", 1)
	k.SetDWordValue("NoRepair", 1)
	k.SetDWordValue("EstimatedSize", 10240)
}

// setAutostartExe configura el arranque con Windows apuntando a un ejecutable
// concreto (el instalado), con privilegios de administrador.
func setAutostartExe(on bool, exe, dataDir string) error {
	if !on {
		return setAutostart(false, "")
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
	return writeTaskXML(xml, dataDir)
}

// scheduleSelfDelete borra la carpeta de instalación tras cerrarse el proceso.
func scheduleSelfDelete() {
	dir := installDir()
	// cmd espera unos segundos y borra la carpeta cuando el .exe ya no está en uso.
	line := fmt.Sprintf(`cmd.exe /c ping 127.0.0.1 -n 4 >nul & rmdir /s /q "%s"`, dir)
	_ = cmdHidden("cmd.exe", line).Start()
}

func elevatedRelaunch(exe, args string) bool {
	err := windows.ShellExecute(0, utf16("runas"), utf16(exe), utf16(args), nil, windows.SW_SHOWNORMAL)
	return err == nil
}

// uninstallCLI realiza la desinstalación desde «Agregar o quitar programas»
// (proceso independiente, sin la app en marcha): borra de forma síncrona todas
// las reglas de MiniWall y revierte la instalación.
func uninstallCLI() {
	cfg := defaultConfig()
	_ = readJSON(filepath.Join(dataDir(), "config.json"), cfg)
	cfg.normalize()

	// Reúne clave→ruta de todas las reglas que MiniWall pudo crear.
	paths := map[string]string{}
	add := func(k, p string) {
		if p == "" {
			if r := cfg.Apps[k]; r != nil {
				p = r.Path
			}
		}
		paths[k] = p
	}
	for k, p := range cfg.Applied {
		add(k, p)
	}
	for _, pr := range cfg.Profiles {
		for _, k := range pr.Blocked {
			add(k, "")
		}
	}
	for k := range cfg.Pending {
		add(k, "")
	}
	for k, p := range paths {
		fwUnblockApp(k, p)
	}
	for k, p := range cfg.Allowed {
		fwUnallowApp(k, p)
	}
	if cfg.Mode == "bloquear" {
		fwBlockAll(false)
	}
	if cfg.StrictBlock {
		fwStrictOutbound(false)
	}
	fwBlockRDP(false, readRDP().Port)

	setAutostart(false, "")
	os.Remove(filepath.Join(programsDir(), "MiniWall.lnk"))
	if d := desktopDir(); d != "" {
		os.Remove(filepath.Join(d, "MiniWall.lnk"))
	}
	registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey)
	scheduleSelfDelete()
}
