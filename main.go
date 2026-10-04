//go:build windows

// MiniWall: firewall y monitor de red minimalista para Windows.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const appTitle = "MiniWall"

var version = "1.0.0"

func osHostname() (string, error) { return os.Hostname() }

func init() { runtime.LockOSThread() }

func main() {
	minimized := false
	for _, a := range os.Args[1:] {
		switch a {
		case "--minimized", "/minimized":
			minimized = true
		case "--uninstall", "/uninstall":
			if !windows.GetCurrentProcessToken().IsElevated() {
				relaunchElevated()
				return
			}
			uninstallCLI()
			return
		case "--install", "/install":
			if !windows.GetCurrentProcessToken().IsElevated() {
				relaunchElevated()
				return
			}
			if err := installApp(nil); err == nil {
				elevatedRelaunch(installedExe(), "")
			}
			return
		}
	}

	// Una sola instancia: si ya está abierta, se muestra la existente.
	mutexName := utf16("Local\\MiniWall-SingleInstance")
	h, err := windows.CreateMutex(nil, false, mutexName)
	if err == windows.ERROR_ALREADY_EXISTS {
		if hw := call(procFindWindowW, uintptr(unsafe.Pointer(utf16("webview"))), uintptr(unsafe.Pointer(utf16(appTitle)))); hw != 0 {
			call(procShowWindow, hw, swRestore)
			call(procShowWindow, hw, swShow)
			call(procSetForegroundWindow, hw)
		}
		return
	}
	defer windows.CloseHandle(h)

	// Se necesitan permisos de administrador para el firewall y el monitor ETW.
	if !windows.GetCurrentProcessToken().IsElevated() {
		if relaunchElevated() {
			return
		}
	}
	// Máximo poder de inspección: permite leer la ruta de cualquier proceso.
	enableDebugPrivilege()

	dir := dataDir()
	if f, err := os.OpenFile(filepath.Join(dir, "miniwall.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		log.SetOutput(f)
		defer f.Close()
	}
	log.Printf("MiniWall %s iniciado", version)

	app := NewApp(dir)
	app.Start()

	win := &lateWindow{}
	srv, err := startServer(app, win)
	if err != nil {
		fatal("No se pudo iniciar la interfaz: " + err.Error())
	}

	s := float64(systemDPI()) / 96
	newWV := func() webview2.WebView {
		return webview2.NewWithOptions(webview2.WebViewOptions{
			DataPath:  filepath.Join(dir, "WebView2"),
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  appTitle,
				Width:  uint(1240 * s),
				Height: uint(800 * s),
				IconId: 1,
				Center: true,
			},
		})
	}
	wv := newWV()
	if wv == nil && !hasWebView2() {
		// Falta el runtime WebView2: se instala y se reintenta.
		if ensureWebView2() == nil {
			wv = newWV()
		}
	}
	if wv == nil {
		// Sin WebView2: abrir la interfaz en el navegador y seguir en la bandeja.
		if hw := call(procFindWindowW, uintptr(unsafe.Pointer(utf16("webview"))), uintptr(unsafe.Pointer(utf16(appTitle)))); hw != 0 {
			call(procShowWindow, hw, swHide)
		}
		windows.ShellExecute(0, utf16("open"), utf16(srv.URL()), nil, nil, windows.SW_SHOWNORMAL)
		runTrayOnly(app, srv)
		return
	}

	mw := attachWindow(uintptr(wv.Window()))
	mw.dispatch = wv.Dispatch
	win.w = mw
	hintShown := false
	mw.closeHide = func() bool {
		app.mu.Lock()
		defer app.mu.Unlock()
		return app.cfg.CloseToTray
	}

	t := newTray(appTitle + " — firewall y monitor de red")
	app.notify = func(title, text, level string) { t.Notify(title, text, level) }
	mw.onHidden = func() {
		if !hintShown {
			hintShown = true
			t.Notify(appTitle+" sigue activo", "Sigue protegiendo desde la bandeja del sistema. Haz clic en el icono para abrirlo.", "info")
		}
	}
	quit := func() {
		mw.quitting = true
		wv.Terminate()
	}
	win.quitFn = quit
	mw.onEndSession = func() { app.Stop() }
	// Cuando un programa pide permiso, trae la ventana al frente para mostrar el
	// pop-up de permitir/bloquear (en lugar de una notificación de Windows).
	app.onAsk = func() { mw.Show() }
	setupTrayMenu(t, app, mw, quit)
	go trayTipLoop(app, t)

	wv.Navigate(srv.URL())
	if minimized {
		call(procShowWindow, uintptr(wv.Window()), swHide)
	}
	wv.Run()

	t.Remove()
	app.Stop()
	log.Print("MiniWall cerrado")
}

// lateWindow permite crear el servidor antes que la ventana.
type lateWindow struct {
	w      *mainWindow
	quitFn func()
}

func (l *lateWindow) Mini(on bool) {
	if l.w != nil {
		l.w.Mini(on)
	}
}

func (l *lateWindow) Hide() {
	if l.w != nil {
		l.w.Hide()
	}
}

func (l *lateWindow) Quit() {
	if l.quitFn != nil {
		l.quitFn()
	}
}

const (
	cmdOpen = iota + 1
	cmdMini
	cmdMonitor
	cmdAsk
	cmdBlockAll
	cmdStrict
	cmdSimple
	cmdInstall
	cmdSnooze
	cmdQuit
	cmdProfileBase = 100
)

func setupTrayMenu(t *tray, app *App, mw *mainWindow, quit func()) {
	t.onOpen = func() {
		if mw.mini {
			mw.Mini(false)
		}
		mw.Show()
	}
	t.onMenu = func() []trayMenuItem {
		app.mu.Lock()
		mode := app.cfg.Mode
		snoozed := app.cfg.Notify.SnoozeUntil > time.Now().Unix()
		cur := app.cfg.Profile
		strict := app.cfg.StrictBlock
		simple := app.cfg.Simple
		installed := app.cfg.Installed
		var profiles []string
		for _, p := range app.cfg.Profiles {
			profiles = append(profiles, p.Name)
		}
		app.mu.Unlock()
		items := []trayMenuItem{
			{ID: cmdOpen, Label: "Abrir MiniWall"},
			{ID: cmdMini, Label: "Minigráfico", Checked: mw.mini},
			{Sep: true},
			{ID: cmdMonitor, Label: "Modo: Monitorizar", Checked: mode == "monitor"},
			{ID: cmdAsk, Label: "Modo: Preguntar antes de conectar", Checked: mode == "preguntar"},
			{ID: cmdBlockAll, Label: "Modo: Bloquear todo", Checked: mode == "bloquear"},
			{ID: cmdStrict, Label: "Bloqueo estricto (pide permiso siempre)", Checked: strict},
			{ID: cmdSimple, Label: "Modo simple (solo Firewall y Amenazas)", Checked: simple},
			{Sep: true},
		}
		for i, p := range profiles {
			items = append(items, trayMenuItem{ID: uintptr(cmdProfileBase + i), Label: "Perfil: " + p, Checked: p == cur})
		}
		items = append(items, trayMenuItem{Sep: true})
		if !installed {
			items = append(items, trayMenuItem{ID: cmdInstall, Label: "Instalar MiniWall en el equipo"})
		}
		items = append(items,
			trayMenuItem{ID: cmdSnooze, Label: "Silenciar alertas 1 hora", Checked: snoozed},
			trayMenuItem{ID: cmdQuit, Label: "Salir"},
		)
		return items
	}
	t.onCommand = func(id uintptr) {
		switch {
		case id == cmdOpen:
			t.onOpen()
		case id == cmdMini:
			mw.Mini(!mw.mini)
			mw.Show()
		case id == cmdMonitor:
			app.SetMode("monitor")
		case id == cmdAsk:
			app.SetMode("preguntar")
		case id == cmdBlockAll:
			app.SetMode("bloquear")
		case id == cmdStrict:
			app.mu.Lock()
			ns := !app.cfg.StrictBlock
			app.mu.Unlock()
			b, _ := json.Marshal(map[string]any{"strictBlock": ns})
			app.UpdateConfig(b)
			if ns {
				t.Notify("Bloqueo estricto activado", "Los programas nuevos quedan bloqueados hasta que los autorices, incluso tras reiniciar.", "info")
			}
		case id == cmdSimple:
			app.mu.Lock()
			ns := !app.cfg.Simple
			app.mu.Unlock()
			b, _ := json.Marshal(map[string]any{"simple": ns})
			app.UpdateConfig(b)
			t.onOpen()
		case id == cmdInstall:
			if err := installApp(app); err != nil {
				t.Notify("No se pudo instalar", err.Error(), "danger")
			} else {
				t.Notify("MiniWall instalado", "Ya está instalado y arrancará con Windows.", "info")
			}
		case id == cmdSnooze:
			app.mu.Lock()
			if app.cfg.Notify.SnoozeUntil > time.Now().Unix() {
				app.cfg.Notify.SnoozeUntil = 0
			} else {
				app.cfg.Notify.SnoozeUntil = time.Now().Add(time.Hour).Unix()
			}
			app.cfgDirty = true
			app.mu.Unlock()
		case id == cmdQuit:
			quit()
		case id >= cmdProfileBase:
			app.mu.Lock()
			i := int(id - cmdProfileBase)
			name := ""
			if i < len(app.cfg.Profiles) {
				name = app.cfg.Profiles[i].Name
			}
			app.mu.Unlock()
			if name != "" {
				app.ProfileAction("switch", name, "")
			}
		}
	}
}

// trayTipLoop muestra la velocidad actual al pasar el ratón por el icono.
func trayTipLoop(app *App, t *tray) {
	for range time.Tick(2 * time.Second) {
		app.mu.Lock()
		var rx, tx int64
		if n := len(app.secs); n > 0 {
			rx, tx = app.secs[n-1].Rx, app.secs[n-1].Tx
		}
		mode := map[string]string{"monitor": "Monitorizando", "preguntar": "Preguntar antes de conectar", "bloquear": "BLOQUEANDO TODO"}[app.cfg.Mode]
		app.mu.Unlock()
		t.SetTip(fmt.Sprintf("%s — %s\n↓ %s/s  ↑ %s/s", appTitle, mode, human(uint64(rx)), human(uint64(tx))))
	}
}

func human(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// runTrayOnly mantiene MiniWall en la bandeja cuando no hay WebView2.
func runTrayOnly(app *App, srv *server) {
	t := newTray(appTitle)
	app.notify = func(title, text, level string) { t.Notify(title, text, level) }
	quit := false
	t.onOpen = func() {
		windows.ShellExecute(0, utf16("open"), utf16(srv.URL()), nil, nil, windows.SW_SHOWNORMAL)
	}
	t.onMenu = func() []trayMenuItem {
		return []trayMenuItem{{ID: cmdOpen, Label: "Abrir MiniWall en el navegador"}, {Sep: true}, {ID: cmdQuit, Label: "Salir"}}
	}
	t.onCommand = func(id uintptr) {
		if id == cmdOpen {
			t.onOpen()
		} else if id == cmdQuit {
			quit = true
			call(modUser32.NewProc("PostQuitMessage"), 0)
		}
	}
	t.Notify(appTitle, "No se encontró Microsoft Edge WebView2; la interfaz se abrió en tu navegador.", "info")
	var msg struct {
		Hwnd    uintptr
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      point
	}
	getMsg := modUser32.NewProc("GetMessageW")
	translate := modUser32.NewProc("TranslateMessage")
	dispatch := modUser32.NewProc("DispatchMessageW")
	for !quit {
		r := call(getMsg, ptr(&msg), 0, 0, 0)
		if r == 0 || int32(r) == -1 {
			break
		}
		call(translate, ptr(&msg))
		call(dispatch, ptr(&msg))
	}
	t.Remove()
	app.Stop()
}

func relaunchElevated() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	args := strings.Join(os.Args[1:], " ")
	err = windows.ShellExecute(0, utf16("runas"), utf16(exe), utf16(args), nil, windows.SW_SHOWNORMAL)
	return err == nil
}

func fatal(msg string) {
	log.Print(msg)
	windows.MessageBox(0, utf16(msg), utf16(appTitle), windows.MB_ICONERROR)
	os.Exit(1)
}
