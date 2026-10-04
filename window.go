//go:build windows

package main

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// Icono en la bandeja del sistema, menú contextual y notificaciones discretas.
// ---------------------------------------------------------------------------

type trayMenuItem struct {
	ID      uintptr
	Label   string
	Checked bool
	Sep     bool
}

type tray struct {
	hwnd       uintptr
	nid        notifyIconData
	taskbarMsg uint32
	onOpen     func()
	onMenu     func() []trayMenuItem
	onCommand  func(id uintptr)
	mu         sync.Mutex
}

var theTray *tray

func trayWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	t := theTray
	if t != nil {
		switch {
		case msg == wmTray:
			switch lp & 0xFFFF {
			case wmLButtonUp, wmLButtonDbl:
				if t.onOpen != nil {
					t.onOpen()
				}
			case wmRButtonUp, wmContextMenu:
				t.showMenu()
			}
			return 0
		case t.taskbarMsg != 0 && uint32(msg) == t.taskbarMsg:
			// El Explorador se reinició: volver a añadir el icono.
			call(procShellNotifyIconW, nimAdd, ptr(&t.nid))
			return 0
		}
	}
	return call(procDefWindowProcW, hwnd, msg, wp, lp)
}

func newTray(tip string) *tray {
	t := &tray{}
	theTray = t
	var hinst windows.Handle
	windows.GetModuleHandleEx(0, nil, &hinst)
	cls := utf16("MiniWallTray")
	wc := wndClassEx{LpfnWndProc: newCallback(trayWndProc), HInstance: hinst, LpszClassName: cls}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	call(procRegisterClassExW, ptr(&wc))
	t.hwnd = call(procCreateWindowExW, 0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(utf16("MiniWallTray"))),
		0, 0, 0, 0, 0, 0, 0, uintptr(hinst), 0)
	t.taskbarMsg = uint32(call(procRegisterWindowMessageW, uintptr(unsafe.Pointer(utf16("TaskbarCreated")))))

	cx := call(procGetSystemMetrics, smCxSmIcon)
	cy := call(procGetSystemMetrics, smCySmIcon)
	icon := call(procLoadImageW, uintptr(hinst), 1, imageIcon, cx, cy, lrShared)
	if icon == 0 {
		icon = call(procLoadImageW, 0, 32512, imageIcon, cx, cy, lrShared) // IDI_APPLICATION
	}
	t.nid.CbSize = uint32(unsafe.Sizeof(t.nid))
	t.nid.HWnd = t.hwnd
	t.nid.UID = 1
	t.nid.UFlags = nifMessage | nifIcon | nifTip
	t.nid.UCallbackMessage = wmTray
	t.nid.HIcon = icon
	copyUTF16(t.nid.SzTip[:], tip)
	call(procShellNotifyIconW, nimAdd, ptr(&t.nid))
	return t
}

func (t *tray) SetTip(tip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nid.UFlags = nifTip
	copyUTF16(t.nid.SzTip[:], tip)
	call(procShellNotifyIconW, nimModify, ptr(&t.nid))
}

// Notify muestra una notificación del sistema (globo / notificación de Windows).
func (t *tray) Notify(title, text, level string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.nid
	n.UFlags = nifInfo
	copyUTF16(n.SzInfoTitle[:], title)
	copyUTF16(n.SzInfo[:], text)
	switch level {
	case "danger":
		n.DwInfoFlags = niifError
	case "warn":
		n.DwInfoFlags = niifWarning
	default:
		n.DwInfoFlags = niifInfo | niifNoSound
	}
	call(procShellNotifyIconW, nimModify, ptr(&n))
}

func (t *tray) Remove() {
	call(procShellNotifyIconW, nimDelete, ptr(&t.nid))
}

func (t *tray) showMenu() {
	if t.onMenu == nil {
		return
	}
	items := t.onMenu()
	m := call(procCreatePopupMenu)
	for _, it := range items {
		if it.Sep {
			call(procAppendMenuW, m, mfSeparator, 0, 0)
			continue
		}
		flags := uintptr(mfString)
		if it.Checked {
			flags |= mfChecked
		}
		call(procAppendMenuW, m, flags, it.ID, uintptr(unsafe.Pointer(utf16(it.Label))))
	}
	var p point
	call(procGetCursorPos, ptr(&p))
	call(procSetForegroundWindow, t.hwnd)
	id := call(procTrackPopupMenu, m, tpmReturnCmd|tpmNoNotify|tpmRightButton|tpmBottomAlign, uintptr(p.X), uintptr(p.Y), 0, t.hwnd, 0)
	call(procPostMessageW, t.hwnd, wmNull, 0, 0)
	call(procDestroyMenu, m)
	if id != 0 && t.onCommand != nil {
		t.onCommand(id)
	}
}

// ---------------------------------------------------------------------------
// Ventana principal: ocultar en lugar de cerrar y modo minigráfico.
// ---------------------------------------------------------------------------

type mainWindow struct {
	hwnd         uintptr
	oldProc      uintptr
	quitting     bool
	mini         bool
	normal       rect
	closeHide    func() bool
	dispatch     func(func())
	onHidden     func()
	onEndSession func()
}

var theWindow *mainWindow

func subclassProc(hwnd, msg, wp, lp uintptr) uintptr {
	w := theWindow
	if w != nil && msg == wmEndSession && wp != 0 && w.onEndSession != nil {
		w.onEndSession()
	}
	if w != nil && msg == wmClose && !w.quitting && w.closeHide != nil && w.closeHide() {
		call(procShowWindow, hwnd, swHide)
		if w.onHidden != nil {
			w.onHidden()
		}
		return 0
	}
	return call(procCallWindowProcW, w.oldProc, hwnd, msg, wp, lp)
}

func attachWindow(hwnd uintptr) *mainWindow {
	w := &mainWindow{hwnd: hwnd}
	theWindow = w
	w.oldProc = call(procSetWindowLongPtrW, hwnd, gwlpWndProc, newCallback(subclassProc))
	return w
}

func (w *mainWindow) Show() {
	w.run(func() {
		if call(procIsIconic, w.hwnd) != 0 {
			call(procShowWindow, w.hwnd, swRestore)
		} else {
			call(procShowWindow, w.hwnd, swShow)
		}
		call(procSetForegroundWindow, w.hwnd)
	})
}

func (w *mainWindow) Hide() {
	w.run(func() { call(procShowWindow, w.hwnd, swHide) })
}

func (w *mainWindow) Visible() bool { return call(procIsWindowVisible, w.hwnd) != 0 }

func (w *mainWindow) run(f func()) {
	if w.dispatch != nil {
		w.dispatch(f)
	} else {
		f()
	}
}

// Mini alterna entre la ventana normal y un minigráfico siempre visible
// en la esquina inferior derecha.
func (w *mainWindow) Mini(on bool) {
	w.run(func() {
		if on == w.mini {
			return
		}
		if on {
			call(procGetWindowRect, w.hwnd, ptr(&w.normal))
			var wa rect
			call(procSystemParametersInfoW, spiGetWorkArea, 0, ptr(&wa), 0)
			s := float64(windowDPI(w.hwnd)) / 96
			mw, mh := int32(300*s), int32(150*s)
			call(procSetWindowPos, w.hwnd, hwndTopmost, uintptr(wa.Right-mw-int32(12*s)), uintptr(wa.Bottom-mh-int32(12*s)),
				uintptr(mw), uintptr(mh), swpShowWindow)
		} else {
			r := w.normal
			call(procSetWindowPos, w.hwnd, hwndNoTopmost, uintptr(r.Left), uintptr(r.Top),
				uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpShowWindow)
		}
		w.mini = on
		call(procShowWindow, w.hwnd, swShow)
	})
}
