//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modShell32  = windows.NewLazySystemDLL("shell32.dll")
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modGdi32    = windows.NewLazySystemDLL("gdi32.dll")

	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
	procGetIfTable2         = modIphlpapi.NewProc("GetIfTable2")
	procFreeMibTable        = modIphlpapi.NewProc("FreeMibTable")
	procGetIpNetTable       = modIphlpapi.NewProc("GetIpNetTable")

	procGetSystemTimes       = modKernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = modKernel32.NewProc("GetTickCount64")

	procRegisterClassExW         = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW          = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW           = modUser32.NewProc("DefWindowProcW")
	procCallWindowProcW          = modUser32.NewProc("CallWindowProcW")
	procSetWindowLongPtrW        = modUser32.NewProc("SetWindowLongPtrW")
	procShowWindow               = modUser32.NewProc("ShowWindow")
	procSetForegroundWindow      = modUser32.NewProc("SetForegroundWindow")
	procFindWindowW              = modUser32.NewProc("FindWindowW")
	procIsWindowVisible          = modUser32.NewProc("IsWindowVisible")
	procIsIconic                 = modUser32.NewProc("IsIconic")
	procSetWindowPos             = modUser32.NewProc("SetWindowPos")
	procGetWindowRect            = modUser32.NewProc("GetWindowRect")
	procSystemParametersInfoW    = modUser32.NewProc("SystemParametersInfoW")
	procCreatePopupMenu          = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW              = modUser32.NewProc("AppendMenuW")
	procTrackPopupMenu           = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu              = modUser32.NewProc("DestroyMenu")
	procGetCursorPos             = modUser32.NewProc("GetCursorPos")
	procPostMessageW             = modUser32.NewProc("PostMessageW")
	procLoadImageW               = modUser32.NewProc("LoadImageW")
	procGetSystemMetrics         = modUser32.NewProc("GetSystemMetrics")
	procRegisterWindowMessageW   = modUser32.NewProc("RegisterWindowMessageW")
	procGetDpiForSystem          = modUser32.NewProc("GetDpiForSystem")
	procGetDpiForWindow          = modUser32.NewProc("GetDpiForWindow")
	procDestroyIcon              = modUser32.NewProc("DestroyIcon")
	procGetIconInfo              = modUser32.NewProc("GetIconInfo")
	procGetDC                    = modUser32.NewProc("GetDC")
	procReleaseDC                = modUser32.NewProc("ReleaseDC")
	procShellNotifyIconW         = modShell32.NewProc("Shell_NotifyIconW")
	procExtractIconExW           = modShell32.NewProc("ExtractIconExW")
	procGetDIBits                = modGdi32.NewProc("GetDIBits")
	procGetObjectW               = modGdi32.NewProc("GetObjectW")
	procDeleteObject             = modGdi32.NewProc("DeleteObject")
	procStartTraceW              = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW            = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2           = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW               = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace             = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace               = modAdvapi32.NewProc("CloseTrace")
	procGetWindowThreadProcessId = modUser32.NewProc("GetWindowThreadProcessId")
)

const (
	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1

	errInsufficientBuffer = 122

	wmClose       = 0x0010
	wmEndSession  = 0x0016
	wmNull        = 0x0000
	wmCommand     = 0x0111
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B
	wmApp         = 0x8000
	wmTray        = wmApp + 42

	swHide    = 0
	swShow    = 5
	swRestore = 9

	gwlpWndProc = ^uintptr(3) // -4

	swpNoSize     = 0x0001
	swpNoMove     = 0x0002
	swpNoActivate = 0x0010
	swpShowWindow = 0x0040

	spiGetWorkArea = 0x0030

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfChecked   = 0x0008
	mfGrayed    = 0x0001

	tpmReturnCmd   = 0x0100
	tpmNoNotify    = 0x0080
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nifInfo    = 0x10

	niifInfo    = 0x01
	niifWarning = 0x02
	niifError   = 0x03
	niifNoSound = 0x10

	imageIcon     = 1
	lrDefaultSize = 0x0040
	lrShared      = 0x8000

	smCxSmIcon = 49
	smCySmIcon = 50
)

var hwndTopmost = ^uintptr(0)   // -1
var hwndNoTopmost = ^uintptr(1) // -2

type rect struct{ Left, Top, Right, Bottom int32 }
type point struct{ X, Y int32 }

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// Comprobación en compilación de que las estructuras coinciden con Windows x64.
var _ = [1]struct{}{}[unsafe.Sizeof(notifyIconData{})-976]
var _ = [1]struct{}{}[unsafe.Sizeof(wndClassEx{})-80]
var _ = [1]struct{}{}[unsafe.Sizeof(memoryStatusEx{})-64]
var _ = [1]struct{}{}[unsafe.Sizeof(windows.MibIfRow2{})-1352]

func call(p *windows.LazyProc, args ...uintptr) uintptr {
	r, _, _ := p.Call(args...)
	return r
}

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func tickCount64() uint64 {
	if procGetTickCount64.Find() != nil {
		return 0
	}
	return uint64(call(procGetTickCount64))
}

// systemDPI devuelve el DPI del sistema (96 = 100 %).
func systemDPI() int {
	if procGetDpiForSystem.Find() == nil {
		if d := call(procGetDpiForSystem); d > 0 {
			return int(d)
		}
	}
	return 96
}

func windowDPI(hwnd uintptr) int {
	if procGetDpiForWindow.Find() == nil {
		if d := call(procGetDpiForWindow, hwnd); d > 0 {
			return int(d)
		}
	}
	return systemDPI()
}

// enableDebugPrivilege activa SeDebugPrivilege para que MiniWall pueda leer la
// ruta e información de cualquier proceso (incluidos los de otros usuarios y del
// sistema), dándole visibilidad total de lo que usa la red.
func enableDebugPrivilege() {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return
	}
	defer tok.Close()
	var luid windows.LUID
	if windows.LookupPrivilegeValue(nil, utf16("SeDebugPrivilege"), &luid) != nil {
		return
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

func newCallback(fn any) uintptr { return syscall.NewCallback(fn) }

func ptr[T any](v *T) uintptr { return uintptr(unsafe.Pointer(v)) }
