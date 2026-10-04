//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// Procesos: PID → ejecutable, nombre descriptivo e icono.
// ---------------------------------------------------------------------------

type procInfo struct {
	Path    string // ruta completa ("" si no se pudo leer)
	Key     string // identificador de app: ruta en minúsculas o nombre especial
	Name    string // nombre para mostrar
	created int64
	checked time.Time
}

type procCache struct {
	mu    sync.Mutex
	byPID map[uint32]*procInfo
	names map[string]string // ruta → descripción del archivo
}

func newProcCache() *procCache {
	return &procCache{byPID: map[uint32]*procInfo{}, names: map[string]string{}}
}

func processCreated(h windows.Handle) int64 {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0
	}
	return c.Nanoseconds()
}

// Get devuelve la info del proceso, revalidando si el PID se reutilizó.
func (pc *procCache) Get(pid uint32) *procInfo {
	switch pid {
	case 0:
		return &procInfo{Key: "system:idle", Name: "Inactividad del sistema"}
	case 4:
		return &procInfo{Key: "system", Name: "Sistema (núcleo de Windows)"}
	}
	pc.mu.Lock()
	pi := pc.byPID[pid]
	pc.mu.Unlock()
	if pi != nil && time.Since(pi.checked) < 20*time.Second {
		return pi
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		if pi != nil {
			return pi // probablemente terminó; conservar el último dato
		}
		pi = &procInfo{Key: fmt.Sprintf("pid:%d", pid), Name: fmt.Sprintf("Proceso %d", pid), checked: time.Now()}
		pc.mu.Lock()
		pc.byPID[pid] = pi
		pc.mu.Unlock()
		return pi
	}
	defer windows.CloseHandle(h)
	created := processCreated(h)
	if pi != nil && pi.created == created && pi.Path != "" {
		pi.checked = time.Now()
		return pi
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	path := ""
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		path = windows.UTF16ToString(buf[:n])
	}
	pi = &procInfo{Path: path, created: created, checked: time.Now()}
	if path == "" {
		pi.Key = fmt.Sprintf("pid:%d", pid)
		pi.Name = fmt.Sprintf("Proceso %d", pid)
	} else {
		pi.Key = strings.ToLower(path)
		pi.Name = pc.displayName(path)
	}
	pc.mu.Lock()
	pc.byPID[pid] = pi
	pc.mu.Unlock()
	return pi
}

// Sweep elimina entradas viejas para que el mapa no crezca sin límite.
func (pc *procCache) Sweep() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	for pid, pi := range pc.byPID {
		if time.Since(pi.checked) > 10*time.Minute {
			delete(pc.byPID, pid)
		}
	}
}

func (pc *procCache) displayName(path string) string {
	pc.mu.Lock()
	n, ok := pc.names[path]
	pc.mu.Unlock()
	if ok {
		return n
	}
	n = fileDescription(path)
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if n == "" || len(n) > 60 {
		n = base
	}
	// Algunos ejecutables genéricos se entienden mejor con su nombre de archivo.
	switch strings.ToLower(base) {
	case "svchost":
		n = "Host de servicios (svchost)"
	case "rundll32", "dllhost", "conhost":
		n = base
	}
	pc.mu.Lock()
	pc.names[path] = n
	pc.mu.Unlock()
	return n
}

func fileDescription(path string) string {
	var zero windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &zero)
	if err != nil || size == 0 {
		return ""
	}
	data := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&data[0])) != nil {
		return ""
	}
	var tp unsafe.Pointer
	var tl uint32
	langs := []string{}
	if windows.VerQueryValue(unsafe.Pointer(&data[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&tp), &tl) == nil && tl >= 4 {
		tr := unsafe.Slice((*uint16)(tp), tl/2)
		for i := 0; i+1 < len(tr); i += 2 {
			langs = append(langs, fmt.Sprintf("%04x%04x", tr[i], tr[i+1]))
		}
	}
	langs = append(langs, "040904b0", "040904e4", "0c0a04b0")
	for _, l := range langs {
		var vp unsafe.Pointer
		var vl uint32
		if windows.VerQueryValue(unsafe.Pointer(&data[0]), `\StringFileInfo\`+l+`\FileDescription`, unsafe.Pointer(&vp), &vl) == nil && vl > 1 {
			s := strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(vp), vl)))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Iconos de aplicaciones → PNG (con caché).
// ---------------------------------------------------------------------------

type iconCache struct {
	mu sync.Mutex
	m  map[string][]byte
}

var icons = &iconCache{m: map[string][]byte{}}

type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

type bitmap struct {
	BmType       int32
	BmWidth      int32
	BmHeight     int32
	BmWidthBytes int32
	BmPlanes     uint16
	BmBitsPixel  uint16
	BmBits       uintptr
}

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

func (ic *iconCache) Get(path string) []byte {
	key := strings.ToLower(path)
	ic.mu.Lock()
	b, ok := ic.m[key]
	ic.mu.Unlock()
	if ok {
		return b
	}
	b = extractIconPNG(path)
	ic.mu.Lock()
	ic.m[key] = b
	ic.mu.Unlock()
	return b
}

func readBitmap(hdc, hbm uintptr) (int, int, []byte) {
	var bm bitmap
	if call(procGetObjectW, hbm, unsafe.Sizeof(bm), ptr(&bm)) == 0 || bm.BmWidth <= 0 || bm.BmHeight <= 0 {
		return 0, 0, nil
	}
	w, h := int(bm.BmWidth), int(bm.BmHeight)
	bi := bitmapInfoHeader{BiWidth: int32(w), BiHeight: -int32(h), BiPlanes: 1, BiBitCount: 32}
	bi.BiSize = uint32(unsafe.Sizeof(bi))
	// BITMAPINFO = cabecera + tabla de colores; reservamos espacio extra.
	var info struct {
		H      bitmapInfoHeader
		Colors [256]uint32
	}
	info.H = bi
	px := make([]byte, w*h*4)
	if call(procGetDIBits, hdc, hbm, 0, uintptr(h), uintptr(unsafe.Pointer(&px[0])), ptr(&info), 0) == 0 {
		return 0, 0, nil
	}
	return w, h, px
}

func extractIconPNG(path string) []byte {
	if path == "" || procExtractIconExW.Find() != nil {
		return nil
	}
	var large, small uintptr
	if call(procExtractIconExW, uintptr(unsafe.Pointer(utf16(path))), 0, ptr(&large), ptr(&small), 1) == 0 {
		return nil
	}
	defer func() {
		if large != 0 {
			call(procDestroyIcon, large)
		}
		if small != 0 {
			call(procDestroyIcon, small)
		}
	}()
	hicon := large
	if hicon == 0 {
		hicon = small
	}
	if hicon == 0 {
		return nil
	}
	var ii iconInfo
	if call(procGetIconInfo, hicon, ptr(&ii)) == 0 {
		return nil
	}
	defer func() {
		if ii.HbmColor != 0 {
			call(procDeleteObject, ii.HbmColor)
		}
		if ii.HbmMask != 0 {
			call(procDeleteObject, ii.HbmMask)
		}
	}()
	if ii.HbmColor == 0 {
		return nil
	}
	hdc := call(procGetDC, 0)
	defer call(procReleaseDC, 0, hdc)
	w, h, px := readBitmap(hdc, ii.HbmColor)
	if px == nil {
		return nil
	}
	hasAlpha := false
	for i := 3; i < len(px); i += 4 {
		if px[i] != 0 {
			hasAlpha = true
			break
		}
	}
	var mask []byte
	if !hasAlpha && ii.HbmMask != 0 {
		_, mh, m := readBitmap(hdc, ii.HbmMask)
		if mh >= h {
			mask = m
		}
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := (y*w + x) * 4
			a := px[i+3]
			if !hasAlpha {
				a = 255
				if mask != nil && mask[i] != 0 {
					a = 0
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{px[i+2], px[i+1], px[i], a})
		}
	}
	var out bytes.Buffer
	if png.Encode(&out, img) != nil {
		return nil
	}
	return out.Bytes()
}

// ---------------------------------------------------------------------------
// Tablas de conexiones TCP/UDP con el PID propietario.
// ---------------------------------------------------------------------------

type sockRow struct {
	Proto  string // "TCP" o "UDP"
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint32
	PID    uint32
}

var tcpStates = map[uint32]string{
	1: "Cerrada", 2: "Escuchando", 3: "SYN enviado", 4: "SYN recibido", 5: "Establecida",
	6: "FIN espera 1", 7: "FIN espera 2", 8: "Cierre espera", 9: "Cerrando", 10: "Último ACK",
	11: "Tiempo espera", 12: "Eliminando",
}

const tcpEstablished = 5
const tcpListen = 2

func fetchTable(p *windows.LazyProc, af, class uint32) []byte {
	if p.Find() != nil {
		return nil
	}
	size := uint32(16 * 1024)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := p.Call(uintptr(unsafe.Pointer(&buf[0])), ptr(&size), 0, uintptr(af), uintptr(class), 0)
		if r == 0 {
			return buf[:size]
		}
		if r != errInsufficientBuffer {
			return nil
		}
		size += 4096
	}
	return nil
}

func port(v uint32) uint16 { return uint16(v>>8&0xff) | uint16(v&0xff)<<8 }

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}) }

func addr6(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	ad := netip.AddrFrom16(a)
	if ad.Is4In6() {
		return ad.Unmap()
	}
	return ad
}

func listSockets() []sockRow {
	var rows []sockRow
	le := binary.LittleEndian
	if b := fetchTable(procGetExtendedTcpTable, afInet, tcpTableOwnerPidAll); len(b) >= 4 {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*24 <= len(b); i++ {
			r := b[4+i*24:]
			rows = append(rows, sockRow{
				Proto:  "TCP",
				State:  le.Uint32(r[0:]),
				Local:  netip.AddrPortFrom(addr4(r[4:8]), port(le.Uint32(r[8:]))),
				Remote: netip.AddrPortFrom(addr4(r[12:16]), port(le.Uint32(r[16:]))),
				PID:    le.Uint32(r[20:]),
			})
		}
	}
	if b := fetchTable(procGetExtendedTcpTable, afInet6, tcpTableOwnerPidAll); len(b) >= 4 {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*56 <= len(b); i++ {
			r := b[4+i*56:]
			rows = append(rows, sockRow{
				Proto:  "TCP",
				Local:  netip.AddrPortFrom(addr6(r[0:16]), port(le.Uint32(r[20:]))),
				Remote: netip.AddrPortFrom(addr6(r[24:40]), port(le.Uint32(r[44:]))),
				State:  le.Uint32(r[48:]),
				PID:    le.Uint32(r[52:]),
			})
		}
	}
	if b := fetchTable(procGetExtendedUdpTable, afInet, udpTableOwnerPid); len(b) >= 4 {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*12 <= len(b); i++ {
			r := b[4+i*12:]
			rows = append(rows, sockRow{
				Proto: "UDP",
				Local: netip.AddrPortFrom(addr4(r[0:4]), port(le.Uint32(r[4:]))),
				PID:   le.Uint32(r[8:]),
			})
		}
	}
	if b := fetchTable(procGetExtendedUdpTable, afInet6, udpTableOwnerPid); len(b) >= 4 {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*28 <= len(b); i++ {
			r := b[4+i*28:]
			rows = append(rows, sockRow{
				Proto: "UDP",
				Local: netip.AddrPortFrom(addr6(r[0:16]), port(le.Uint32(r[20:]))),
				PID:   le.Uint32(r[24:]),
			})
		}
	}
	return rows
}

func fileStamp(path string) (int64, int64) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0
	}
	return st.Size(), st.ModTime().Unix()
}
