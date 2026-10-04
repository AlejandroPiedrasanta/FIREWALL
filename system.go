//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ---------------------------------------------------------------------------
// Contadores de interfaces de red (totales reales de bytes).
// ---------------------------------------------------------------------------

type ifaceInfo struct {
	Name   string `json:"name"`
	Desc   string `json:"desc"`
	Type   string `json:"type"`
	Speed  uint64 `json:"speed"`
	Up     bool   `json:"up"`
	Rx     uint64 `json:"rx"`
	Tx     uint64 `json:"tx"`
	MAC    string `json:"mac"`
	hw     bool
	filter bool
}

func ifTypeName(t uint32) string {
	switch t {
	case 6:
		return "Ethernet"
	case 71:
		return "Wi-Fi"
	case 24:
		return "Loopback"
	case 131:
		return "Túnel"
	case 243, 244:
		return "Móvil"
	case 53:
		return "Virtual"
	default:
		return fmt.Sprintf("Tipo %d", t)
	}
}

func listInterfaces() []ifaceInfo {
	if procGetIfTable2.Find() != nil {
		return nil
	}
	var table uintptr
	if call(procGetIfTable2, ptr(&table)) != 0 || table == 0 {
		return nil
	}
	defer call(procFreeMibTable, table)
	n := *(*uint32)(unsafe.Pointer(table))
	rowSize := unsafe.Sizeof(windows.MibIfRow2{})
	var out []ifaceInfo
	for i := uint32(0); i < n; i++ {
		row := (*windows.MibIfRow2)(unsafe.Pointer(table + 8 + uintptr(i)*rowSize))
		mac := ""
		if row.PhysicalAddressLength == 6 {
			p := row.PhysicalAddress
			mac = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5])
		}
		out = append(out, ifaceInfo{
			Name:   windows.UTF16ToString(row.Alias[:]),
			Desc:   windows.UTF16ToString(row.Description[:]),
			Type:   ifTypeName(row.Type),
			Speed:  row.ReceiveLinkSpeed,
			Up:     row.OperStatus == 1,
			Rx:     row.InOctets,
			Tx:     row.OutOctets,
			MAC:    mac,
			hw:     row.InterfaceAndOperStatusFlags&0x01 != 0,
			filter: row.InterfaceAndOperStatusFlags&0x02 != 0,
		})
	}
	return out
}

// totalCounters suma los bytes de los adaptadores físicos activos.
func totalCounters(ifs []ifaceInfo) (rx, tx uint64) {
	for _, i := range ifs {
		if i.hw && !i.filter && i.Type != "Loopback" {
			rx += i.Rx
			tx += i.Tx
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Recursos de hardware: CPU, memoria, discos.
// ---------------------------------------------------------------------------

type cpuSampler struct{ idle, total uint64 }

func ft(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

func (c *cpuSampler) Sample() float64 {
	var idle, kern, user windows.Filetime
	if call(procGetSystemTimes, ptr(&idle), ptr(&kern), ptr(&user)) == 0 {
		return 0
	}
	i, t := ft(idle), ft(kern)+ft(user) // el tiempo de núcleo incluye el inactivo
	di, dt := i-c.idle, t-c.total
	first := c.total == 0
	c.idle, c.total = i, t
	if first || dt == 0 {
		return 0
	}
	v := 100 * float64(dt-di) / float64(dt)
	if v < 0 {
		v = 0
	}
	return v
}

func memoryStatus() (used, total uint64, load uint32) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	if call(procGlobalMemoryStatusEx, ptr(&m)) == 0 {
		return
	}
	return m.TotalPhys - m.AvailPhys, m.TotalPhys, m.MemoryLoad
}

type diskInfo struct {
	Drive string `json:"drive"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
}

func listDisks() []diskInfo {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []diskInfo
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		if windows.GetDriveType(utf16(root)) != windows.DRIVE_FIXED {
			continue
		}
		var free, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(utf16(root), &free, &total, &totalFree) == nil {
			out = append(out, diskInfo{Drive: root[:2], Total: total, Free: totalFree})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Comandos del sistema (netsh, schtasks) sin ventana de consola.
// ---------------------------------------------------------------------------

func runHidden(cmdline string) (string, error) {
	exe := strings.Fields(cmdline)[0]
	c := exec.Command(exe)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CmdLine: cmdline, CreationFlags: 0x08000000}
	out, err := c.CombinedOutput()
	s := decodeOEM(out)
	if err != nil {
		return s, fmt.Errorf("%s: %v %s", exe, err, strings.TrimSpace(s))
	}
	return s, nil
}

// decodeOEM convierte la salida de consola (página de códigos OEM) a UTF-8.
func decodeOEM(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	acp := uint32(1) // CP_OEMCP
	n, err := windows.MultiByteToWideChar(acp, 0, &b[0], int32(len(b)), nil, 0)
	if err != nil || n == 0 {
		return string(b)
	}
	w := make([]uint16, n)
	if _, err := windows.MultiByteToWideChar(acp, 0, &b[0], int32(len(b)), &w[0], n); err != nil {
		return string(b)
	}
	return windows.UTF16ToString(w)
}

// ---------------------------------------------------------------------------
// Wi-Fi: red actual (para detectar gemelos malvados).
// ---------------------------------------------------------------------------

type wifiNow struct {
	Connected bool   `json:"connected"`
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Auth      string `json:"auth"`
	Cipher    string `json:"cipher"`
	Signal    string `json:"signal"`
	Channel   string `json:"channel"`
	Radio     string `json:"radio"`
	Location  bool   `json:"-"`
}

var macRe = regexp.MustCompile(`(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}`)

func currentWifi() (wifiNow, error) {
	out, err := runHidden(`netsh wlan show interfaces`)
	var w wifiNow
	if err != nil {
		return w, err
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch {
		case k == "ssid":
			w.SSID = v
		case strings.HasSuffix(k, "bssid"):
			if m := macRe.FindString(line); m != "" {
				w.BSSID = strings.ToUpper(strings.ReplaceAll(m, "-", ":"))
			}
		case strings.HasPrefix(k, "auth") || strings.HasPrefix(k, "autent"):
			w.Auth = v
		case strings.HasPrefix(k, "cipher") || strings.HasPrefix(k, "cifrado"):
			w.Cipher = v
		case strings.HasSuffix(v, "%") && w.Signal == "":
			w.Signal = v
		case k == "channel" || k == "canal":
			w.Channel = v
		case strings.HasPrefix(k, "radio"):
			w.Radio = v
		}
	}
	w.Connected = w.SSID != "" && w.BSSID != ""
	if !w.Connected && strings.Contains(strings.ToLower(out), "privacy-location") {
		w.Location = true
	}
	return w, nil
}

// ---------------------------------------------------------------------------
// Red local: dispositivos vistos en la caché ARP de este equipo (lectura pasiva).
// ---------------------------------------------------------------------------

type arpEntry struct {
	IP  netip.Addr
	MAC string
}

func readARP() []arpEntry {
	if procGetIpNetTable.Find() != nil {
		return nil
	}
	size := uint32(0)
	call(procGetIpNetTable, 0, ptr(&size), 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size+1024)
	size = uint32(len(buf))
	if call(procGetIpNetTable, uintptr(unsafe.Pointer(&buf[0])), ptr(&size), 1) != 0 {
		return nil
	}
	le := binary.LittleEndian
	n := int(le.Uint32(buf))
	var out []arpEntry
	for i := 0; i < n && 4+(i+1)*24 <= len(buf); i++ {
		r := buf[4+i*24:]
		plen := le.Uint32(r[4:])
		typ := le.Uint32(r[20:])
		if plen != 6 || (typ != 3 && typ != 4) { // dinámica o estática
			continue
		}
		mac := r[8:14]
		if mac[0]&1 == 1 || (mac[0]|mac[1]|mac[2]|mac[3]|mac[4]|mac[5]) == 0 {
			continue // multidifusión / difusión / vacía
		}
		ip := addr4(r[16:20])
		if !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			continue
		}
		b := ip.As4()
		if b[3] == 255 || b[3] == 0 {
			continue
		}
		out = append(out, arpEntry{IP: ip, MAC: fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// localNet devuelve IPs/MACs propias y las puertas de enlace.
func localNet() (self map[string]string, gateways map[string]bool) {
	self, gateways = map[string]string{}, map[string]bool{}
	size := uint32(15000)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(afInet, 0x80 /*GAA_FLAG_INCLUDE_GATEWAYS*/, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return
		}
		for a := aa; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			mac := ""
			if a.PhysicalAddressLength == 6 {
				p := a.PhysicalAddress
				mac = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5])
			}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				if ip := u.Address.IP(); ip != nil {
					if ad, ok := netip.AddrFromSlice(ip); ok {
						self[ad.Unmap().String()] = mac
					}
				}
			}
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				if ip := g.Address.IP(); ip != nil {
					if ad, ok := netip.AddrFromSlice(ip); ok {
						gateways[ad.Unmap().String()] = true
					}
				}
			}
		}
		return
	}
	return
}

// ---------------------------------------------------------------------------
// Privacidad: uso de cámara y micrófono (registro de Windows).
// ---------------------------------------------------------------------------

type capUse struct {
	Device string `json:"device"` // "cámara" | "micrófono"
	App    string `json:"app"`
	Path   string `json:"path"`
	Active bool   `json:"active"`
	Last   int64  `json:"last"` // unix
}

const consentStore = `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\`

func filetimeUnix(v uint64) int64 {
	if v == 0 {
		return 0
	}
	return int64(v/10000000) - 11644473600
}

func readCapability(root registry.Key, capName, device string, out *[]capUse) {
	readOne := func(k registry.Key, sub, display, path string) {
		ck, err := registry.OpenKey(k, sub, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer ck.Close()
		start, _, _ := ck.GetIntegerValue("LastUsedTimeStart")
		stop, _, _ := ck.GetIntegerValue("LastUsedTimeStop")
		if start == 0 {
			return
		}
		*out = append(*out, capUse{Device: device, App: display, Path: path, Active: stop == 0 || stop < start, Last: filetimeUnix(start)})
	}
	base, err := registry.OpenKey(root, consentStore+capName, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer base.Close()
	subs, _ := base.ReadSubKeyNames(-1)
	for _, s := range subs {
		if s == "NonPackaged" {
			np, err := registry.OpenKey(base, s, registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				continue
			}
			apps, _ := np.ReadSubKeyNames(-1)
			for _, a := range apps {
				p := strings.ReplaceAll(a, "#", `\`)
				readOne(np, a, p, p)
			}
			np.Close()
			continue
		}
		name := s
		if i := strings.Index(name, "_"); i > 0 {
			name = name[:i]
		}
		readOne(base, s, name, "")
	}
}

func privacyStatus() []capUse {
	var out []capUse
	readCapability(registry.CURRENT_USER, "webcam", "cámara", &out)
	readCapability(registry.CURRENT_USER, "microphone", "micrófono", &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	return out
}

// ---------------------------------------------------------------------------
// Escritorio remoto (RDP).
// ---------------------------------------------------------------------------

type rdpStatus struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

func readRDP() rdpStatus {
	st := rdpStatus{Port: 3389}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, registry.QUERY_VALUE); err == nil {
		v, _, err := k.GetIntegerValue("fDenyTSConnections")
		st.Enabled = err == nil && v == 0
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("PortNumber"); err == nil && v > 0 && v < 65536 {
			st.Port = int(v)
		}
		k.Close()
	}
	return st
}

// ---------------------------------------------------------------------------
// Estado del Firewall de Windows (registro local).
// ---------------------------------------------------------------------------

type fwProfileState struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	BlockOutDflt bool   `json:"blockOut"`
}

func firewallState() []fwProfileState {
	names := [][2]string{{"DomainProfile", "Dominio"}, {"StandardProfile", "Privada"}, {"PublicProfile", "Pública"}}
	var out []fwProfileState
	for _, n := range names {
		st := fwProfileState{Name: n[1], Enabled: true}
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+n[0], registry.QUERY_VALUE)
		if err == nil {
			if v, _, err := k.GetIntegerValue("EnableFirewall"); err == nil {
				st.Enabled = v != 0
			}
			if v, _, err := k.GetIntegerValue("DefaultOutboundAction"); err == nil {
				st.BlockOutDflt = v == 1
			}
			k.Close()
		}
		out = append(out, st)
	}
	return out
}

func uptime() time.Duration { return time.Duration(tickCount64()) * time.Millisecond }
