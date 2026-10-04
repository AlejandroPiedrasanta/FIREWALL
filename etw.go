//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Tráfico por proceso mediante ETW (proveedor Microsoft-Windows-Kernel-Network),
// el mismo mecanismo que usan los monitores de red de Windows. Requiere
// permisos de administrador.

var kernelNetworkGUID = windows.GUID{
	Data1: 0x7DD42A49, Data2: 0x5329, Data3: 0x4832,
	Data4: [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88},
}

const etwSessionName = "MiniWall-Net"

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type etwProps struct {
	P    eventTraceProperties
	Name [256]uint16
}

type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [88]byte
	LogfileHeader       [280]byte
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	_                   uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	_                   uint32
	Context             uintptr
}

type eventHeader struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	ProviderID    windows.GUID
	ID            uint16
	Version       uint8
	Channel       uint8
	Level         uint8
	Opcode        uint8
	Task          uint16
	Keyword       uint64
	ProcessorTime uint64
	ActivityID    windows.GUID
}

type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// Comprobación en compilación de que las estructuras tienen el tamaño de Windows x64.
var _ = [1]struct{}{}[unsafe.Sizeof(eventTraceProperties{})-120]
var _ = [1]struct{}{}[unsafe.Sizeof(eventTraceLogfile{})-448]
var _ = [1]struct{}{}[unsafe.Sizeof(eventRecord{})-112]

const (
	wnodeFlagTracedGUID         = 0x00020000
	eventTraceRealTimeMode      = 0x00000100
	eventTraceControlStop       = 1
	eventControlEnableProvider  = 1
	traceLevelInformation       = 4
	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000
	invalidProcessTraceHandle   = ^uint64(0)
	kernelNetworkKeywordIPv4    = 0x10
	kernelNetworkKeywordIPv6    = 0x20
	errAlreadyExists            = 183
)

type flowAcc struct{ Rx, Tx uint64 }

type hostKey struct {
	PID  uint32
	Addr netip.Addr
}

type etwMonitor struct {
	mu     sync.Mutex
	pids   map[uint32]*flowAcc
	hosts  map[hostKey]*flowAcc
	props  *etwProps
	handle uint64
	trace  uint64
	Err    error
	Active bool
	cb     uintptr
}

var etwSingleton *etwMonitor

func newProps() *etwProps {
	p := &etwProps{}
	p.P.Wnode.BufferSize = uint32(unsafe.Sizeof(*p))
	p.P.Wnode.Flags = wnodeFlagTracedGUID
	p.P.Wnode.ClientContext = 1 // QPC
	if g, err := windows.GenerateGUID(); err == nil {
		p.P.Wnode.GUID = g
	}
	p.P.LogFileMode = eventTraceRealTimeMode
	p.P.BufferSize = 64 // KB
	p.P.MinimumBuffers = 4
	p.P.MaximumBuffers = 32
	p.P.FlushTimer = 1
	p.P.LoggerNameOffset = uint32(unsafe.Offsetof(p.Name))
	return p
}

func stopSession() {
	p := newProps()
	call(procControlTraceW, 0, uintptr(unsafe.Pointer(utf16(etwSessionName))), ptr(p), eventTraceControlStop)
}

// startETW arranca la sesión en tiempo real; si falla, Err indica el motivo y
// MiniWall sigue funcionando con totales por interfaz.
func startETW() *etwMonitor {
	m := &etwMonitor{pids: map[uint32]*flowAcc{}, hosts: map[hostKey]*flowAcc{}}
	etwSingleton = m
	if err := procStartTraceW.Find(); err != nil {
		m.Err = err
		return m
	}
	stopSession() // por si quedó una sesión de una ejecución anterior

	m.props = newProps()
	r := call(procStartTraceW, ptr(&m.handle), uintptr(unsafe.Pointer(utf16(etwSessionName))), ptr(m.props))
	if r == errAlreadyExists {
		stopSession()
		m.props = newProps()
		r = call(procStartTraceW, ptr(&m.handle), uintptr(unsafe.Pointer(utf16(etwSessionName))), ptr(m.props))
	}
	if r != 0 {
		m.Err = fmt.Errorf("StartTrace: %w", windows.Errno(r))
		return m
	}
	guid := kernelNetworkGUID
	r = call(procEnableTraceEx2, uintptr(m.handle), ptr(&guid), eventControlEnableProvider,
		traceLevelInformation, kernelNetworkKeywordIPv4|kernelNetworkKeywordIPv6, 0, 0, 0)
	if r != 0 {
		m.Err = fmt.Errorf("EnableTraceEx2: %w", windows.Errno(r))
		stopSession()
		return m
	}

	m.cb = newCallback(etwEventCallback)
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		lf := &eventTraceLogfile{
			LoggerName:          utf16(etwSessionName),
			ProcessTraceMode:    processTraceModeRealTime | processTraceModeEventRecord,
			EventRecordCallback: m.cb,
		}
		h := uint64(call(procOpenTraceW, ptr(lf)))
		if h == invalidProcessTraceHandle || h == 0xFFFFFFFF {
			ready <- errors.New("OpenTrace falló")
			return
		}
		m.trace = h
		ready <- nil
		call(procProcessTrace, ptr(&h), 1, 0, 0) // bloquea hasta que se detenga la sesión
		call(procCloseTrace, uintptr(h))
	}()
	if err := <-ready; err != nil {
		m.Err = err
		stopSession()
		return m
	}
	m.Active = true
	return m
}

func (m *etwMonitor) Stop() {
	if m == nil || !m.Active {
		return
	}
	m.Active = false
	stopSession()
}

func etwEventCallback(rec *eventRecord) uintptr {
	m := etwSingleton
	if m == nil || rec == nil || rec.EventHeader.ProviderID != kernelNetworkGUID || rec.UserData == 0 {
		return 0
	}
	var send, v6 bool
	switch rec.EventHeader.ID {
	case 10, 42: // TCPv4 / UDPv4 enviados
		send = true
	case 11, 43: // TCPv4 / UDPv4 recibidos
	case 26, 58: // TCPv6 / UDPv6 enviados
		send, v6 = true, true
	case 27, 59: // TCPv6 / UDPv6 recibidos
		v6 = true
	default:
		return 0
	}
	n := int(rec.UserDataLength)
	if n < 16 || (v6 && n < 40) {
		return 0
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(rec.UserData)), n)
	pid := binary.LittleEndian.Uint32(data[0:])
	size := uint64(binary.LittleEndian.Uint32(data[4:]))
	var remote netip.Addr
	if v6 {
		remote = addr6(data[8:24])
	} else {
		remote = addr4(data[8:12])
	}
	if remote.IsLoopback() || remote.IsUnspecified() {
		return 0
	}
	m.mu.Lock()
	a := m.pids[pid]
	if a == nil {
		a = &flowAcc{}
		m.pids[pid] = a
	}
	k := hostKey{pid, remote}
	h := m.hosts[k]
	if h == nil {
		h = &flowAcc{}
		m.hosts[k] = h
	}
	if send {
		a.Tx += size
		h.Tx += size
	} else {
		a.Rx += size
		h.Rx += size
	}
	m.mu.Unlock()
	return 0
}

// Drain devuelve y reinicia los acumulados desde la última llamada.
func (m *etwMonitor) Drain() (map[uint32]*flowAcc, map[hostKey]*flowAcc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, h := m.pids, m.hosts
	m.pids = map[uint32]*flowAcc{}
	m.hosts = map[hostKey]*flowAcc{}
	return p, h
}
