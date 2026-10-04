//go:build windows

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type secSample struct{ T, Rx, Tx int64 }

type liveApp struct {
	Key      string
	Path     string
	Name     string
	RxRate   uint64
	TxRate   uint64
	Rx, Tx   uint64
	Conns    int
	LastSeen int64
	// Análisis de amenazas:
	Risk      int      // 0 ok · 1 sospechoso · 2 peligro
	Reasons   []string // por qué
	Signed    int      // -1 desconocido · 0 sin firma/ inválida · 1 firmado
	Exposed   bool     // escucha en todas las interfaces (servicio accesible desde la red)
	Listen    int      // nº de puertos a la escucha
	Tor       bool     // posible red Tor / servicio oculto
	Adobe     bool     // pertenece a Adobe
	countries map[string]bool
}

type hostLive struct {
	IP        string
	Name      string
	CC        string
	Apps      map[string]bool
	Rx, Tx    uint64
	Conns     int
	FirstSeen int64
	LastSeen  int64
}

type Alert struct {
	ID    int64  `json:"id"`
	T     int64  `json:"t"`
	Kind  string `json:"kind"`
	Level string `json:"level"` // info | warn | danger
	Title string `json:"title"`
	Text  string `json:"text"`
	Key   string `json:"key,omitempty"`
	Read  bool   `json:"read"`
}

type connView struct {
	Key    string `json:"key"`
	App    string `json:"app"`
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
	Host   string `json:"host"`
	CC     string `json:"cc"`
	State  string `json:"state"`
}

type listenView struct {
	Key     string `json:"key"`
	App     string `json:"app"`
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    uint16 `json:"port"`
	Exposed bool   `json:"exposed"` // 0.0.0.0 / :: → accesible desde la red
	Risk    int    `json:"risk"`
}

type App struct {
	mu      sync.Mutex
	dir     string
	cfg     *Config
	hist    *History
	procs   *procCache
	etw     *etwMonitor
	cpu     cpuSampler
	started time.Time

	firstRun   bool
	cfgDirty   bool
	lastStep   time.Time
	lastRx     uint64
	lastTx     uint64
	secs       []secSample
	apps       map[string]*liveApp
	hosts      map[string]*hostLive
	conns      []connView
	listens    []listenView
	alerts     []*Alert
	alertSeq   int64
	checked    map[string]bool
	cpuHist    []float64
	memHist    []float64
	memUsed    uint64
	memTotal   uint64
	ifaces     []ifaceInfo
	disks      []diskInfo
	wifi       wifiNow
	wifiErr    string
	wifiStatus string
	wifiLevel  string
	wifiSeen   map[string]bool
	privacy    []capUse
	privActive map[string]bool
	rdp        rdpStatus
	rdpPeers   map[string]bool
	rdpActive  []string
	arp        []arpEntry
	selfIPs    map[string]string
	gateways   map[string]bool
	dnsNames   map[string]string
	dnsPending map[string]bool
	dnsQueue   chan string
	fwQueue    chan func()
	fwErr      string
	tick       int64

	allowOn    map[string]string // reglas de permiso aplicadas (modo estricto, en memoria)
	sigQueue   chan string       // rutas pendientes de comprobar firma
	sigPending map[string]bool
	threatSeen map[string]int  // clave → nivel ya avisado
	adobeSeen  map[string]bool // apps Adobe ya avisadas
	notify     func(title, text, level string)
	onAsk      func() // traer la ventana al frente cuando un programa pide permiso
	stopOnce   sync.Once
}

func NewApp(dir string) *App {
	a := &App{
		dir:        dir,
		procs:      newProcCache(),
		started:    time.Now(),
		apps:       map[string]*liveApp{},
		hosts:      map[string]*hostLive{},
		checked:    map[string]bool{},
		wifiSeen:   map[string]bool{},
		privActive: map[string]bool{},
		rdpPeers:   map[string]bool{},
		dnsNames:   map[string]string{},
		dnsPending: map[string]bool{},
		dnsQueue:   make(chan string, 512),
		fwQueue:    make(chan func(), 256),
		allowOn:    map[string]string{},
		sigQueue:   make(chan string, 256),
		sigPending: map[string]bool{},
		threatSeen: map[string]int{},
		adobeSeen:  map[string]bool{},
		notify:     func(string, string, string) {},
		onAsk:      func() {},
	}
	a.cfg = defaultConfig()
	if err := readJSON(filepath.Join(dir, "config.json"), a.cfg); err != nil {
		a.firstRun = true
		a.cfg = defaultConfig()
	}
	a.cfg.normalize()
	a.hist = loadHistory(filepath.Join(dir, "history.json"))
	a.hist.retention = a.cfg.Retention
	if raw := readAlerts(filepath.Join(dir, "alerts.json")); raw != nil {
		a.alerts = raw
		for _, al := range raw {
			if al.ID > a.alertSeq {
				a.alertSeq = al.ID
			}
		}
	}
	return a
}

func readAlerts(path string) []*Alert {
	var al []*Alert
	if readJSON(path, &al) != nil {
		return nil
	}
	return al
}

func (a *App) Start() {
	a.etw = startETW()
	if a.etw.Err != nil {
		log.Printf("ETW no disponible: %v", a.etw.Err)
	}
	go a.fwWorker()
	for i := 0; i < 4; i++ {
		go a.dnsWorker()
	}
	for i := 0; i < 2; i++ {
		go a.sigWorker()
	}
	// Sincroniza las reglas del perfil activo y el modo con el firewall.
	a.queueFW(func() {
		a.mu.Lock()
		mode, rdpBlocked, strict := a.cfg.Mode, a.cfg.RDPBlocked, a.cfg.StrictBlock
		port := readRDP().Port
		a.mu.Unlock()
		// El bloqueo de salida por defecto (modo estricto) se reaplica en cada
		// arranque: así sigue protegiendo tras reiniciar aunque alguien lo quitara.
		if mode == "preguntar" && strict {
			a.fwResult(fwStrictOutbound(true))
		}
		a.syncRulesForce(true) // reaplica reglas por si se borraron a mano
		if mode == "bloquear" {
			a.fwResult(fwBlockAll(true))
		}
		if rdpBlocked {
			a.fwResult(fwBlockRDP(true, port))
		}
	})
	go a.loop()
	go a.guardLoop()
}

// guardLoop refuerza la protección: reactiva el Firewall de Windows si alguien
// lo apaga y reaplica las reglas de MiniWall periódicamente, de modo que los
// bloqueos no puedan desaparecer sin que vuelvan a ponerse.
func (a *App) guardLoop() {
	for range time.Tick(45 * time.Second) {
		a.mu.Lock()
		guard, mode, strict := a.cfg.Guard, a.cfg.Mode, a.cfg.StrictBlock
		a.mu.Unlock()
		if !guard {
			continue
		}
		a.queueFW(func() {
			if !fwIsOn() {
				a.fwResult(fwEnable())
				a.alert("system", "warn", "Firewall reactivado", "El Firewall de Windows se había desactivado y MiniWall lo ha vuelto a encender.", "")
			}
			if mode == "preguntar" && strict {
				fwStrictOutbound(true)
			} else if mode == "bloquear" {
				fwBlockAll(true)
			}
			a.syncRulesForce(true)
		})
	}
}

func (a *App) Stop() {
	a.stopOnce.Do(func() {
		a.etw.Stop()
		a.mu.Lock()
		blockAll := a.cfg.Mode == "bloquear"
		a.mu.Unlock()
		if blockAll {
			// La directiva global se restaura al salir para no dejar el equipo sin
			// conexión si MiniWall se cierra o se desinstala. Se reaplica al iniciar.
			fwBlockAll(false)
		}
		a.save(true)
	})
}

// ClearAll elimina todas las reglas creadas por MiniWall (útil antes de desinstalar).
func (a *App) ClearAll() {
	a.mu.Lock()
	applied := map[string]string{}
	for k, v := range a.cfg.Applied {
		applied[k] = v
	}
	allowApplied := map[string]string{}
	for k, v := range a.allowOn {
		allowApplied[k] = v
	}
	prevMode := a.cfg.Mode
	prevStrict := a.cfg.StrictBlock
	port := a.rdp.Port
	a.cfg.Pending = map[string]int64{}
	a.cfg.Allowed = map[string]string{}
	for _, p := range a.cfg.Profiles {
		p.Blocked = nil
	}
	a.cfg.Mode = "monitor"
	a.cfg.RDPBlocked = false
	a.cfg.StrictBlock = false
	a.cfgDirty = true
	a.mu.Unlock()
	a.queueFW(func() {
		for k, p := range applied {
			fwUnblockApp(k, p)
			a.markApplied(k, p, false)
		}
		for k, p := range allowApplied {
			fwUnallowApp(k, p)
			a.markAllowed(k, p, false)
		}
		if prevMode == "bloquear" {
			fwBlockAll(false)
		}
		if prevStrict {
			fwStrictOutbound(false)
		}
		fwBlockRDP(false, port)
		a.fwResult(nil)
	})
}

func (a *App) loop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for now := range t.C {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("error en el ciclo de monitorización: %v", r)
				}
			}()
			a.step(now)
		}()
	}
}

func (a *App) step(now time.Time) {
	a.tick++
	tick := a.tick

	// 1. Totales por interfaz. La tasa se normaliza por el tiempo transcurrido
	// real para que un ciclo retrasado no produzca picos falsos (más preciso).
	ifs := listInterfaces()
	rx, tx := totalCounters(ifs)
	var dRx, dTx uint64
	if a.lastRx != 0 && rx >= a.lastRx && tx >= a.lastTx {
		dRx, dTx = rx-a.lastRx, tx-a.lastTx
	}
	a.lastRx, a.lastTx = rx, tx
	a.hist.AddTotals(now, dRx, dTx) // el historial guarda bytes reales transferidos
	elapsed := 1.0
	if !a.lastStep.IsZero() {
		if e := now.Sub(a.lastStep).Seconds(); e > 0.05 && e < 10 {
			elapsed = e
		}
	}
	a.lastStep = now
	rateRx := uint64(float64(dRx)/elapsed + 0.5)
	rateTx := uint64(float64(dTx)/elapsed + 0.5)

	// 2. Tráfico por proceso (ETW). Se resuelven los PID fuera del candado.
	type appDelta struct {
		pi     *procInfo
		rx, tx uint64
	}
	var deltas []appDelta
	var hostDeltas []struct {
		key    string
		ip     netip.Addr
		rx, tx uint64
	}
	if a.etw != nil && a.etw.Active {
		pids, hosts := a.etw.Drain()
		for pid, f := range pids {
			deltas = append(deltas, appDelta{a.procs.Get(pid), f.Rx, f.Tx})
		}
		for hk, f := range hosts {
			pi := a.procs.Get(hk.PID)
			hostDeltas = append(hostDeltas, struct {
				key    string
				ip     netip.Addr
				rx, tx uint64
			}{pi.Key, hk.Addr, f.Rx, f.Tx})
		}
	}

	// 3. Conexiones (cada segundo, para un estado en tiempo real preciso).
	var socks []sockRow
	var sockProcs map[uint32]*procInfo
	if true {
		socks = listSockets()
		sockProcs = map[uint32]*procInfo{}
		for _, s := range socks {
			if _, ok := sockProcs[s.PID]; !ok {
				sockProcs[s.PID] = a.procs.Get(s.PID)
			}
		}
	}

	cpu := a.cpu.Sample()
	used, total, _ := memoryStatus()

	a.mu.Lock()
	defer a.mu.Unlock()

	a.ifaces = ifs
	a.secs = append(a.secs, secSample{now.Unix(), int64(rateRx), int64(rateTx)})
	if len(a.secs) > 900 {
		a.secs = a.secs[len(a.secs)-900:]
	}
	a.cpuHist = pushF(a.cpuHist, cpu, 120)
	mp := 0.0
	if total > 0 {
		mp = 100 * float64(used) / float64(total)
	}
	a.memHist = pushF(a.memHist, mp, 120)
	a.memUsed, a.memTotal = used, total

	for _, la := range a.apps {
		la.RxRate, la.TxRate = 0, 0
	}
	for _, d := range deltas {
		la := a.liveApp(d.pi, now)
		la.RxRate += d.rx
		la.TxRate += d.tx
		la.Rx += d.rx
		la.Tx += d.tx
		a.hist.AddApp(now, d.pi.Key, d.pi.Name, d.rx, d.tx)
		if d.pi.Path != "" {
			a.seeApp(d.pi, now)
		}
	}
	for _, hd := range hostDeltas {
		ip := hd.ip.String()
		h := a.host(hd.ip, now)
		h.Rx += hd.rx
		h.Tx += hd.tx
		h.Apps[hd.key] = true
		a.hist.AddHost(now, ip, h.CC, h.Name, hd.rx, hd.tx)
	}

	if socks != nil {
		a.processSockets(socks, sockProcs, now)
		a.checkAdobe(now)
	}
	if tick%2 == 0 {
		a.checkPrivacy(now)
	}
	if tick%30 == 1 {
		a.rdp = readRDP()
		a.disks = listDisks()
		a.procs.Sweep()
		a.pruneHosts(now)
	}
	if tick%15 == 3 {
		go a.checkNetwork(now)
	}
	if tick%60 == 5 {
		a.checkLimit(now)
		a.hist.Prune(now)
	}
	if tick%120 == 0 {
		go a.save(false)
	} else if a.cfgDirty && tick%10 == 0 {
		go a.saveConfig()
	}
	if a.firstRun && now.Sub(a.started) > 2*time.Minute {
		a.firstRun = false // termina el periodo de aprendizaje inicial
	}
}

func pushF(s []float64, v float64, max int) []float64 {
	s = append(s, v)
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return s
}

func (a *App) liveApp(pi *procInfo, now time.Time) *liveApp {
	la := a.apps[pi.Key]
	if la == nil {
		la = &liveApp{Key: pi.Key, Path: pi.Path, Name: pi.Name, Adobe: isAdobe(pi.Path, pi.Name)}
		a.apps[pi.Key] = la
	}
	la.LastSeen = now.Unix()
	if la.Path == "" && pi.Path != "" {
		la.Path = pi.Path
	}
	return la
}

// checkAdobe avisa (una vez por app) cuando un programa de Adobe se conecta.
// Salta siempre, incluso durante el arranque, porque el usuario quiere estar
// avisado de cualquier conexión de Adobe.
func (a *App) checkAdobe(now time.Time) {
	for k, la := range a.apps {
		if !la.Adobe || la.Conns == 0 || a.adobeSeen[k] {
			continue
		}
		a.adobeSeen[k] = true
		a.alert("adobe", "warn", "⚠ Conexión de Adobe",
			la.Name+" (Adobe) está conectándose a Internet.\n"+la.Path, k)
	}
}

func (a *App) host(ip netip.Addr, now time.Time) *hostLive {
	k := ip.String()
	h := a.hosts[k]
	if h == nil {
		h = &hostLive{IP: k, CC: countryOf(ip), Apps: map[string]bool{}, FirstSeen: now.Unix()}
		a.hosts[k] = h
		a.resolve(k)
	}
	if h.Name == "" {
		h.Name = a.dnsNames[k]
	}
	h.LastSeen = now.Unix()
	return h
}

func (a *App) pruneHosts(now time.Time) {
	cut := now.Add(-3 * time.Hour).Unix()
	for k, h := range a.hosts {
		if h.LastSeen < cut && h.Conns == 0 {
			delete(a.hosts, k)
		}
	}
	for k, la := range a.apps {
		if la.LastSeen < cut && la.Conns == 0 {
			delete(a.apps, k)
		}
	}
}

// processSockets actualiza conexiones, puertos en escucha, RDP y apps nuevas.
func (a *App) processSockets(socks []sockRow, procs map[uint32]*procInfo, now time.Time) {
	for _, la := range a.apps {
		la.Conns = 0
		la.Exposed = false
		la.Listen = 0
		la.Tor = false
		la.countries = map[string]bool{}
	}
	for _, h := range a.hosts {
		h.Conns = 0
	}
	var conns []connView
	var listens []listenView
	rdpNow := map[string]bool{}
	selfPath := strings.ToLower(selfExe())
	for _, s := range socks {
		pi := procs[s.PID]
		if pi == nil {
			continue
		}
		if s.Proto == "UDP" || s.State == tcpListen {
			if !s.Local.Addr().IsLoopback() {
				exposed := s.Local.Addr().IsUnspecified() // 0.0.0.0 o :: → accesible desde la red
				la := a.liveApp(pi, now)
				la.Listen++
				if exposed {
					la.Exposed = true
				}
				listens = append(listens, listenView{Key: pi.Key, App: pi.Name, Proto: s.Proto, Addr: s.Local.Addr().String(), Port: s.Local.Port(), Exposed: exposed})
			}
			continue
		}
		ra := s.Remote.Addr()
		if !ra.IsValid() || ra.IsUnspecified() || ra.IsLoopback() || s.State == 12 {
			continue
		}
		la := a.liveApp(pi, now)
		la.Conns++
		if torRemote(s.Remote) {
			la.Tor = true
		}
		h := a.host(ra, now)
		h.Conns++
		h.Apps[pi.Key] = true
		if la.countries == nil {
			la.countries = map[string]bool{}
		}
		if h.CC != "" {
			la.countries[h.CC] = true
		}
		conns = append(conns, connView{
			Key: pi.Key, App: pi.Name, Proto: s.Proto,
			Local: s.Local.String(), Remote: s.Remote.String(), IP: ra.String(), Port: s.Remote.Port(),
			Host: h.Name, CC: h.CC, State: tcpStates[s.State],
		})
		if s.State == tcpEstablished && pi.Path != "" && pi.Key != selfPath {
			a.seeApp(pi, now)
		}
		// Escritorio remoto entrante: conexión establecida en el puerto local RDP.
		if s.State == tcpEstablished && int(s.Local.Port()) == a.rdp.Port {
			peer := ra.String()
			rdpNow[peer] = true
			if !a.rdpPeers[peer] {
				where := ""
				if h.CC != "" {
					where = " (" + h.CC + ")"
				}
				a.alert("rdp", "danger", "Conexión de Escritorio remoto",
					fmt.Sprintf("Conexión RDP entrante desde %s%s. Si no la esperabas, bloquea el Escritorio remoto en Seguridad.", peer, where), "")
			}
		}
	}
	a.rdpPeers = rdpNow
	a.rdpActive = a.rdpActive[:0]
	for p := range rdpNow {
		a.rdpActive = append(a.rdpActive, p)
	}
	// Recalcula el riesgo de cada app activa y avisa de amenazas nuevas.
	for _, la := range a.apps {
		if la.Conns > 0 || la.Listen > 0 || la.RxRate+la.TxRate > 0 {
			a.computeRisk(la)
			a.raiseThreat(la)
		}
	}
	riskByKey := map[string]int{}
	for _, la := range a.apps {
		riskByKey[la.Key] = la.Risk
	}
	for i := range listens {
		listens[i].Risk = riskByKey[listens[i].Key]
	}
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].App != conns[j].App {
			return conns[i].App < conns[j].App
		}
		return conns[i].Remote < conns[j].Remote
	})
	sort.Slice(listens, func(i, j int) bool { return listens[i].Port < listens[j].Port })
	a.conns = conns
	a.listens = listens
}

// raiseThreat avisa una vez cuando una app alcanza un nivel de riesgo nuevo.
func (a *App) raiseThreat(la *liveApp) {
	if la.Risk == 0 || a.firstRun {
		return
	}
	if a.threatSeen[la.Key] >= la.Risk {
		return
	}
	a.threatSeen[la.Key] = la.Risk
	reason := ""
	if len(la.Reasons) > 0 {
		reason = la.Reasons[0]
	}
	if la.Risk == riskDanger {
		a.alert("threat", "danger", "⚠ Programa peligroso detectado",
			la.Name+": "+reason+".\nRevísalo en Amenazas; puedes bloquearlo con un clic.", la.Key)
	} else {
		a.alert("threat", "warn", "Programa sospechoso",
			la.Name+": "+reason+".", la.Key)
	}
}

var selfPathCache string

func selfExe() string {
	if selfPathCache == "" {
		selfPathCache, _ = os.Executable()
	}
	return selfPathCache
}

// seeApp registra una app con actividad de red: alerta si es nueva o si su
// ejecutable cambió, y en modo "preguntar" la bloquea hasta que decidas.
func (a *App) seeApp(pi *procInfo, now time.Time) {
	key := pi.Key
	rec := a.cfg.Apps[key]
	if rec == nil {
		size, mt := fileStamp(pi.Path)
		rec = &AppRecord{Key: key, Path: pi.Path, Name: pi.Name, FirstSeen: now.Unix(), Size: size, ModTime: mt}
		a.cfg.Apps[key] = rec
		a.cfgDirty = true
		a.checked[key] = true
		if a.firstRun {
			return
		}
		if a.cfg.Mode == "preguntar" && (a.cfg.AskSystem || !isSystemPath(pi.Path)) && key != strings.ToLower(selfExe()) {
			a.cfg.Pending[key] = now.Unix()
			path := pi.Path
			if a.cfg.StrictBlock {
				// En modo estricto el bloqueo de salida por defecto ya impide la
				// conexión; no hace falta regla por app. Solo se pide permiso.
				a.alert("ask", "warn", "¿Permitir conexión?", pi.Name+" intenta conectarse a Internet y está bloqueado hasta que lo autorices.", key)
			} else {
				a.queueFW(func() { a.fwResult(fwBlockApp(key, path)); a.markApplied(key, path, true) })
				a.alert("ask", "warn", "¿Permitir conexión?", pi.Name+" quiere conectarse a Internet. Se ha bloqueado hasta que decidas.", key)
			}
			go a.onAsk() // trae la ventana al frente para mostrar el pop-up
			return
		}
		a.alert("newapp", "info", "Nueva app con acceso a la red", pi.Name+" se ha conectado por primera vez.\n"+pi.Path, key)
		return
	}
	if a.checked[key] {
		return
	}
	a.checked[key] = true
	size, mt := fileStamp(pi.Path)
	if size > 0 && rec.Size > 0 && (size != rec.Size || mt != rec.ModTime) {
		a.alert("appchanged", "info", "Una app ha cambiado", pi.Name+" se ha modificado o actualizado desde la última vez que se conectó.\n"+pi.Path, key)
	}
	if size > 0 && (size != rec.Size || mt != rec.ModTime || rec.Name != pi.Name) {
		rec.Size, rec.ModTime, rec.Name = size, mt, pi.Name
		a.cfgDirty = true
	}
}

func (a *App) checkPrivacy(now time.Time) {
	list := privacyStatus()
	active := map[string]bool{}
	for _, c := range list {
		if !c.Active {
			continue
		}
		k := c.Device + "|" + c.App
		active[k] = true
		if !a.privActive[k] && now.Sub(a.started) > 5*time.Second {
			name := c.App
			if c.Path != "" {
				name = strings.TrimSuffix(filepath.Base(c.Path), filepath.Ext(c.Path))
			}
			a.alert("privacy", "warn", "Uso de "+c.Device, name+" está usando la "+c.Device+".", "")
		}
	}
	a.privActive = active
	a.privacy = list
}

// checkNetwork lee la caché ARP (dispositivos de la red local) y la Wi‑Fi
// actual para detectar posibles gemelos malvados.
func (a *App) checkNetwork(now time.Time) {
	arp := readARP()
	self, gws := localNet()
	w, werr := currentWifi()

	a.mu.Lock()
	defer a.mu.Unlock()
	a.arp, a.selfIPs, a.gateways = arp, self, gws
	for _, e := range arp {
		d := a.cfg.Devices[e.MAC]
		if d == nil {
			d = &Device{MAC: e.MAC, IP: e.IP.String(), FirstSeen: now.Unix()}
			a.cfg.Devices[e.MAC] = d
			if !a.firstRun && len(a.cfg.Devices) > 1 {
				a.alert("device", "info", "Nuevo dispositivo en tu red", fmt.Sprintf("Se ha detectado un dispositivo nuevo: %s (%s).", e.IP, e.MAC), e.MAC)
			}
		}
		d.IP = e.IP.String()
		d.LastSeen = now.Unix()
		if n := a.dnsNames[d.IP]; n != "" {
			d.Host = n
		} else {
			a.resolve(d.IP)
		}
		a.cfgDirty = true
	}

	if werr != nil {
		a.wifiErr = "Sin adaptador Wi‑Fi o servicio WLAN detenido."
		a.wifi = wifiNow{}
		a.wifiStatus, a.wifiLevel = "No se usa Wi‑Fi en este equipo.", "info"
		return
	}
	a.wifiErr = ""
	a.wifi = w
	if !w.Connected {
		a.wifiStatus, a.wifiLevel = "No hay conexión Wi‑Fi activa.", "info"
		if w.Location {
			a.wifiStatus = "Windows exige permiso de ubicación para leer la red Wi‑Fi. Actívalo en Configuración › Privacidad › Ubicación para detectar gemelos malvados."
		}
		return
	}
	rec := a.cfg.Wifi[w.SSID]
	if rec == nil {
		a.cfg.Wifi[w.SSID] = &WifiRecord{SSID: w.SSID, Auth: w.Auth, BSSIDs: map[string]int64{w.BSSID: now.Unix()}}
		a.cfgDirty = true
		a.wifiStatus, a.wifiLevel = "Red registrada como conocida. Se vigilarán cambios en su punto de acceso y seguridad.", "ok"
		return
	}
	seenKey := w.SSID + "|" + w.BSSID + "|" + w.Auth
	if rec.Auth != "" && w.Auth != "" && !strings.EqualFold(rec.Auth, w.Auth) {
		a.wifiStatus, a.wifiLevel = fmt.Sprintf("¡Atención! La red «%s» usa ahora seguridad «%s» (antes «%s»). Podría ser un gemelo malvado.", w.SSID, w.Auth, rec.Auth), "danger"
		if !a.wifiSeen[seenKey] {
			a.alert("eviltwin", "danger", "Posible gemelo malvado", a.wifiStatus, w.SSID)
		}
	} else if _, ok := rec.BSSIDs[w.BSSID]; !ok {
		a.wifiStatus, a.wifiLevel = fmt.Sprintf("Punto de acceso desconocido (%s) para «%s». Si no tienes repetidores o red mesh, podría ser un gemelo malvado.", w.BSSID, w.SSID), "warn"
		if !a.wifiSeen[seenKey] {
			a.alert("eviltwin", "warn", "Punto de acceso desconocido", a.wifiStatus, w.SSID)
		}
	} else {
		rec.BSSIDs[w.BSSID] = now.Unix()
		a.wifiStatus, a.wifiLevel = "Red conocida: punto de acceso y seguridad coinciden con los registrados.", "ok"
	}
	a.wifiSeen[seenKey] = true
}

func (a *App) trustWifi() {
	w := a.wifi
	if !w.Connected {
		return
	}
	rec := a.cfg.Wifi[w.SSID]
	if rec == nil {
		rec = &WifiRecord{SSID: w.SSID, BSSIDs: map[string]int64{}}
		a.cfg.Wifi[w.SSID] = rec
	}
	rec.Auth = w.Auth
	rec.BSSIDs[w.BSSID] = time.Now().Unix()
	a.wifiStatus, a.wifiLevel = "Punto de acceso marcado como de confianza.", "ok"
	a.cfgDirty = true
}

func (a *App) checkLimit(now time.Time) {
	if a.cfg.LimitGB <= 0 {
		return
	}
	start := billingStart(now, a.cfg.BillingDay)
	rx, tx := a.hist.Period(start, now)
	used := float64(rx+tx) / 1e9
	pct := used / a.cfg.LimitGB * 100
	k := dayKey(start)
	lvl := 0
	if pct >= 100 {
		lvl = 2
	} else if pct >= 80 {
		lvl = 1
	}
	if lvl > a.cfg.LimitAlerted[k] {
		a.cfg.LimitAlerted[k] = lvl
		a.cfgDirty = true
		if lvl == 2 {
			a.alert("limit", "danger", "Límite de datos alcanzado", fmt.Sprintf("Has usado %.2f GB de %.0f GB en este periodo.", used, a.cfg.LimitGB), "")
		} else {
			a.alert("limit", "warn", "Límite de datos al 80 %", fmt.Sprintf("Has usado %.2f GB de %.0f GB en este periodo.", used, a.cfg.LimitGB), "")
		}
	}
}

// alert registra una alerta y, si corresponde, muestra una notificación discreta.
func (a *App) alert(kind, level, title, text, key string) {
	a.alertSeq++
	al := &Alert{ID: a.alertSeq, T: time.Now().Unix(), Kind: kind, Level: level, Title: title, Text: text, Key: key}
	a.alerts = append(a.alerts, al)
	if len(a.alerts) > 500 {
		a.alerts = a.alerts[len(a.alerts)-500:]
	}
	n := a.cfg.Notify
	enabled := map[string]bool{
		// "ask" NO usa notificación de Windows: se muestra como pop-up dentro de la app.
		"newapp": n.NewApp, "ask": false, "appchanged": n.AppChanged, "device": n.Devices,
		"rdp": n.RDP, "privacy": n.Privacy, "eviltwin": n.EvilTwin, "limit": n.Limit,
		"system": true, "threat": true, "adobe": n.Adobe,
	}[kind]
	if n.Balloons && enabled && time.Now().Unix() >= n.SnoozeUntil {
		notify := a.notify
		go notify(title, firstLine(text), level)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------------------------------------------------------------------------
// Resolución inversa de nombres (asíncrona y con caché).
// ---------------------------------------------------------------------------

func (a *App) resolve(ip string) {
	if _, ok := a.dnsNames[ip]; ok || a.dnsPending[ip] {
		return
	}
	a.dnsPending[ip] = true
	select {
	case a.dnsQueue <- ip:
	default:
		delete(a.dnsPending, ip)
	}
}

func (a *App) dnsWorker() {
	for ip := range a.dnsQueue {
		name := ""
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			name = strings.TrimSuffix(names[0], ".")
		}
		a.mu.Lock()
		a.dnsNames[ip] = name
		delete(a.dnsPending, ip)
		if h := a.hosts[ip]; h != nil && name != "" {
			h.Name = name
		}
		if len(a.dnsNames) > 20000 {
			a.dnsNames = map[string]string{}
		}
		a.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Operaciones de firewall (serializadas en un único hilo de trabajo).
// ---------------------------------------------------------------------------

func (a *App) queueFW(f func()) {
	select {
	case a.fwQueue <- f:
	default:
		log.Print("cola de firewall llena")
	}
}

func (a *App) fwWorker() {
	for f := range a.fwQueue {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("error de firewall: %v", r)
				}
			}()
			f()
		}()
	}
}

func (a *App) fwResult(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.fwErr = err.Error()
		log.Print(err)
	} else {
		a.fwErr = ""
	}
}

func (a *App) markApplied(key, path string, on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if on {
		a.cfg.Applied[key] = path
	} else {
		delete(a.cfg.Applied, key)
	}
	a.cfgDirty = true
}

// syncRules hace que las reglas del firewall coincidan con el perfil activo.
func (a *App) syncRules() { a.syncRulesForce(false) }

func (a *App) syncRulesForce(force bool) {
	a.mu.Lock()
	strict := a.cfg.StrictBlock && a.cfg.Mode == "preguntar"
	want := a.cfg.desiredBlocked()
	applied := map[string]string{}
	for k, v := range a.cfg.Applied {
		applied[k] = v
	}
	paths := map[string]string{}
	for k := range want {
		if r := a.cfg.Apps[k]; r != nil {
			paths[k] = r.Path
		}
	}
	// Reglas de permiso: solo en modo estricto, para apps permitidas que no estén bloqueadas.
	wantAllow := map[string]string{}
	if strict {
		for k := range a.cfg.Allowed {
			if a.cfg.isBlocked(k) {
				continue
			}
			p := a.cfg.Allowed[k]
			if p == "" {
				if r := a.cfg.Apps[k]; r != nil {
					p = r.Path
				}
			}
			if p != "" {
				wantAllow[k] = p
			}
		}
	}
	allowApplied := map[string]string{}
	for k, v := range a.allowOn {
		allowApplied[k] = v
	}
	a.mu.Unlock()

	// --- reglas de bloqueo (permanentes; sobreviven a reinicios) ---
	for k, p := range applied {
		if !want[k] {
			fwUnblockApp(k, p)
			a.markApplied(k, p, false)
		}
	}
	for k := range want {
		if _, ok := applied[k]; ok && !force {
			continue
		}
		if p := paths[k]; p != "" {
			if err := fwBlockApp(k, p); err != nil {
				a.fwResult(err)
				continue
			}
			a.markApplied(k, p, true)
		}
	}

	// --- reglas de permiso (modo estricto) ---
	for k, p := range allowApplied {
		if _, ok := wantAllow[k]; !ok {
			fwUnallowApp(k, p)
			a.markAllowed(k, p, false)
		}
	}
	for k, p := range wantAllow {
		if _, ok := allowApplied[k]; ok && !force {
			continue
		}
		if err := fwAllowApp(k, p); err != nil {
			a.fwResult(err)
			continue
		}
		a.markAllowed(k, p, true)
	}
}

// markAllowed registra qué reglas de permiso están aplicadas (solo en memoria;
// se reconstruyen al iniciar). Las DECISIONES de permiso se guardan en cfg.Allowed.
func (a *App) markAllowed(key, path string, on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if on {
		a.allowOn[key] = path
	} else {
		delete(a.allowOn, key)
	}
}

// ---------------------------------------------------------------------------
// Persistencia.
// ---------------------------------------------------------------------------

var saveMu sync.Mutex

func (a *App) saveConfig() {
	saveMu.Lock()
	defer saveMu.Unlock()
	a.mu.Lock()
	a.cfgDirty = false
	err := writeJSONAtomic(filepath.Join(a.dir, "config.json"), a.cfg)
	a.mu.Unlock()
	if err != nil {
		log.Printf("no se pudo guardar la configuración: %v", err)
	}
}

func (a *App) save(final bool) {
	a.saveConfig()
	saveMu.Lock()
	defer saveMu.Unlock()
	if err := a.hist.Save(filepath.Join(a.dir, "history.json")); err != nil {
		log.Printf("no se pudo guardar el historial: %v", err)
	}
	a.mu.Lock()
	al := append([]*Alert(nil), a.alerts...)
	a.mu.Unlock()
	writeJSONAtomic(filepath.Join(a.dir, "alerts.json"), al)
}
