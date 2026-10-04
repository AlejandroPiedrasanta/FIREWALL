//go:build windows

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed ui
var uiFS embed.FS

// Servidor HTTP local (solo 127.0.0.1) que alimenta la interfaz. Todas las
// llamadas a /api exigen un token aleatorio generado en cada inicio.

type server struct {
	app    *App
	token  string
	addr   string
	window windowCtl
}

type windowCtl interface {
	Mini(on bool)
	Hide()
}

func startServer(app *App, win windowCtl) (*server, error) {
	// En algunos equipos el registro de Windows asocia .js a text/plain, lo que
	// impediría cargar la interfaz; se fijan los tipos explícitamente.
	for ext, typ := range map[string]string{
		".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
		".html": "text/html; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
	} {
		mime.AddExtensionType(ext, typ)
	}
	b := make([]byte, 24)
	rand.Read(b)
	s := &server{app: app, token: hex.EncodeToString(b), window: win}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.addr = ln.Addr().String()
	sub, _ := fs.Sub(uiFS, "ui")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/", s.api)
	srv := &http.Server{Handler: s.guard(mux), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	return s, nil
}

func (s *server) URL() string { return "http://" + s.addr + "/?t=" + s.token }

// guard evita accesos desde otros orígenes (DNS rebinding, otras webs).
func (s *server) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.addr {
			http.Error(w, "host no permitido", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			tok := r.Header.Get("X-Token")
			if r.URL.Path == "/api/icon" && tok == "" {
				tok = r.URL.Query().Get("t")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
				http.Error(w, "token inválido", http.StatusUnauthorized)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

type req struct {
	Key    string          `json:"key"`
	Block  bool            `json:"block"`
	Allow  bool            `json:"allow"`
	Mode   string          `json:"mode"`
	Action string          `json:"action"`
	Name   string          `json:"name"`
	New    string          `json:"newName"`
	MAC    string          `json:"mac"`
	On     bool            `json:"on"`
	Config json.RawMessage `json:"config"`
	IDs    []int64         `json:"ids"`
}

func (s *server) api(w http.ResponseWriter, r *http.Request) {
	var body req
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
	}
	a := s.app
	q := r.URL.Query()
	switch strings.TrimPrefix(r.URL.Path, "/api/") {
	case "state":
		writeJSON(w, a.State())
	case "history":
		writeJSON(w, a.HistoryView(q.Get("range"), q.Get("day")))
	case "hour":
		t, _ := strconv.ParseInt(q.Get("t"), 10, 64)
		writeJSON(w, a.hist.AppsBetween(t, t+3599, 30))
	case "usage":
		off, _ := strconv.Atoi(q.Get("offset"))
		writeJSON(w, a.UsageView(q.Get("period"), off))
	case "conns":
		writeJSON(w, a.ConnsView())
	case "lan":
		writeJSON(w, a.LanView())
	case "security":
		writeJSON(w, a.SecurityView())
	case "system":
		writeJSON(w, a.SystemView())
	case "alerts":
		a.mu.Lock()
		al := make([]*Alert, len(a.alerts))
		for i := range a.alerts {
			c := *a.alerts[len(a.alerts)-1-i]
			al[i] = &c
		}
		a.mu.Unlock()
		writeJSON(w, al)
	case "alerts/read":
		a.mu.Lock()
		for _, al := range a.alerts {
			al.Read = true
		}
		a.mu.Unlock()
		writeJSON(w, "ok")
	case "alerts/clear":
		a.mu.Lock()
		a.alerts = nil
		a.mu.Unlock()
		writeJSON(w, "ok")
	case "config":
		if r.Method == http.MethodPost {
			if err := a.UpdateConfig(body.Config); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		a.mu.Lock()
		b, _ := json.Marshal(a.cfg)
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case "block":
		writeJSON(w, a.SetBlocked(body.Key, body.Block))
	case "ask":
		writeJSON(w, a.Answer(body.Key, body.Allow))
	case "mode":
		writeJSON(w, a.SetMode(body.Mode))
	case "profile":
		if err := a.ProfileAction(body.Action, body.Name, body.New); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, "ok")
	case "rdp":
		a.mu.Lock()
		a.cfg.RDPBlocked = body.On
		a.cfgDirty = true
		port := a.rdp.Port
		a.mu.Unlock()
		a.queueFW(func() { a.fwResult(fwBlockRDP(body.On, port)) })
		writeJSON(w, "ok")
	case "rules/clear":
		a.ClearAll()
		writeJSON(w, "ok")
	case "firewall/enable":
		a.queueFW(func() { a.fwResult(fwEnable()) })
		writeJSON(w, "ok")
	case "device":
		a.mu.Lock()
		if d := a.cfg.Devices[body.MAC]; d != nil {
			d.Name = strings.TrimSpace(body.Name)
			a.cfgDirty = true
		}
		a.mu.Unlock()
		writeJSON(w, "ok")
	case "device/forget":
		a.mu.Lock()
		delete(a.cfg.Devices, body.MAC)
		a.cfgDirty = true
		a.mu.Unlock()
		writeJSON(w, "ok")
	case "wifi/trust":
		a.mu.Lock()
		a.trustWifi()
		a.mu.Unlock()
		writeJSON(w, "ok")
	case "snooze":
		mins, _ := strconv.Atoi(body.Name)
		a.mu.Lock()
		if mins <= 0 {
			a.cfg.Notify.SnoozeUntil = 0
		} else {
			a.cfg.Notify.SnoozeUntil = time.Now().Add(time.Duration(mins) * time.Minute).Unix()
		}
		a.cfgDirty = true
		a.mu.Unlock()
		writeJSON(w, "ok")
	case "window":
		switch body.Action {
		case "mini":
			s.window.Mini(true)
		case "normal":
			s.window.Mini(false)
		case "hide":
			s.window.Hide()
		}
		writeJSON(w, "ok")
	case "icon":
		path := q.Get("p")
		a.mu.Lock()
		_, known := a.cfg.Apps[strings.ToLower(path)]
		if la := a.apps[strings.ToLower(path)]; la != nil {
			known = true
		}
		a.mu.Unlock()
		var png []byte
		if known {
			png = icons.Get(path)
		}
		if png == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "max-age=86400")
		w.Write(png)
	default:
		http.NotFound(w, r)
	}
}

// ---------------------------------------------------------------------------
// Vistas de datos para la interfaz.
// ---------------------------------------------------------------------------

type appView struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	RxRate  uint64 `json:"rxRate"`
	TxRate  uint64 `json:"txRate"`
	TodayRx uint64 `json:"todayRx"`
	TodayTx uint64 `json:"todayTx"`
	Conns   int    `json:"conns"`
	Blocked bool   `json:"blocked"`
	Pending bool   `json:"pending"`
	CanFW   bool   `json:"canFw"`
	System  bool   `json:"system"`
	Active  bool   `json:"active"`
	First   int64  `json:"first"`
}

type stateView struct {
	Now      int64      `json:"now"`
	Secs     [][3]int64 `json:"secs"`
	Apps     []appView  `json:"apps"`
	Mode     string     `json:"mode"`
	Profile  string     `json:"profile"`
	Profiles []string   `json:"profiles"`
	Unread   int        `json:"unread"`
	Latest   *Alert     `json:"latest"`
	TodayRx  uint64     `json:"todayRx"`
	TodayTx  uint64     `json:"todayTx"`
	ETW      bool       `json:"etw"`
	ETWErr   string     `json:"etwErr"`
	FWErr    string     `json:"fwErr"`
	CPU      float64    `json:"cpu"`
	Mem      float64    `json:"mem"`
	Theme    string     `json:"theme"`
	Snoozed  bool       `json:"snoozed"`
	Conns    int        `json:"conns"`
	Hosts    int        `json:"hosts"`
	Version  string     `json:"version"`
}

func (a *App) appViews(today map[string]u2) []appView {
	keys := map[string]bool{}
	for k := range a.apps {
		keys[k] = true
	}
	for k := range today {
		keys[k] = true
	}
	for k := range a.cfg.Pending {
		keys[k] = true
	}
	if p := a.cfg.active(); p != nil {
		for _, k := range p.Blocked {
			keys[k] = true
		}
	}
	out := make([]appView, 0, len(keys))
	for k := range keys {
		v := appView{Key: k, Blocked: a.cfg.isBlocked(k)}
		_, v.Pending = a.cfg.Pending[k]
		if la := a.apps[k]; la != nil {
			v.Name, v.Path, v.RxRate, v.TxRate, v.Conns = la.Name, la.Path, la.RxRate, la.TxRate, la.Conns
			v.Active = la.Conns > 0 || la.RxRate+la.TxRate > 0
		}
		if r := a.cfg.Apps[k]; r != nil {
			if v.Path == "" {
				v.Path = r.Path
			}
			if v.Name == "" {
				v.Name = r.Name
			}
			v.First = r.FirstSeen
		}
		if v.Name == "" {
			v.Name = a.hist.Names[k]
		}
		if v.Name == "" {
			v.Name = k
		}
		if t, ok := today[k]; ok {
			v.TodayRx, v.TodayTx = t[0], t[1]
		}
		v.CanFW = v.Path != ""
		v.System = v.Path == "" || isSystemPath(v.Path)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := out[i].RxRate+out[i].TxRate, out[j].RxRate+out[j].TxRate
		if ri != rj {
			return ri > rj
		}
		ti, tj := out[i].TodayRx+out[i].TodayTx, out[j].TodayRx+out[j].TodayTx
		if ti != tj {
			return ti > tj
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func (a *App) State() stateView {
	today := a.hist.DayApps(time.Now())
	a.hist.mu.Lock()
	var trx, ttx uint64
	if d := a.hist.Daily[dayKey(time.Now())]; d != nil {
		trx, ttx = d.Rx, d.Tx
	}
	a.hist.mu.Unlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	v := stateView{
		Now: time.Now().Unix(), Mode: a.cfg.Mode, Profile: a.cfg.Profile, TodayRx: trx, TodayTx: ttx,
		ETW: a.etw != nil && a.etw.Active, FWErr: a.fwErr, Theme: a.cfg.Theme,
		Snoozed: a.cfg.Notify.SnoozeUntil > time.Now().Unix(), Conns: len(a.conns), Version: version,
	}
	if a.etw != nil && a.etw.Err != nil {
		v.ETWErr = a.etw.Err.Error()
	}
	n := len(a.secs)
	start := n - 600
	if start < 0 {
		start = 0
	}
	for _, s := range a.secs[start:] {
		v.Secs = append(v.Secs, [3]int64{s.T, s.Rx, s.Tx})
	}
	v.Apps = a.appViews(today)
	if len(v.Apps) > 300 {
		v.Apps = v.Apps[:300]
	}
	for _, p := range a.cfg.Profiles {
		v.Profiles = append(v.Profiles, p.Name)
	}
	for _, al := range a.alerts {
		if !al.Read {
			v.Unread++
		}
	}
	if len(a.alerts) > 0 {
		c := *a.alerts[len(a.alerts)-1]
		v.Latest = &c
	}
	if len(a.cpuHist) > 0 {
		v.CPU = a.cpuHist[len(a.cpuHist)-1]
		v.Mem = a.memHist[len(a.memHist)-1]
	}
	for _, h := range a.hosts {
		if h.Conns > 0 {
			v.Hosts++
		}
	}
	return v
}

type historyView struct {
	From   int64         `json:"from"`
	To     int64         `json:"to"`
	Step   int64         `json:"step"`
	Points []seriesPoint `json:"points"`
	Apps   []usageItem   `json:"apps"`
}

func (a *App) HistoryView(rng, day string) historyView {
	now := time.Now()
	var from, to time.Time
	to = now
	switch rng {
	case "1h":
		from = now.Add(-time.Hour)
	case "7d":
		from = now.AddDate(0, 0, -7)
	case "30d":
		from = now.AddDate(0, 0, -30)
	default:
		from = now.Add(-24 * time.Hour)
	}
	if day != "" {
		if d, err := time.ParseInLocation("2006-01-02", day, time.Local); err == nil {
			from, to = d, d.Add(24*time.Hour-time.Second)
		}
	}
	span := to.Unix() - from.Unix()
	step := int64(60)
	for span/step > 720 {
		step *= 2
	}
	step = (step + 59) / 60 * 60
	v := historyView{From: from.Unix(), To: to.Unix(), Step: step}
	v.Points = a.hist.Series(from.Unix(), to.Unix(), step)
	v.Apps = a.hist.AppsBetween(from.Unix(), to.Unix(), 30)
	return v
}

type usageView struct {
	Label     string      `json:"label"`
	From      string      `json:"from"`
	To        string      `json:"to"`
	Days      []dayTotal  `json:"days"`
	Apps      []usageItem `json:"apps"`
	Hosts     []usageItem `json:"hosts"`
	Countries []usageItem `json:"countries"`
	Rx        uint64      `json:"rx"`
	Tx        uint64      `json:"tx"`
	LimitGB   float64     `json:"limitGB"`
	PeriodRx  uint64      `json:"periodRx"`
	PeriodTx  uint64      `json:"periodTx"`
	PeriodEnd string      `json:"periodEnd"`
}

func (a *App) UsageView(period string, offset int) usageView {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	var from, to time.Time
	switch period {
	case "day":
		from = today.AddDate(0, 0, offset)
		to = from
	case "month":
		from = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, offset, 0)
		to = from.AddDate(0, 1, -1)
	default: // semana (lunes a domingo)
		wd := (int(today.Weekday()) + 6) % 7
		from = today.AddDate(0, 0, -wd+7*offset)
		to = from.AddDate(0, 0, 6)
	}
	v := usageView{From: dayKey(from), To: dayKey(to)}
	v.Days, v.Apps, v.Hosts, v.Countries = a.hist.Days(from, to)
	for _, d := range v.Days {
		v.Rx += d.Rx
		v.Tx += d.Tx
	}
	a.mu.Lock()
	v.LimitGB = a.cfg.LimitGB
	bd := a.cfg.BillingDay
	a.mu.Unlock()
	if v.LimitGB > 0 {
		ps := billingStart(now, bd)
		v.PeriodRx, v.PeriodTx = a.hist.Period(ps, now)
		v.PeriodEnd = dayKey(ps.AddDate(0, 1, -1))
	}
	return v
}

type hostView struct {
	IP    string   `json:"ip"`
	Name  string   `json:"name"`
	CC    string   `json:"cc"`
	Apps  []string `json:"apps"`
	Rx    uint64   `json:"rx"`
	Tx    uint64   `json:"tx"`
	Conns int      `json:"conns"`
	First int64    `json:"first"`
	Last  int64    `json:"last"`
}

type connsResp struct {
	Conns   []connView   `json:"conns"`
	Hosts   []hostView   `json:"hosts"`
	Listens []listenView `json:"listens"`
}

func (a *App) ConnsView() connsResp {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := connsResp{Conns: a.conns, Listens: a.listens}
	for _, h := range a.hosts {
		hv := hostView{IP: h.IP, Name: h.Name, CC: h.CC, Rx: h.Rx, Tx: h.Tx, Conns: h.Conns, First: h.FirstSeen, Last: h.LastSeen}
		for k := range h.Apps {
			name := k
			if la := a.apps[k]; la != nil {
				name = la.Name
			} else if rec := a.cfg.Apps[k]; rec != nil {
				name = rec.Name
			}
			hv.Apps = append(hv.Apps, name)
		}
		sort.Strings(hv.Apps)
		r.Hosts = append(r.Hosts, hv)
	}
	sort.Slice(r.Hosts, func(i, j int) bool {
		if r.Hosts[i].Conns != r.Hosts[j].Conns {
			return r.Hosts[i].Conns > r.Hosts[j].Conns
		}
		return r.Hosts[i].Rx+r.Hosts[i].Tx > r.Hosts[j].Rx+r.Hosts[j].Tx
	})
	if r.Conns == nil {
		r.Conns = []connView{}
	}
	return r
}

type deviceView struct {
	Device
	Online  bool `json:"online"`
	Self    bool `json:"self"`
	Gateway bool `json:"gateway"`
	Random  bool `json:"random"`
}

type lanResp struct {
	Devices    []deviceView `json:"devices"`
	Wifi       wifiNow      `json:"wifi"`
	WifiStatus string       `json:"wifiStatus"`
	WifiLevel  string       `json:"wifiLevel"`
	WifiErr    string       `json:"wifiErr"`
	Ifaces     []ifaceInfo  `json:"ifaces"`
}

func (a *App) LanView() lanResp {
	a.mu.Lock()
	defer a.mu.Unlock()
	online := map[string]bool{}
	for _, e := range a.arp {
		online[e.MAC] = true
	}
	r := lanResp{Wifi: a.wifi, WifiStatus: a.wifiStatus, WifiLevel: a.wifiLevel, WifiErr: a.wifiErr}
	for ip, mac := range a.selfIPs {
		if strings.Contains(ip, ":") || mac == "" {
			continue
		}
		r.Devices = append(r.Devices, deviceView{Device: Device{MAC: mac, IP: ip, Name: "Este equipo", LastSeen: time.Now().Unix()}, Online: true, Self: true})
	}
	cut := time.Now().Add(-30 * 24 * time.Hour).Unix()
	for _, d := range a.cfg.Devices {
		if d.LastSeen < cut {
			continue
		}
		dv := deviceView{Device: *d, Online: online[d.MAC], Gateway: a.gateways[d.IP]}
		if b := parseMAC0(d.MAC); b&0x02 != 0 {
			dv.Random = true
		}
		r.Devices = append(r.Devices, dv)
	}
	sort.Slice(r.Devices, func(i, j int) bool {
		di, dj := r.Devices[i], r.Devices[j]
		if di.Self != dj.Self {
			return di.Self
		}
		if di.Gateway != dj.Gateway {
			return di.Gateway
		}
		if di.Online != dj.Online {
			return di.Online
		}
		return di.IP < dj.IP
	})
	for _, i := range a.ifaces {
		if i.hw && !i.filter {
			r.Ifaces = append(r.Ifaces, i)
		}
	}
	return r
}

func parseMAC0(mac string) byte {
	if len(mac) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(mac[:2], 16, 8)
	return byte(v)
}

type securityResp struct {
	Firewall   []fwProfileState `json:"firewall"`
	Mode       string           `json:"mode"`
	RDP        rdpStatus        `json:"rdp"`
	RDPBlocked bool             `json:"rdpBlocked"`
	RDPActive  []string         `json:"rdpActive"`
	Privacy    []capUse         `json:"privacy"`
	WifiStatus string           `json:"wifiStatus"`
	WifiLevel  string           `json:"wifiLevel"`
	Listens    []listenView     `json:"listens"`
	ETW        bool             `json:"etw"`
	FWErr      string           `json:"fwErr"`
	Apps       int              `json:"apps"`
	Blocked    int              `json:"blocked"`
}

func (a *App) SecurityView() securityResp {
	fw := firewallState()
	a.mu.Lock()
	defer a.mu.Unlock()
	r := securityResp{
		Firewall: fw, Mode: a.cfg.Mode, RDP: a.rdp, RDPBlocked: a.cfg.RDPBlocked, RDPActive: a.rdpActive,
		Privacy: a.privacy, WifiStatus: a.wifiStatus, WifiLevel: a.wifiLevel, Listens: a.listens,
		ETW: a.etw != nil && a.etw.Active, FWErr: a.fwErr, Apps: len(a.cfg.Apps), Blocked: len(a.cfg.desiredBlocked()),
	}
	if len(r.Privacy) > 30 {
		r.Privacy = r.Privacy[:30]
	}
	return r
}

type systemResp struct {
	CPU      []float64   `json:"cpu"`
	Mem      []float64   `json:"mem"`
	MemUsed  uint64      `json:"memUsed"`
	MemTotal uint64      `json:"memTotal"`
	Disks    []diskInfo  `json:"disks"`
	Uptime   int64       `json:"uptime"`
	Ifaces   []ifaceInfo `json:"ifaces"`
	Host     string      `json:"host"`
	Procs    int         `json:"procs"`
}

func (a *App) SystemView() systemResp {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := systemResp{CPU: a.cpuHist, Mem: a.memHist, MemUsed: a.memUsed, MemTotal: a.memTotal, Disks: a.disks, Uptime: int64(uptime().Seconds())}
	r.Host, _ = osHostname()
	for _, i := range a.ifaces {
		if i.hw && !i.filter {
			r.Ifaces = append(r.Ifaces, i)
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Acciones.
// ---------------------------------------------------------------------------

func (a *App) SetBlocked(key string, block bool) string {
	a.mu.Lock()
	rec := a.cfg.Apps[key]
	path := ""
	if rec != nil {
		path = rec.Path
	} else if la := a.apps[key]; la != nil {
		path = la.Path
		if path != "" {
			a.cfg.Apps[key] = &AppRecord{Key: key, Path: path, Name: la.Name, FirstSeen: time.Now().Unix()}
		}
	}
	if path == "" {
		a.mu.Unlock()
		return "Esta app no se puede bloquear (no tiene ejecutable propio)."
	}
	a.cfg.setBlocked(key, block)
	if !block {
		delete(a.cfg.Pending, key)
	}
	a.cfgDirty = true
	a.mu.Unlock()
	a.queueFW(a.syncRules)
	return "ok"
}

// Answer responde a una solicitud de "preguntar antes de conectar".
func (a *App) Answer(key string, allow bool) string {
	a.mu.Lock()
	delete(a.cfg.Pending, key)
	a.cfg.setBlocked(key, !allow)
	a.cfgDirty = true
	a.mu.Unlock()
	a.queueFW(a.syncRules)
	return "ok"
}

func (a *App) SetMode(mode string) string {
	if mode != "monitor" && mode != "preguntar" && mode != "bloquear" {
		return "modo no válido"
	}
	a.mu.Lock()
	prev := a.cfg.Mode
	a.cfg.Mode = mode
	a.cfgDirty = true
	a.mu.Unlock()
	if prev == mode {
		return "ok"
	}
	a.queueFW(func() {
		if mode == "bloquear" {
			a.fwResult(fwBlockAll(true))
		} else if prev == "bloquear" {
			a.fwResult(fwBlockAll(false))
		}
	})
	return "ok"
}

func (a *App) ProfileAction(action, name, newName string) error {
	name = strings.TrimSpace(name)
	newName = strings.TrimSpace(newName)
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.cfg
	switch action {
	case "switch":
		if c.profile(name) == nil {
			return errText("perfil no encontrado")
		}
		c.Profile = name
	case "create":
		if name == "" || len(name) > 40 || c.profile(name) != nil {
			return errText("nombre no válido o repetido")
		}
		// El perfil nuevo parte de las reglas del perfil activo.
		var blocked []string
		if p := c.active(); p != nil {
			blocked = append(blocked, p.Blocked...)
		}
		c.Profiles = append(c.Profiles, &Profile{Name: name, Blocked: blocked})
		c.Profile = name
	case "rename":
		p := c.profile(name)
		if p == nil || newName == "" || len(newName) > 40 || c.profile(newName) != nil {
			return errText("nombre no válido o repetido")
		}
		if c.Profile == name {
			c.Profile = newName
		}
		p.Name = newName
	case "delete":
		if len(c.Profiles) <= 1 {
			return errText("debe quedar al menos un perfil")
		}
		out := c.Profiles[:0]
		for _, p := range c.Profiles {
			if p.Name != name {
				out = append(out, p)
			}
		}
		c.Profiles = out
		if c.profile(c.Profile) == nil {
			c.Profile = c.Profiles[0].Name
		}
	default:
		return errText("acción no válida")
	}
	a.cfgDirty = true
	a.queueFW(a.syncRules)
	return nil
}

type errText string

func (e errText) Error() string { return string(e) }

// UpdateConfig aplica solo los campos de ajustes que la interfaz puede cambiar.
func (a *App) UpdateConfig(raw json.RawMessage) error {
	var in struct {
		Theme       *string    `json:"theme"`
		Notify      *NotifyCfg `json:"notify"`
		LimitGB     *float64   `json:"limitGB"`
		BillingDay  *int       `json:"billingDay"`
		Retention   *int       `json:"retention"`
		CloseToTray *bool      `json:"closeToTray"`
		AskSystem   *bool      `json:"askSystem"`
		Autostart   *bool      `json:"autostart"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.cfg
	if in.Theme != nil {
		switch *in.Theme {
		case "oscuro", "claro", "medianoche", "grafito", "bosque":
			c.Theme = *in.Theme
		}
	}
	if in.Notify != nil {
		snooze := c.Notify.SnoozeUntil
		c.Notify = *in.Notify
		c.Notify.SnoozeUntil = snooze
	}
	if in.LimitGB != nil && *in.LimitGB >= 0 && *in.LimitGB < 1e6 {
		c.LimitGB = *in.LimitGB
	}
	if in.BillingDay != nil {
		c.BillingDay = *in.BillingDay
	}
	if in.Retention != nil {
		c.Retention = *in.Retention
	}
	if in.CloseToTray != nil {
		c.CloseToTray = *in.CloseToTray
	}
	if in.AskSystem != nil {
		c.AskSystem = *in.AskSystem
	}
	if in.Autostart != nil && *in.Autostart != c.Autostart {
		on := *in.Autostart
		c.Autostart = on
		dir := a.dir
		a.queueFW(func() { a.fwResult(setAutostart(on, dir)) })
	}
	c.normalize()
	a.hist.retention = c.Retention
	a.cfgDirty = true
	return nil
}
