package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Configuración persistente (%APPDATA%\MiniWall\config.json).
// ---------------------------------------------------------------------------

type AppRecord struct {
	Key       string `json:"key"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	FirstSeen int64  `json:"firstSeen"`
	Size      int64  `json:"size"`
	ModTime   int64  `json:"modTime"`
}

type Profile struct {
	Name    string   `json:"name"`
	Blocked []string `json:"blocked"`
}

type Device struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	FirstSeen int64  `json:"firstSeen"`
	LastSeen  int64  `json:"lastSeen"`
}

type WifiRecord struct {
	SSID   string           `json:"ssid"`
	Auth   string           `json:"auth"`
	BSSIDs map[string]int64 `json:"bssids"`
}

type NotifyCfg struct {
	Balloons    bool  `json:"balloons"`
	SnoozeUntil int64 `json:"snoozeUntil"`
	NewApp      bool  `json:"newApp"`
	AppChanged  bool  `json:"appChanged"`
	Devices     bool  `json:"devices"`
	RDP         bool  `json:"rdp"`
	Privacy     bool  `json:"privacy"`
	EvilTwin    bool  `json:"evilTwin"`
	Limit       bool  `json:"limit"`
	Adobe       bool  `json:"adobe"`
	Threat      bool  `json:"threat"`
}

type Config struct {
	Theme        string                 `json:"theme"`
	Mode         string                 `json:"mode"` // monitor | preguntar | bloquear
	Profile      string                 `json:"profile"`
	Profiles     []*Profile             `json:"profiles"`
	Apps         map[string]*AppRecord  `json:"apps"`
	Pending      map[string]int64       `json:"pending"`
	Applied      map[string]string      `json:"applied"` // reglas creadas: clave → ruta
	RDPBlocked   bool                   `json:"rdpBlocked"`
	Notify       NotifyCfg              `json:"notify"`
	LimitGB      float64                `json:"limitGB"`
	BillingDay   int                    `json:"billingDay"`
	LimitAlerted map[string]int         `json:"limitAlerted"`
	Retention    int                    `json:"retention"`
	CloseToTray  bool                   `json:"closeToTray"`
	AskSystem    bool                   `json:"askSystem"`
	Autostart    bool                   `json:"autostart"`
	StrictBlock  bool                   `json:"strictBlock"` // bloqueo por defecto de salida en modo preguntar
	Guard        bool                   `json:"guard"`       // reaplica reglas y reactiva el firewall periódicamente
	Simple       bool                   `json:"simple"`      // modo ultra simple (solo Firewall y Amenazas)
	Installed    bool                   `json:"installed"`   // instalado en el equipo
	Allowed      map[string]string      `json:"allowed"`     // reglas de permiso creadas (modo estricto): clave → ruta
	Devices      map[string]*Device     `json:"devices"`
	Wifi         map[string]*WifiRecord `json:"wifi"`
}

func defaultConfig() *Config {
	return &Config{
		Theme: "oscuro",
		// Por defecto se pregunta antes de dejar conectar cualquier programa nuevo:
		// MiniWall es el filtro principal de acceso a Internet.
		Mode:        "preguntar",
		Profile:     "Normal",
		Profiles:    []*Profile{{Name: "Normal"}, {Name: "Wi-Fi pública"}, {Name: "Juegos"}},
		Notify:      NotifyCfg{Balloons: true, NewApp: true, AppChanged: true, Devices: true, RDP: true, Privacy: true, EvilTwin: true, Limit: true, Adobe: true, Threat: true},
		BillingDay:  1,
		Retention:   30,
		CloseToTray: true,
		Guard:       true,
	}
}

func (c *Config) normalize() {
	d := defaultConfig()
	if c.Theme == "" {
		c.Theme = d.Theme
	}
	if c.Mode == "" {
		c.Mode = d.Mode
	}
	if len(c.Profiles) == 0 {
		c.Profiles = d.Profiles
	}
	if c.profile(c.Profile) == nil {
		c.Profile = c.Profiles[0].Name
	}
	if c.Apps == nil {
		c.Apps = map[string]*AppRecord{}
	}
	if c.Pending == nil {
		c.Pending = map[string]int64{}
	}
	if c.Applied == nil {
		c.Applied = map[string]string{}
	}
	if c.Allowed == nil {
		c.Allowed = map[string]string{}
	}
	if c.Devices == nil {
		c.Devices = map[string]*Device{}
	}
	if c.Wifi == nil {
		c.Wifi = map[string]*WifiRecord{}
	}
	if c.LimitAlerted == nil {
		c.LimitAlerted = map[string]int{}
	}
	if c.BillingDay < 1 || c.BillingDay > 28 {
		c.BillingDay = 1
	}
	if c.Retention < 1 {
		c.Retention = 30
	}
	if c.Retention > 365 {
		c.Retention = 365
	}
}

func (c *Config) profile(name string) *Profile {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func (c *Config) active() *Profile { return c.profile(c.Profile) }

func (c *Config) isAllowed(key string) bool { _, ok := c.Allowed[key]; return ok }

// desiredBlocked: apps que deben tener regla de bloqueo ahora mismo.
func (c *Config) desiredBlocked() map[string]bool {
	m := map[string]bool{}
	if p := c.active(); p != nil {
		for _, k := range p.Blocked {
			m[k] = true
		}
	}
	for k := range c.Pending {
		m[k] = true
	}
	return m
}

func (c *Config) isBlocked(key string) bool {
	if _, ok := c.Pending[key]; ok {
		return true
	}
	if p := c.active(); p != nil {
		for _, k := range p.Blocked {
			if k == key {
				return true
			}
		}
	}
	return false
}

func (c *Config) setBlocked(key string, block bool) {
	p := c.active()
	if p == nil {
		return
	}
	out := p.Blocked[:0]
	for _, k := range p.Blocked {
		if k != key {
			out = append(out, k)
		}
	}
	p.Blocked = out
	if block {
		p.Blocked = append(p.Blocked, key)
	}
}

func writeJSONAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---------------------------------------------------------------------------
// Historial de tráfico ("máquina del tiempo"): muestras por minuto, uso por
// hora y app, y resúmenes diarios con apps, hosts y países.
// ---------------------------------------------------------------------------

type u2 = [2]uint64 // {recibido, enviado}

type HostDay struct {
	Rx   uint64 `json:"rx"`
	Tx   uint64 `json:"tx"`
	CC   string `json:"cc,omitempty"`
	Name string `json:"name,omitempty"`
}

type DayUsage struct {
	Rx        uint64              `json:"rx"`
	Tx        uint64              `json:"tx"`
	Apps      map[string]*u2      `json:"apps"`
	Hosts     map[string]*HostDay `json:"hosts"`
	Countries map[string]*u2      `json:"countries"`
}

type History struct {
	mu        sync.Mutex
	Minutes   [][3]int64               `json:"minutes"` // {unix-minuto, rx, tx}
	Hourly    map[int64]map[string]*u2 `json:"hourly"`  // unix-hora → app → bytes
	Daily     map[string]*DayUsage     `json:"daily"`
	Names     map[string]string        `json:"names"` // app → nombre visible
	retention int
}

const maxHostsPerDay = 1500

func newHistory() *History {
	return &History{Hourly: map[int64]map[string]*u2{}, Daily: map[string]*DayUsage{}, Names: map[string]string{}, retention: 30}
}

func dayKey(t time.Time) string { return t.Format("2006-01-02") }

func (h *History) day(t time.Time) *DayUsage {
	k := dayKey(t)
	d := h.Daily[k]
	if d == nil {
		d = &DayUsage{}
		h.Daily[k] = d
	}
	if d.Apps == nil {
		d.Apps = map[string]*u2{}
	}
	if d.Hosts == nil {
		d.Hosts = map[string]*HostDay{}
	}
	if d.Countries == nil {
		d.Countries = map[string]*u2{}
	}
	return d
}

func add2(m map[string]*u2, k string, rx, tx uint64) {
	v := m[k]
	if v == nil {
		v = &u2{}
		m[k] = v
	}
	v[0] += rx
	v[1] += tx
}

// AddTotals suma bytes de interfaz al minuto y al día actuales.
func (h *History) AddTotals(now time.Time, rx, tx uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := now.Unix() / 60 * 60
	if n := len(h.Minutes); n > 0 && h.Minutes[n-1][0] == m {
		h.Minutes[n-1][1] += int64(rx)
		h.Minutes[n-1][2] += int64(tx)
	} else {
		h.Minutes = append(h.Minutes, [3]int64{m, int64(rx), int64(tx)})
	}
	d := h.day(now)
	d.Rx += rx
	d.Tx += tx
}

func (h *History) AddApp(now time.Time, key, name string, rx, tx uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hr := now.Unix() / 3600 * 3600
	m := h.Hourly[hr]
	if m == nil {
		m = map[string]*u2{}
		h.Hourly[hr] = m
	}
	add2(m, key, rx, tx)
	add2(h.day(now).Apps, key, rx, tx)
	if name != "" {
		h.Names[key] = name
	}
}

func (h *History) AddHost(now time.Time, ip, cc, name string, rx, tx uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.day(now)
	hd := d.Hosts[ip]
	if hd == nil {
		if len(d.Hosts) >= maxHostsPerDay {
			ip = "otros"
			hd = d.Hosts[ip]
		}
		if hd == nil {
			hd = &HostDay{CC: cc}
			d.Hosts[ip] = hd
		}
	}
	hd.Rx += rx
	hd.Tx += tx
	if name != "" && ip != "otros" {
		hd.Name = name
	}
	if cc != "" {
		add2(d.Countries, cc, rx, tx)
	}
}

// Prune elimina datos más antiguos que la retención configurada.
func (h *History) Prune(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	minuteDays := h.retention
	if minuteDays > 90 {
		minuteDays = 90 // la resolución por minuto se limita a 90 días
	}
	cut := now.Add(-time.Duration(minuteDays) * 24 * time.Hour).Unix()
	i := sort.Search(len(h.Minutes), func(i int) bool { return h.Minutes[i][0] >= cut })
	if i > 0 {
		h.Minutes = append([][3]int64(nil), h.Minutes[i:]...)
	}
	hcut := now.Add(-time.Duration(h.retention) * 24 * time.Hour).Unix()
	for k := range h.Hourly {
		if k < hcut {
			delete(h.Hourly, k)
		}
	}
	dcut := dayKey(now.AddDate(0, 0, -400))
	for k := range h.Daily {
		if k < dcut {
			delete(h.Daily, k)
		}
	}
}

type seriesPoint struct {
	T  int64  `json:"t"`
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

// Series agrega las muestras por minuto entre from y to en buckets de step segundos.
func (h *History) Series(from, to, step int64) []seriesPoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	if step < 60 {
		step = 60
	}
	from = from / step * step
	n := int((to-from)/step) + 1
	if n <= 0 || n > 5000 {
		return nil
	}
	out := make([]seriesPoint, n)
	for i := range out {
		out[i].T = from + int64(i)*step
	}
	i := sort.Search(len(h.Minutes), func(i int) bool { return h.Minutes[i][0] >= from })
	for ; i < len(h.Minutes) && h.Minutes[i][0] <= to; i++ {
		b := int((h.Minutes[i][0] - from) / step)
		if b >= 0 && b < n {
			out[b].Rx += uint64(h.Minutes[i][1])
			out[b].Tx += uint64(h.Minutes[i][2])
		}
	}
	return out
}

type usageItem struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	CC   string `json:"cc,omitempty"`
	Rx   uint64 `json:"rx"`
	Tx   uint64 `json:"tx"`
}

func sortUsage(items []usageItem, limit int) []usageItem {
	sort.Slice(items, func(i, j int) bool { return items[i].Rx+items[i].Tx > items[j].Rx+items[j].Tx })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

// AppsBetween suma el uso por app de las horas entre from y to.
func (h *History) AppsBetween(from, to int64, limit int) []usageItem {
	h.mu.Lock()
	defer h.mu.Unlock()
	acc := map[string]*u2{}
	for hr, m := range h.Hourly {
		if hr+3600 <= from || hr > to {
			continue
		}
		for k, v := range m {
			add2(acc, k, v[0], v[1])
		}
	}
	var items []usageItem
	for k, v := range acc {
		items = append(items, usageItem{Key: k, Name: h.Names[k], Rx: v[0], Tx: v[1]})
	}
	return sortUsage(items, limit)
}

type dayTotal struct {
	Day string `json:"day"`
	Rx  uint64 `json:"rx"`
	Tx  uint64 `json:"tx"`
}

// Days devuelve totales diarios y el uso agregado por app/host/país del rango.
func (h *History) Days(from, to time.Time) (days []dayTotal, apps, hosts, countries []usageItem) {
	h.mu.Lock()
	defer h.mu.Unlock()
	aa, ca := map[string]*u2{}, map[string]*u2{}
	ha := map[string]*HostDay{}
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		k := dayKey(d)
		du := h.Daily[k]
		if du == nil {
			days = append(days, dayTotal{Day: k})
			continue
		}
		days = append(days, dayTotal{Day: k, Rx: du.Rx, Tx: du.Tx})
		for a, v := range du.Apps {
			add2(aa, a, v[0], v[1])
		}
		for c, v := range du.Countries {
			add2(ca, c, v[0], v[1])
		}
		for ip, v := range du.Hosts {
			x := ha[ip]
			if x == nil {
				x = &HostDay{CC: v.CC, Name: v.Name}
				ha[ip] = x
			}
			x.Rx += v.Rx
			x.Tx += v.Tx
			if v.Name != "" {
				x.Name = v.Name
			}
		}
	}
	for k, v := range aa {
		apps = append(apps, usageItem{Key: k, Name: h.Names[k], Rx: v[0], Tx: v[1]})
	}
	for k, v := range ca {
		countries = append(countries, usageItem{Key: k, Name: k, CC: k, Rx: v[0], Tx: v[1]})
	}
	for k, v := range ha {
		n := v.Name
		if n == "" {
			n = k
		}
		hosts = append(hosts, usageItem{Key: k, Name: n, CC: v.CC, Rx: v.Rx, Tx: v.Tx})
	}
	return days, sortUsage(apps, 50), sortUsage(hosts, 50), sortUsage(countries, 60)
}

// DayApps devuelve el uso por app de un día concreto.
func (h *History) DayApps(t time.Time) map[string]u2 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]u2{}
	if d := h.Daily[dayKey(t)]; d != nil {
		for k, v := range d.Apps {
			out[k] = *v
		}
	}
	return out
}

// Period suma los totales de un rango de días (para el límite de datos).
func (h *History) Period(from, to time.Time) (rx, tx uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		if du := h.Daily[dayKey(d)]; du != nil {
			rx += du.Rx
			tx += du.Tx
		}
	}
	return
}

func (h *History) Save(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return writeJSONAtomic(path, h)
}

func loadHistory(path string) *History {
	h := newHistory()
	if err := readJSON(path, h); err != nil {
		h = newHistory()
	}
	if h.Hourly == nil {
		h.Hourly = map[int64]map[string]*u2{}
	}
	if h.Daily == nil {
		h.Daily = map[string]*DayUsage{}
	}
	if h.Names == nil {
		h.Names = map[string]string{}
	}
	return h
}

// billingStart devuelve el inicio del periodo de facturación que contiene t.
func billingStart(t time.Time, day int) time.Time {
	y, m, d := t.Date()
	start := time.Date(y, m, day, 0, 0, 0, 0, t.Location())
	if d < day {
		start = start.AddDate(0, -1, 0)
	}
	return start
}

func dataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	d := filepath.Join(base, "MiniWall")
	os.MkdirAll(d, 0o700)
	return d
}
