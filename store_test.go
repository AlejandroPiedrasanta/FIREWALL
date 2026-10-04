package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestCountryOf(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":              "US",
		"1.0.0.1":              "AU",
		"80.58.61.250":         "ES", // Telefónica
		"2001:4860:4860::8888": "US",
		"192.168.1.10":         "",
		"127.0.0.1":            "",
	}
	for ip, want := range cases {
		if got := countryOf(netip.MustParseAddr(ip)); got != want {
			t.Errorf("countryOf(%s) = %q, quiero %q", ip, got, want)
		}
	}
}

func TestHistorySeries(t *testing.T) {
	h := newHistory()
	base := time.Date(2026, 10, 4, 10, 0, 0, 0, time.Local)
	for i := 0; i < 180; i++ {
		h.AddTotals(base.Add(time.Duration(i)*time.Minute), 100, 10)
	}
	h.AddApp(base, "c:\\a.exe", "A", 500, 50)
	h.AddApp(base.Add(2*time.Hour), "c:\\b.exe", "B", 900, 0)
	pts := h.Series(base.Unix(), base.Add(3*time.Hour).Unix()-1, 3600)
	if len(pts) != 3 || pts[0].Rx != 6000 || pts[2].Tx != 600 {
		t.Fatalf("series inesperada: %+v", pts)
	}
	apps := h.AppsBetween(base.Unix(), base.Add(time.Hour).Unix()-1, 10)
	if len(apps) != 1 || apps[0].Name != "A" {
		t.Fatalf("apps por hora inesperadas: %+v", apps)
	}
	days, top, _, _ := h.Days(base, base)
	if len(days) != 1 || days[0].Rx != 18000 || len(top) != 2 || top[0].Name != "B" {
		t.Fatalf("días inesperados: %+v %+v", days, top)
	}
}

func TestBillingStart(t *testing.T) {
	d := billingStart(time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC), 10)
	if d.Month() != 2 || d.Day() != 10 {
		t.Fatalf("inicio de facturación inesperado: %v", d)
	}
}

func TestProfiles(t *testing.T) {
	c := defaultConfig()
	c.normalize()
	c.setBlocked("x", true)
	c.Pending["y"] = 1
	if !c.isBlocked("x") || !c.isBlocked("y") || len(c.desiredBlocked()) != 2 {
		t.Fatal("bloqueo no registrado")
	}
	c.setBlocked("x", false)
	if c.isBlocked("x") {
		t.Fatal("desbloqueo no registrado")
	}
}
