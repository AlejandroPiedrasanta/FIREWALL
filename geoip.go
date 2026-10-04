package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"io"
	"net/netip"
	"sort"
	"sync"
)

// Base de datos IP → país incrustada (geo-whois-asn-country, dominio público CC0).

//go:embed assets/geo4.bin.gz
var geo4gz []byte

//go:embed assets/geo6.bin.gz
var geo6gz []byte

type geoTable struct {
	starts4 []uint32
	starts6 []uint64
	ccs     []byte
}

var (
	geoOnce sync.Once
	geo4    geoTable
	geo6    geoTable
)

func loadGeo(gz []byte, wide bool) geoTable {
	var t geoTable
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return t
	}
	raw, err := io.ReadAll(zr)
	if err != nil || len(raw) < 4 {
		return t
	}
	n := int(binary.LittleEndian.Uint32(raw))
	w := 4
	if wide {
		w = 8
	}
	if len(raw) < 4+n*w+n*2 {
		return t
	}
	p := raw[4:]
	if wide {
		t.starts6 = make([]uint64, n)
		for i := range t.starts6 {
			t.starts6[i] = binary.LittleEndian.Uint64(p[i*8:])
		}
	} else {
		t.starts4 = make([]uint32, n)
		for i := range t.starts4 {
			t.starts4[i] = binary.LittleEndian.Uint32(p[i*4:])
		}
	}
	t.ccs = append([]byte(nil), p[n*w:n*w+n*2]...)
	return t
}

// countryOf devuelve el código ISO de 2 letras o "" si no se conoce.
func countryOf(a netip.Addr) string {
	geoOnce.Do(func() {
		geo4 = loadGeo(geo4gz, false)
		geo6 = loadGeo(geo6gz, true)
	})
	if !isPublic(a) {
		return ""
	}
	var i int
	var t *geoTable
	if a.Is4() {
		t = &geo4
		b := a.As4()
		v := binary.BigEndian.Uint32(b[:])
		i = sort.Search(len(t.starts4), func(k int) bool { return t.starts4[k] > v }) - 1
	} else {
		t = &geo6
		b := a.As16()
		v := binary.BigEndian.Uint64(b[:8])
		i = sort.Search(len(t.starts6), func(k int) bool { return t.starts6[k] > v }) - 1
	}
	if i < 0 || i*2+2 > len(t.ccs) {
		return ""
	}
	cc := string(t.ccs[i*2 : i*2+2])
	if cc == "--" || cc == "ZZ" {
		return ""
	}
	return cc
}

// isPublic indica si la IP es enrutable en Internet (no local, privada, etc.).
func isPublic(a netip.Addr) bool {
	return a.IsValid() && !a.IsLoopback() && !a.IsPrivate() && !a.IsLinkLocalUnicast() &&
		!a.IsMulticast() && !a.IsUnspecified() && !a.IsLinkLocalMulticast() &&
		!(a.Is4() && a.As4()[0] == 100 && a.As4()[1]&0xC0 == 64) // CGNAT 100.64/10
}
