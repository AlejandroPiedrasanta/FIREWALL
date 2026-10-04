//go:build ignore

// gengeo convierte la base de datos CC0 "geo-whois-asn-country" (paquete npm
// @ip-location-db/geo-whois-asn-country) en tablas binarias compactas que
// MiniWall incrusta para ubicar IPs por país sin conexión a Internet.
//
// Uso: go run tools/gengeo/main.go <dir-con-csv> assets/
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

type rng struct {
	start uint64
	end   uint64
	cc    string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("uso: gengeo <dir-csv> <dir-salida>")
		os.Exit(2)
	}
	src, dst := os.Args[1], os.Args[2]
	must(build(filepath.Join(src, "geo-whois-asn-country-ipv4-num.csv"), filepath.Join(dst, "geo4.bin.gz"), 32))
	must(build(filepath.Join(src, "geo-whois-asn-country-ipv6-num.csv"), filepath.Join(dst, "geo6.bin.gz"), 128))
}

func must(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// parse devuelve el valor de 64 bits usado como clave: la IP completa para
// IPv4 y los 64 bits altos para IPv6 (los bloques asignados son /64 o mayores).
func parse(s string, bits int) uint64 {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("número inválido: " + s)
	}
	if bits == 128 {
		n.Rsh(n, 64)
	}
	return n.Uint64()
}

func build(in, out string, bits int) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	var rs []rng
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(strings.TrimSpace(sc.Text()), ",")
		if len(p) != 3 || len(p[2]) != 2 {
			continue
		}
		r := rng{start: parse(p[0], bits), end: parse(p[1], bits), cc: strings.ToUpper(p[2])}
		rs = append(rs, r)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	// Construye una lista de inicios de tramo; los huecos se marcan con "--".
	var starts []uint64
	var ccs []string
	maxv := uint64(math.MaxUint64)
	if bits == 32 {
		maxv = math.MaxUint32
	}
	var next uint64
	full := false
	for _, r := range rs {
		if full {
			break
		}
		if r.end < next {
			continue // solapamiento por truncado de IPv6
		}
		if r.start < next {
			r.start = next
		}
		if r.start > next {
			push(&starts, &ccs, next, "--")
		}
		push(&starts, &ccs, r.start, r.cc)
		if r.end >= maxv {
			full = true
		} else {
			next = r.end + 1
		}
	}
	if !full {
		push(&starts, &ccs, next, "--")
	}

	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	zw, _ := gzip.NewWriterLevel(o, gzip.BestCompression)
	w := bufio.NewWriter(zw)
	binary.Write(w, binary.LittleEndian, uint32(len(starts)))
	for _, s := range starts {
		if bits == 32 {
			binary.Write(w, binary.LittleEndian, uint32(s))
		} else {
			binary.Write(w, binary.LittleEndian, s)
		}
	}
	for _, c := range ccs {
		w.WriteString(c)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	fmt.Printf("%s: %d tramos\n", out, len(starts))
	return nil
}

// push añade un tramo fusionándolo con el anterior si es del mismo país.
func push(starts *[]uint64, ccs *[]string, start uint64, cc string) {
	n := len(*starts)
	if n > 0 && (*ccs)[n-1] == cc {
		return
	}
	if n > 0 && (*starts)[n-1] == start {
		(*ccs)[n-1] = cc
		return
	}
	*starts = append(*starts, start)
	*ccs = append(*ccs, cc)
}
