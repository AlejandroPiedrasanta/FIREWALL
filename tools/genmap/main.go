//go:build ignore

// genmap genera ui/worldmap.js a partir de Natural Earth (dominio público):
// siluetas de países (escala 1:110m) en proyección Miller y puntos de
// etiqueta / nombres en español (escala 1:50m, incluye países pequeños).
//
// Uso: go run tools/genmap/main.go ne_110m.geojson ne_50m.geojson ui/worldmap.js
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

const (
	W      = 1000.0
	latMax = 84.0
	latMin = -58.0
)

type feature struct {
	Properties map[string]any `json:"properties"`
	Geometry   struct {
		Type        string          `json:"type"`
		Coordinates json.RawMessage `json:"coordinates"`
	} `json:"geometry"`
}

type collection struct {
	Features []feature `json:"features"`
}

func miller(lat float64) float64 {
	r := lat * math.Pi / 180
	return 1.25 * math.Log(math.Tan(math.Pi/4+0.4*r))
}

var yTop, yBot = miller(latMax), miller(latMin)
var H = W * (yTop - yBot) / (2 * math.Pi)

func project(lon, lat float64) (float64, float64) {
	lat = math.Max(latMin, math.Min(latMax, lat))
	x := (lon + 180) / 360 * W
	y := (yTop - miller(lat)) / (yTop - yBot) * H
	return x, y
}

func code(p map[string]any) string {
	for _, k := range []string{"ISO_A2_EH", "ISO_A2"} {
		if s, ok := p[k].(string); ok && len(s) == 2 && s != "-9" {
			return s
		}
	}
	return ""
}

func load(path string) collection {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var c collection
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return c
}

func ring(sb *strings.Builder, pts [][]float64) {
	var lx, ly float64 = -1, -1
	n := 0
	for i, p := range pts {
		x, y := project(p[0], p[1])
		x, y = math.Round(x*10)/10, math.Round(y*10)/10
		if x == lx && y == ly {
			continue
		}
		if i == 0 {
			fmt.Fprintf(sb, "M%g %g", x, y)
		} else {
			fmt.Fprintf(sb, "L%g %g", x, y)
		}
		lx, ly = x, y
		n++
	}
	sb.WriteString("Z")
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("uso: genmap <110m.geojson> <50m.geojson> <salida.js>")
		os.Exit(2)
	}
	shapes := map[string]string{}
	for _, f := range load(os.Args[1]).Features {
		c := code(f.Properties)
		if c == "" || c == "AQ" {
			continue
		}
		var sb strings.Builder
		switch f.Geometry.Type {
		case "Polygon":
			var poly [][][]float64
			json.Unmarshal(f.Geometry.Coordinates, &poly)
			for _, r := range poly {
				ring(&sb, r)
			}
		case "MultiPolygon":
			var mp [][][][]float64
			json.Unmarshal(f.Geometry.Coordinates, &mp)
			for _, poly := range mp {
				for _, r := range poly {
					ring(&sb, r)
				}
			}
		}
		shapes[c] += sb.String()
	}
	type label struct {
		X, Y float64
		Name string
	}
	labels := map[string]label{}
	for _, f := range load(os.Args[2]).Features {
		c := code(f.Properties)
		if c == "" {
			continue
		}
		lx, _ := f.Properties["LABEL_X"].(float64)
		ly, _ := f.Properties["LABEL_Y"].(float64)
		name, _ := f.Properties["NAME_ES"].(string)
		if name == "" {
			name, _ = f.Properties["NAME"].(string)
		}
		x, y := project(lx, ly)
		if _, dup := labels[c]; !dup {
			labels[c] = label{math.Round(x*10) / 10, math.Round(y*10) / 10, name}
		}
	}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out strings.Builder
	out.WriteString("// Generado por tools/genmap a partir de Natural Earth (dominio público). No editar.\n")
	fmt.Fprintf(&out, "window.WORLD={w:%g,h:%g,shapes:{\n", W, math.Round(H))
	sk := make([]string, 0, len(shapes))
	for k := range shapes {
		sk = append(sk, k)
	}
	sort.Strings(sk)
	for _, k := range sk {
		fmt.Fprintf(&out, "%s:%q,\n", k, shapes[k])
	}
	out.WriteString("},labels:{\n")
	for _, k := range keys {
		l := labels[k]
		n, _ := json.Marshal(l.Name)
		fmt.Fprintf(&out, "%s:[%g,%g,%s],\n", k, l.X, l.Y, n)
	}
	out.WriteString("}};\n")
	if err := os.WriteFile(os.Args[3], []byte(out.String()), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%d siluetas, %d etiquetas, alto %.0f\n", len(shapes), len(labels), H)
}
