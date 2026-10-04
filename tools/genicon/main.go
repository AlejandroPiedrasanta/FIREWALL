//go:build ignore

// genicon dibuja el icono de MiniWall (escudo con gráfica de tráfico) en PNG.
//
// Uso: go run tools/genicon/main.go winres/icon.png
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

const S = 256

func clamp(v float64) float64 { return math.Max(0, math.Min(1, v)) }

// sdRoundBox: distancia con signo a un rectángulo redondeado centrado.
func sdRoundBox(x, y, hw, hh, r float64) float64 {
	qx := math.Abs(x) - hw + r
	qy := math.Abs(y) - hh + r
	return math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - r
}

// inShield: silueta de escudo en coordenadas normalizadas [-1,1].
func shieldDist(x, y float64) float64 {
	// parte superior rectangular con esquinas suaves y punta inferior curva
	top := sdRoundBox(x, y+0.12, 0.62, 0.5, 0.2)
	// punta: intersección de dos círculos
	c1 := math.Hypot(x-0.62, y-0.05) - 1.24
	c2 := math.Hypot(x+0.62, y-0.05) - 1.24
	tip := math.Max(math.Max(c1, c2), -(y - 0.2))
	d := math.Min(top, math.Max(tip, y-1.0))
	return math.Max(d, -(y + 0.62))
}

func lineDist(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := clamp(((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy))
	return math.Hypot(px-ax-t*dx, py-ay-t*dy)
}

func main() {
	img := image.NewNRGBA(image.Rect(0, 0, S, S))
	pts := [][2]float64{{-0.42, 0.18}, {-0.2, 0.18}, {-0.08, -0.22}, {0.08, 0.36}, {0.2, 0.02}, {0.42, 0.02}}
	for py := 0; py < S; py++ {
		for px := 0; px < S; px++ {
			var r, g, b, a float64
			// supermuestreo 4x4 para bordes suaves
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					x := (float64(px)+(float64(sx)+0.5)/4)/S*2 - 1
					y := (float64(py)+(float64(sy)+0.5)/4)/S*2 - 1
					bg := sdRoundBox(x, y, 0.94, 0.94, 0.3)
					if bg > 0 {
						continue
					}
					t := (y + 1) / 2
					cr, cg, cb := 0.10+0.05*t, 0.82-0.30*t, 0.78-0.05*t // turquesa → azul
					sd := shieldDist(x*1.15, y*1.15-0.02)
					if sd < 0 {
						cr, cg, cb = 0.06, 0.09, 0.14
						ld := math.Inf(1)
						for i := 0; i+1 < len(pts); i++ {
							ld = math.Min(ld, lineDist(x, y, pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1]))
						}
						if ld < 0.055 {
							cr, cg, cb = 0.25, 0.95, 0.80
						}
						if sd > -0.05 {
							cr, cg, cb = 0.92, 0.97, 1
						}
					}
					r += cr
					g += cg
					b += cb
					a++
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{
				uint8(255 * clamp(r/a)), uint8(255 * clamp(g/a)), uint8(255 * clamp(b/a)), uint8(255 * a / 16),
			})
		}
	}
	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	png.Encode(f, img)
}
