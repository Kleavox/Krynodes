package tray

import (
	"encoding/binary"
	"math"
)

const side = 32

type point struct{ x, y float64 }

var (
	hub     = point{6, 12}
	strokes = [][2]point{{{6, 3.75}, {6, 20.25}}, {hub, {17.75, 5}}, {hub, {17.75, 19}}}
	knots   = []struct {
		at     point
		radius float64
	}{{hub, 3.1}, {point{17.75, 5}, 2.75}, {point{17.75, 19}, 2.75}}
)

func distance(p, a, b point) float64 {
	dx, dy := b.x-a.x, b.y-a.y
	t := math.Max(0, math.Min(1, ((p.x-a.x)*dx+(p.y-a.y)*dy)/(dx*dx+dy*dy)))
	return math.Hypot(p.x-a.x-t*dx, p.y-a.y-t*dy)
}

func coverage(p point, scale float64) float64 {
	best := 0.0
	for _, stroke := range strokes {
		best = math.Max(best, (1.5-distance(p, stroke[0], stroke[1]))*scale+0.5)
	}
	for _, knot := range knots {
		best = math.Max(best, (knot.radius-math.Hypot(p.x-knot.at.x, p.y-knot.at.y))*scale+0.5)
	}
	return math.Max(0, math.Min(1, best))
}

func icon(connected bool) []byte {
	red, green, blue := byte(0x8b), byte(0x7b), byte(0xff)
	if !connected {
		red, green, blue = 0x9a, 0x9a, 0x9a
	}
	pixels := side * side * 4
	mask := side * side / 8
	image := 40 + pixels + mask
	out := make([]byte, 0, 22+image)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 1)
	out = binary.LittleEndian.AppendUint16(out, 1)
	out = append(out, side, side, 0, 0)
	out = binary.LittleEndian.AppendUint16(out, 1)
	out = binary.LittleEndian.AppendUint16(out, 32)
	out = binary.LittleEndian.AppendUint32(out, uint32(image))
	out = binary.LittleEndian.AppendUint32(out, 22)
	for _, value := range []uint32{40, side, side * 2} {
		out = binary.LittleEndian.AppendUint32(out, value)
	}
	out = binary.LittleEndian.AppendUint16(out, 1)
	out = binary.LittleEndian.AppendUint16(out, 32)
	out = append(out, make([]byte, 24)...)
	scale := float64(side) / 24
	for row := side - 1; row >= 0; row-- {
		for column := range side {
			alpha := coverage(point{(float64(column) + 0.5) / scale, (float64(row) + 0.5) / scale}, scale)
			out = append(out, blue, green, red, byte(math.Round(255*alpha)))
		}
	}
	return append(out, make([]byte, mask)...)
}
