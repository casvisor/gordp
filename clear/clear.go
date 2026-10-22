// Copyright 2026 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package clear decodes ClearCodec (MS-RDPEGFX 2.2.4.1), the lossless codec
// Windows uses for text and flat UI on the graphics pipeline.
//
// ClearCodec draws over what is already on the surface: parts of a bitmap
// that no layer covers keep their old pixels, and its glyph cache stores and
// replays whole surface rectangles. The decoder does not hold surfaces, so it
// returns the pixels it produced with a coverage mask and leaves the glyph
// cache operations to whoever does.
package clear

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	flagGlyphIndex = 0x01
	flagGlyphHit   = 0x02
	flagCacheReset = 0x04

	vbarSize      = 32768
	shortVBarSize = 16384
	glyphCount    = 4000
)

var errShort = errors.New("clear: data too short")

// Result is one decoded ClearCodec bitmap.
type Result struct {
	// DrawGlyph, if not -1, is a glyph cache index whose stored rectangle is
	// drawn first.
	DrawGlyph int
	// RGBA holds width*height non-premultiplied pixels; alpha 0 marks pixels
	// the bitmap does not cover, which keep the surface's pixels. It is nil
	// when nothing but the glyph is drawn.
	RGBA []byte
	// StoreGlyph, if not -1, is a glyph cache index under which the resulting
	// surface rectangle is saved after drawing.
	StoreGlyph int
}

// Decoder holds the ClearCodec state shared by all surfaces of a session.
type Decoder struct {
	seq      int
	vbars    [][]byte // RGB triplets
	vbarPos  int
	short    [][]byte
	shortPos int
}

// NewDecoder returns a decoder with empty caches.
func NewDecoder() *Decoder {
	return &Decoder{seq: -1, vbars: make([][]byte, vbarSize), short: make([][]byte, shortVBarSize)}
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) need(n int) error {
	if n < 0 || r.pos+n > len(r.b) {
		return errShort
	}
	return nil
}

func (r *reader) u8() byte    { v := r.b[r.pos]; r.pos++; return v }
func (r *reader) u16() uint16 { v := binary.LittleEndian.Uint16(r.b[r.pos:]); r.pos += 2; return v }
func (r *reader) u32() uint32 { v := binary.LittleEndian.Uint32(r.b[r.pos:]); r.pos += 4; return v }

// runLength reads a run length that grows to 16 and then 32 bits.
func (r *reader) runLength(first byte) (int, error) {
	n := int(first)
	if n < 0xFF {
		return n, nil
	}
	if err := r.need(2); err != nil {
		return 0, err
	}
	n = int(r.u16())
	if n < 0xFFFF {
		return n, nil
	}
	if err := r.need(4); err != nil {
		return 0, err
	}
	return int(r.u32()), nil
}

// canvas is the decoded bitmap with its coverage.
type canvas struct {
	w, h int
	px   []byte
}

func (c *canvas) set(x, y int, r, g, b byte) {
	if x < 0 || y < 0 || x >= c.w || y >= c.h {
		return
	}
	o := (y*c.w + x) * 4
	c.px[o], c.px[o+1], c.px[o+2], c.px[o+3] = r, g, b, 0xFF
}

// Decode decodes one ClearCodec bitmap of w x h pixels.
func (d *Decoder) Decode(src []byte, w, h int) (*Result, error) {
	if w <= 0 || h <= 0 || w > 0xFFFF || h > 0xFFFF {
		return nil, fmt.Errorf("clear: bad size %dx%d", w, h)
	}
	r := &reader{b: src}
	if err := r.need(2); err != nil {
		return nil, err
	}
	glyphFlags := r.u8()
	seq := int(r.u8())
	if d.seq < 0 || (d.seq == 0 && seq != 0) {
		d.seq = seq
	}
	if seq != d.seq {
		return nil, fmt.Errorf("clear: sequence %d, expected %d", seq, d.seq)
	}
	d.seq = (seq + 1) % 256
	if glyphFlags&flagCacheReset != 0 {
		d.vbarPos, d.shortPos = 0, 0
	}

	res := &Result{DrawGlyph: -1, StoreGlyph: -1}
	if glyphFlags&flagGlyphHit != 0 && glyphFlags&flagGlyphIndex == 0 {
		return nil, fmt.Errorf("clear: bad glyph flags 0x%02x", glyphFlags)
	}
	if glyphFlags&flagGlyphIndex != 0 {
		if w*h > 1024*1024 {
			return nil, fmt.Errorf("clear: glyph too large")
		}
		if err := r.need(2); err != nil {
			return nil, err
		}
		index := int(r.u16())
		if index >= glyphCount {
			return nil, fmt.Errorf("clear: bad glyph index %d", index)
		}
		if glyphFlags&flagGlyphHit != 0 {
			res.DrawGlyph = index
		} else {
			res.StoreGlyph = index
		}
	}

	if len(src)-r.pos < 12 {
		if res.DrawGlyph >= 0 {
			return res, nil
		}
		return nil, fmt.Errorf("clear: missing composition header")
	}
	residual, bands, subcodecs := int(r.u32()), int(r.u32()), int(r.u32())
	c := &canvas{w: w, h: h, px: make([]byte, w*h*4)}
	if residual > 0 {
		if err := d.residual(r, residual, c); err != nil {
			return nil, err
		}
	}
	if bands > 0 {
		if err := d.bands(r, bands, c); err != nil {
			return nil, err
		}
	}
	if subcodecs > 0 {
		if err := d.subcodecs(r, subcodecs, c); err != nil {
			return nil, err
		}
	}
	res.RGBA = c.px
	return res, nil
}

// residual is the background layer: runs of solid colors over the whole bitmap.
func (d *Decoder) residual(r *reader, size int, c *canvas) error {
	if err := r.need(size); err != nil {
		return err
	}
	end := r.pos + size
	total := c.w * c.h
	i := 0
	for r.pos < end {
		if err := r.need(4); err != nil {
			return err
		}
		b, g, rr, first := r.u8(), r.u8(), r.u8(), r.u8()
		n, err := r.runLength(first)
		if err != nil {
			return err
		}
		if i >= total || n > total-i {
			return fmt.Errorf("clear: residual overflows the bitmap")
		}
		for k := 0; k < n; k++ {
			o := (i + k) * 4
			c.px[o], c.px[o+1], c.px[o+2], c.px[o+3] = rr, g, b, 0xFF
		}
		i += n
	}
	if i != total {
		return fmt.Errorf("clear: residual covers %d of %d pixels", i, total)
	}
	return nil
}

// bands draws runs of vertical bars, each a column segment that is stored in
// (or replayed from) the vbar caches.
func (d *Decoder) bands(r *reader, size int, c *canvas) error {
	if err := r.need(size); err != nil {
		return err
	}
	end := r.pos + size
	for r.pos < end {
		if err := r.need(11); err != nil {
			return err
		}
		xStart, xEnd, yStart, yEnd := int(r.u16()), int(r.u16()), int(r.u16()), int(r.u16())
		bb, bg, br := r.u8(), r.u8(), r.u8()
		if xEnd < xStart || yEnd < yStart {
			return fmt.Errorf("clear: bad band")
		}
		height := yEnd - yStart + 1
		if height > 52 {
			return fmt.Errorf("clear: band too tall")
		}
		for i := 0; i <= xEnd-xStart; i++ {
			if err := r.need(2); err != nil {
				return err
			}
			header := r.u16()
			var vbar []byte
			var short []byte
			yOn := 0
			update := false
			switch {
			case header&0xC000 == 0x4000: // short vbar cache hit
				short = d.short[header&0x3FFF]
				if err := r.need(1); err != nil {
					return err
				}
				yOn = int(r.u8())
				update = true
			case header&0xC000 == 0x0000: // short vbar cache miss
				yOn = int(header & 0xFF)
				yOff := int(header>>8) & 0x3F
				if yOff < yOn {
					return fmt.Errorf("clear: bad short vbar")
				}
				count := yOff - yOn
				if err := r.need(count * 3); err != nil {
					return err
				}
				short = make([]byte, count*3)
				for y := 0; y < count; y++ {
					b, g, rr := r.u8(), r.u8(), r.u8()
					short[y*3], short[y*3+1], short[y*3+2] = rr, g, b
				}
				d.short[d.shortPos] = short
				d.shortPos = (d.shortPos + 1) % shortVBarSize
				update = true
			case header&0x8000 == 0x8000: // vbar cache hit
				vbar = d.vbars[header&0x7FFF]
				if vbar == nil {
					vbar = make([]byte, height*3)
				}
			}
			if update {
				// Background above and below the short vbar.
				vbar = make([]byte, height*3)
				for y := 0; y < height; y++ {
					k := y - yOn
					if k >= 0 && k*3 < len(short) {
						copy(vbar[y*3:y*3+3], short[k*3:k*3+3])
					} else {
						vbar[y*3], vbar[y*3+1], vbar[y*3+2] = br, bg, bb
					}
				}
				d.vbars[d.vbarPos] = vbar
				d.vbarPos = (d.vbarPos + 1) % vbarSize
			}
			if len(vbar) != height*3 {
				resized := make([]byte, height*3)
				copy(resized, vbar)
				vbar = resized
			}
			x := xStart + i
			for y := 0; y < height && y < c.h; y++ {
				c.set(x, yStart+y, vbar[y*3], vbar[y*3+1], vbar[y*3+2])
			}
		}
	}
	return nil
}

// subcodecs draws rectangles coded with one of the subcodecs.
func (d *Decoder) subcodecs(r *reader, size int, c *canvas) error {
	if err := r.need(size); err != nil {
		return err
	}
	end := r.pos + size
	for r.pos < end {
		if err := r.need(13); err != nil {
			return err
		}
		x0, y0, w, h := int(r.u16()), int(r.u16()), int(r.u16()), int(r.u16())
		n := int(r.u32())
		id := r.u8()
		if err := r.need(n); err != nil {
			return err
		}
		if x0+w > c.w || y0+h > c.h {
			return fmt.Errorf("clear: subcodec rectangle outside the bitmap")
		}
		data := r.b[r.pos : r.pos+n]
		r.pos += n
		switch id {
		case 0: // uncompressed BGR
			if n != w*h*3 {
				return fmt.Errorf("clear: bad uncompressed size")
			}
			for y := 0; y < h; y++ {
				for x := 0; x < w; x++ {
					p := data[(y*w+x)*3:]
					c.set(x0+x, y0+y, p[2], p[1], p[0])
				}
			}
		case 1: // NSCodec
			rgba, err := DecodeNSCodec(data, w, h)
			if err != nil {
				return err
			}
			for y := 0; y < h; y++ {
				for x := 0; x < w; x++ {
					p := rgba[(y*w+x)*4:]
					c.set(x0+x, y0+y, p[0], p[1], p[2])
				}
			}
		case 2:
			if err := rlex(data, w, h, x0, y0, c); err != nil {
				return err
			}
		default:
			return fmt.Errorf("clear: unknown subcodec %d", id)
		}
	}
	return nil
}

// rlex decodes the RLEX subcodec: a palette, then runs of one color followed
// by a "suite" of consecutive palette entries.
func rlex(data []byte, w, h, x0, y0 int, c *canvas) error {
	if len(data) < 1 {
		return errShort
	}
	count := int(data[0])
	if count < 1 || count > 127 || len(data) < 1+count*3 {
		return fmt.Errorf("clear: bad rlex palette")
	}
	palette := make([][3]byte, count)
	for i := range palette {
		p := data[1+i*3:]
		palette[i] = [3]byte{p[2], p[1], p[0]}
	}
	bits := 0
	for v := count - 1; v > 0; v >>= 1 {
		bits++
	}
	// numBits is floor(log2(count-1)) + 1, and 1 for a single color.
	bits = max(bits, 1)
	r := &reader{b: data, pos: 1 + count*3}
	total := w * h
	i := 0
	put := func(color [3]byte) {
		c.set(x0+i%w, y0+i/w, color[0], color[1], color[2])
		i++
	}
	for r.pos < len(data) {
		if err := r.need(2); err != nil {
			return err
		}
		tmp := r.u8()
		first := r.u8()
		suiteDepth := int(tmp>>bits) & (0xFF >> bits)
		stop := int(tmp) & (1<<bits - 1)
		start := stop - suiteDepth
		run, err := r.runLength(first)
		if err != nil {
			return err
		}
		if start < 0 || start >= count || stop >= count {
			return fmt.Errorf("clear: bad rlex index")
		}
		if i+run+suiteDepth+1 > total {
			return fmt.Errorf("clear: rlex overflows the bitmap")
		}
		for k := 0; k < run; k++ {
			put(palette[start])
		}
		for k := 0; k <= suiteDepth; k++ {
			put(palette[start+k])
		}
	}
	if i != total {
		return fmt.Errorf("clear: rlex covers %d of %d pixels", i, total)
	}
	return nil
}
