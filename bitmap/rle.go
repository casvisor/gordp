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

package bitmap

import "fmt"

// Interleaved RLE order codes (MS-RDPBCGR 2.2.9.1.1.3.1.2.3). The decoder below
// follows the compression format described there; it shares nothing with the
// GPL rdesktop decoder.
const (
	codeBGRun       = 0x00
	codeFGRun       = 0x01
	codeFGBGImage   = 0x02
	codeColorRun    = 0x03
	codeColorImage  = 0x04
	codeSetFGFGRun  = 0x0C
	codeSetFGBGImg  = 0x0D
	codeDitheredRun = 0x0E

	megaBGRun       = 0xF0
	megaFGRun       = 0xF1
	megaFGBGImage   = 0xF2
	megaColorRun    = 0xF3
	megaColorImage  = 0xF4
	megaSetFGFGRun  = 0xF6
	megaSetFGBGImg  = 0xF7
	megaDitheredRun = 0xF8
	specialFGBG1    = 0xF9
	specialFGBG2    = 0xFA
	codeWhite       = 0xFD
	codeBlack       = 0xFE
)

const (
	white uint16 = 0xFFFF
	black uint16 = 0x0000
)

// decompressInterleaved16 decompresses an interleaved-RLE 16bpp bitmap into
// top-down pixels. The stream is decoded in its natural bottom-up order, then
// flipped to top-down for display.
func decompressInterleaved16(src []byte, w, h int) ([]uint16, error) {
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("bitmap: bad size %dx%d", w, h)
	}
	d := &rleDecoder{src: src, dst: make([]uint16, w*h), rowDelta: w}
	if err := d.run(); err != nil {
		return nil, err
	}
	// Flip bottom-up decode order to top-down.
	out := make([]uint16, w*h)
	for y := 0; y < h; y++ {
		copy(out[y*w:(y+1)*w], d.dst[(h-1-y)*w:(h-y)*w])
	}
	return out, nil
}

type rleDecoder struct {
	src      []byte
	s        int
	dst      []uint16
	d        int
	rowDelta int

	fgPel       uint16
	insertFgPel bool
	firstLine   bool
}

func (r *rleDecoder) run() error {
	r.fgPel = white
	r.firstLine = true

	for r.s < len(r.src) {
		if r.firstLine && r.d >= r.rowDelta {
			r.firstLine = false
			r.insertFgPel = false
		}

		header := r.src[r.s]
		code := extractCode(header)

		switch code {
		case codeBGRun, megaBGRun:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			if err := r.bgRun(n); err != nil {
				return err
			}
			r.insertFgPel = true
		case codeFGRun, megaFGRun:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			if err := r.fgRun(n); err != nil {
				return err
			}
			r.insertFgPel = false
		case codeSetFGFGRun, megaSetFGFGRun:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			if r.fgPel, err = r.readPixel(); err != nil {
				return err
			}
			if err := r.fgRun(n); err != nil {
				return err
			}
			r.insertFgPel = false
		case codeDitheredRun, megaDitheredRun:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			pa, err := r.readPixel()
			if err != nil {
				return err
			}
			pb, err := r.readPixel()
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				if err := r.put(pa); err != nil {
					return err
				}
				if err := r.put(pb); err != nil {
					return err
				}
			}
			r.insertFgPel = false
		case codeColorRun, megaColorRun:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			px, err := r.readPixel()
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				if err := r.put(px); err != nil {
					return err
				}
			}
			r.insertFgPel = false
		case codeColorImage, megaColorImage:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				px, err := r.readPixel()
				if err != nil {
					return err
				}
				if err := r.put(px); err != nil {
					return err
				}
			}
			r.insertFgPel = false
		case codeFGBGImage, megaFGBGImage:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			if err := r.fgbgImage(n); err != nil {
				return err
			}
			r.insertFgPel = false
		case codeSetFGBGImg, megaSetFGBGImg:
			n, err := r.runLength(header, code)
			if err != nil {
				return err
			}
			if r.fgPel, err = r.readPixel(); err != nil {
				return err
			}
			if err := r.fgbgImage(n); err != nil {
				return err
			}
			r.insertFgPel = false
		case specialFGBG1:
			r.s++
			if err := r.fgbgMask(8, 0x03); err != nil {
				return err
			}
			r.insertFgPel = false
		case specialFGBG2:
			r.s++
			if err := r.fgbgMask(8, 0x05); err != nil {
				return err
			}
			r.insertFgPel = false
		case codeWhite:
			r.s++
			if err := r.put(white); err != nil {
				return err
			}
		case codeBlack:
			r.s++
			if err := r.put(black); err != nil {
				return err
			}
		default:
			return fmt.Errorf("bitmap: unknown RLE code 0x%02x", header)
		}
	}
	return nil
}

func extractCode(header byte) byte {
	if header&0xC0 != 0xC0 {
		return header >> 5
	}
	if header&0xF0 == 0xF0 {
		return header
	}
	return header >> 4
}

// runLength reads the run length for the order and advances past the header and
// any length-extension byte(s). It handles the regular, lite, FGBG and
// mega-mega length forms.
func (r *rleDecoder) runLength(header, code byte) (int, error) {
	isMega := header&0xF0 == 0xF0
	if isMega {
		if r.s+3 > len(r.src) {
			return 0, errShort
		}
		n := int(r.src[r.s+1]) | int(r.src[r.s+2])<<8
		r.s += 3
		return n, nil
	}

	isLite := header&0xC0 == 0xC0
	isFgbg := code == codeFGBGImage || code == codeSetFGBGImg

	var mask, extBase int
	if isLite {
		mask = 0x0F
		extBase = 16
	} else {
		mask = 0x1F
		extBase = 32
	}
	n := int(header) & mask

	if isFgbg {
		if n == 0 {
			if r.s+2 > len(r.src) {
				return 0, errShort
			}
			n = int(r.src[r.s+1]) + 1
			r.s += 2
		} else {
			n *= 8
			r.s++
		}
		return n, nil
	}

	if n == 0 {
		if r.s+2 > len(r.src) {
			return 0, errShort
		}
		n = int(r.src[r.s+1]) + extBase
		r.s += 2
	} else {
		r.s++
	}
	return n, nil
}

func (r *rleDecoder) bgRun(n int) error {
	if r.firstLine {
		if r.insertFgPel {
			if err := r.put(r.fgPel); err != nil {
				return err
			}
			n--
		}
		for ; n > 0; n-- {
			if err := r.put(black); err != nil {
				return err
			}
		}
		return nil
	}
	if r.insertFgPel {
		if err := r.put(r.above() ^ r.fgPel); err != nil {
			return err
		}
		n--
	}
	for ; n > 0; n-- {
		if err := r.put(r.above()); err != nil {
			return err
		}
	}
	return nil
}

func (r *rleDecoder) fgRun(n int) error {
	for ; n > 0; n-- {
		if r.firstLine {
			if err := r.put(r.fgPel); err != nil {
				return err
			}
		} else {
			if err := r.put(r.above() ^ r.fgPel); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *rleDecoder) fgbgImage(n int) error {
	for n > 0 {
		if r.s >= len(r.src) {
			return errShort
		}
		mask := r.src[r.s]
		r.s++
		bits := 8
		if n < 8 {
			bits = n
		}
		if err := r.fgbgBits(mask, bits); err != nil {
			return err
		}
		n -= bits
	}
	return nil
}

func (r *rleDecoder) fgbgMask(count int, mask byte) error {
	return r.fgbgBits(mask, count)
}

func (r *rleDecoder) fgbgBits(mask byte, bits int) error {
	for i := 0; i < bits; i++ {
		set := mask&(1<<uint(i)) != 0
		var pel uint16
		if set {
			if r.firstLine {
				pel = r.fgPel
			} else {
				pel = r.above() ^ r.fgPel
			}
		} else {
			if r.firstLine {
				pel = black
			} else {
				pel = r.above()
			}
		}
		if err := r.put(pel); err != nil {
			return err
		}
	}
	return nil
}

func (r *rleDecoder) above() uint16 {
	if r.d-r.rowDelta < 0 {
		return black
	}
	return r.dst[r.d-r.rowDelta]
}

func (r *rleDecoder) put(pel uint16) error {
	if r.d >= len(r.dst) {
		return fmt.Errorf("bitmap: RLE wrote past the destination")
	}
	r.dst[r.d] = pel
	r.d++
	return nil
}

func (r *rleDecoder) readPixel() (uint16, error) {
	if r.s+2 > len(r.src) {
		return 0, errShort
	}
	p := uint16(r.src[r.s]) | uint16(r.src[r.s+1])<<8
	r.s += 2
	return p, nil
}

var errShort = fmt.Errorf("bitmap: truncated RLE stream")
