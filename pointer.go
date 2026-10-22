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

package gordp

import (
	"fmt"

	"github.com/casvisor/gordp/core"
	"github.com/casvisor/gordp/pdu"
)

// pointerCacheSize matches the pointerCacheSize the client advertises.
const pointerCacheSize = 21

// Pointer is the mouse cursor shape the remote session wants shown. The cursor
// is not part of the desktop image, so a viewer draws it locally.
type Pointer struct {
	// Hidden means the session hides the cursor (for example while typing).
	Hidden bool
	// Default means the system default arrow; RGBA is empty.
	Default bool
	// HotX and HotY locate the click point within the image.
	HotX, HotY int
	// Width and Height are the image size; RGBA holds Width*Height pixels,
	// top-down, non-premultiplied.
	Width, Height int
	RGBA          []byte
}

// handlePointerUpdate decodes a fast-path pointer update and reports the shape
// that is now in effect through OnPointer.
func (c *Client) handlePointerUpdate(code byte, data []byte) error {
	if c.OnPointer == nil && code != pdu.FastPathUpdateColor && code != pdu.FastPathUpdatePointer && code != pdu.FastPathUpdateLargePointer {
		return nil
	}
	var p *Pointer
	switch code {
	case pdu.FastPathUpdatePointerNull:
		p = &Pointer{Hidden: true}
	case pdu.FastPathUpdatePointerDef:
		p = &Pointer{Default: true}
	case pdu.FastPathUpdateCached:
		if len(data) < 2 {
			return nil
		}
		p = c.pointers[int(data[0])|int(data[1])<<8]
		if p == nil {
			return nil
		}
	case pdu.FastPathUpdateColor:
		index, ptr, err := parseColorPointer(core.NewReader(data), 24, false)
		if err != nil {
			return err
		}
		c.cachePointer(index, ptr)
		p = ptr
	case pdu.FastPathUpdatePointer:
		r := core.NewReader(data)
		bpp, err := r.ReadUint16LE()
		if err != nil {
			return err
		}
		index, ptr, err := parseColorPointer(r, int(bpp), false)
		if err != nil {
			return err
		}
		c.cachePointer(index, ptr)
		p = ptr
	case pdu.FastPathUpdateLargePointer:
		r := core.NewReader(data)
		bpp, err := r.ReadUint16LE()
		if err != nil {
			return err
		}
		index, ptr, err := parseColorPointer(r, int(bpp), true)
		if err != nil {
			return err
		}
		c.cachePointer(index, ptr)
		p = ptr
	default:
		return nil
	}
	if c.OnPointer != nil {
		c.OnPointer(p)
	}
	return nil
}

func (c *Client) cachePointer(index int, p *Pointer) {
	if c.pointers == nil {
		c.pointers = map[int]*Pointer{}
	}
	if index >= 0 && index < pointerCacheSize {
		c.pointers[index] = p
	}
}

// parseColorPointer reads TS_COLORPOINTERATTRIBUTE (MS-RDPBCGR 2.2.9.1.1.4.4),
// or with large set the TS_LARGEPOINTERATTRIBUTE body whose mask lengths are
// 32-bit, and converts the XOR and AND masks to an RGBA image the way the Windows
// client draws them. Pixels that invert the screen cannot be shown by a plain
// image, so they become a black and white checkerboard, as FreeRDP does.
func parseColorPointer(r *core.Reader, xorBpp int, large bool) (int, *Pointer, error) {
	var hdr [5]uint16
	for i := range hdr {
		v, err := r.ReadUint16LE()
		if err != nil {
			return 0, nil, err
		}
		hdr[i] = v
	}
	index, hotX, hotY := int(hdr[0]), int(hdr[1]), int(hdr[2])
	width, height := int(hdr[3]), int(hdr[4])
	var andLen, xorLen int
	if large {
		a, err := r.ReadUint32LE()
		if err != nil {
			return 0, nil, err
		}
		x, err := r.ReadUint32LE()
		if err != nil {
			return 0, nil, err
		}
		andLen, xorLen = int(a), int(x)
	} else {
		a, err := r.ReadUint16LE()
		if err != nil {
			return 0, nil, err
		}
		x, err := r.ReadUint16LE()
		if err != nil {
			return 0, nil, err
		}
		andLen, xorLen = int(a), int(x)
	}
	xorMask, err := r.ReadBytes(xorLen)
	if err != nil {
		return 0, nil, err
	}
	andMask, err := r.ReadBytes(andLen)
	if err != nil {
		return 0, nil, err
	}
	if width == 0 || height == 0 || width > 384 || height > 384 {
		return index, &Pointer{Default: true}, nil
	}

	andStep := (width + 7) / 8
	andStep += andStep % 2
	if andLen > 0 && andStep*height > andLen {
		return 0, nil, fmt.Errorf("gordp: pointer and-mask too short")
	}
	andBit := func(x, y int) bool {
		if andLen == 0 {
			return false
		}
		return andMask[y*andStep+x/8]&(0x80>>(x%8)) != 0
	}
	inverted := func(x, y int) (byte, byte, byte, byte) {
		if (x+y)&1 != 0 {
			return 0, 0, 0, 0xFF
		}
		return 0xFF, 0xFF, 0xFF, 0xFF
	}

	out := make([]byte, width*height*4)
	if xorBpp == 1 {
		xorStep := (width + 7) / 8
		xorStep += xorStep % 2
		if xorStep*height > xorLen || andLen == 0 {
			return 0, nil, fmt.Errorf("gordp: pointer xor-mask too short")
		}
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				xor := xorMask[y*xorStep+x/8]&(0x80>>(x%8)) != 0
				and := andBit(x, y)
				var cr, cg, cb, ca byte
				switch {
				case !and && !xor:
					cr, cg, cb, ca = 0, 0, 0, 0xFF
				case !and && xor:
					cr, cg, cb, ca = 0xFF, 0xFF, 0xFF, 0xFF
				case and && xor:
					cr, cg, cb, ca = inverted(x, y)
				}
				o := (y*width + x) * 4
				out[o], out[o+1], out[o+2], out[o+3] = cr, cg, cb, ca
			}
		}
		return index, &Pointer{HotX: hotX, HotY: hotY, Width: width, Height: height, RGBA: out}, nil
	}

	bytesPP := xorBpp / 8
	if bytesPP != 2 && bytesPP != 3 && bytesPP != 4 {
		return index, &Pointer{Default: true}, nil
	}
	xorStep := width * bytesPP
	xorStep += xorStep % 2
	if xorStep*height > xorLen {
		return 0, nil, fmt.Errorf("gordp: pointer xor-mask too short")
	}
	for y := 0; y < height; y++ {
		// Both masks are stored bottom-up.
		row := xorMask[(height-1-y)*xorStep:]
		for x := 0; x < width; x++ {
			var cr, cg, cb, ca byte
			px := row[x*bytesPP:]
			switch bytesPP {
			case 4:
				cb, cg, cr, ca = px[0], px[1], px[2], px[3]
			case 3:
				cb, cg, cr, ca = px[0], px[1], px[2], 0xFF
			case 2: // RGB555
				v := uint16(px[0]) | uint16(px[1])<<8
				cr = byte((v>>10)&0x1F) << 3
				cg = byte((v>>5)&0x1F) << 3
				cb = byte(v&0x1F) << 3
				ca = 0xFF
			}
			if andBit(x, height-1-y) {
				switch {
				case cr == 0 && cg == 0 && cb == 0 && ca == 0xFF:
					ca = 0
				case cr == 0xFF && cg == 0xFF && cb == 0xFF && ca == 0xFF:
					cr, cg, cb, ca = inverted(x, y)
				}
			}
			o := (y*width + x) * 4
			out[o], out[o+1], out[o+2], out[o+3] = cr, cg, cb, ca
		}
	}
	return index, &Pointer{HotX: hotX, HotY: hotY, Width: width, Height: height, RGBA: out}, nil
}
