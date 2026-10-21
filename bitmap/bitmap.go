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

// Package bitmap parses RDP bitmap update rectangles and decodes them to pixels.
// It handles uncompressed data and the interleaved RLE compression that Windows
// uses for the legacy bitmap path (the path the server takes when the client,
// like gordp, advertises no drawing orders).
package bitmap

import (
	"fmt"

	"github.com/casvisor/gordp/core"
)

// bitmap data flags (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
const (
	flagCompression  = 0x0001
	flagNoCompHeader = 0x0400
)

// Rect is one decoded bitmap rectangle, as top-down RGBA (4 bytes per pixel).
type Rect struct {
	DestLeft int
	DestTop  int
	Width    int
	Height   int
	Bpp      int
	RGBA     []byte
}

// ParseBitmapUpdate parses a TS_UPDATE_BITMAP body (without the update type,
// which the fast-path header already carried) and returns the decoded rects.
func ParseBitmapUpdate(data []byte) ([]Rect, error) {
	r := core.NewReader(data)
	// updateType (0x0001) is present even on the fast-path bitmap update.
	if _, err := r.ReadUint16LE(); err != nil {
		return nil, err
	}
	count, err := r.ReadUint16LE()
	if err != nil {
		return nil, err
	}

	rects := make([]Rect, 0, count)
	for i := 0; i < int(count); i++ {
		rect, err := parseRectangle(r)
		if err != nil {
			return nil, fmt.Errorf("bitmap: rectangle %d: %w", i, err)
		}
		rects = append(rects, rect)
	}
	return rects, nil
}

func parseRectangle(r *core.Reader) (Rect, error) {
	destLeft, _ := r.ReadUint16LE()
	destTop, _ := r.ReadUint16LE()
	destRight, _ := r.ReadUint16LE()
	destBottom, _ := r.ReadUint16LE()
	width, _ := r.ReadUint16LE()
	height, _ := r.ReadUint16LE()
	bpp, _ := r.ReadUint16LE()
	flags, _ := r.ReadUint16LE()
	length, err := r.ReadUint16LE()
	if err != nil {
		return Rect{}, err
	}

	compressed := flags&flagCompression != 0
	if compressed && flags&flagNoCompHeader == 0 {
		// Skip the TS_CD_HEADER; the real data is the main body size.
		if _, err := r.ReadUint16LE(); err != nil { // cbCompFirstRowSize
			return Rect{}, err
		}
		mainBody, err := r.ReadUint16LE()
		if err != nil {
			return Rect{}, err
		}
		if _, err := r.ReadUint16LE(); err != nil { // cbScanWidth
			return Rect{}, err
		}
		if _, err := r.ReadUint16LE(); err != nil { // cbUncompressedSize
			return Rect{}, err
		}
		length = mainBody
	}

	payload, err := r.ReadBytes(int(length))
	if err != nil {
		return Rect{}, err
	}

	_ = destRight
	_ = destBottom
	w, h := int(width), int(height)

	var rgba []byte
	switch bpp {
	case 15, 16:
		var pixels []uint16
		if compressed {
			pixels, err = decompressInterleaved16(payload, w, h)
		} else {
			pixels, err = rawPixels16(payload, w, h)
		}
		if err == nil {
			rgba = pixels16ToRGBA(pixels, w, h, bpp == 15)
		}
	case 24, 32:
		if compressed {
			rgba, err = decodePlanar32(payload, w, h)
		} else {
			rgba, err = rawPixels32(payload, w, h)
		}
	default:
		return Rect{}, fmt.Errorf("bitmap: %d bpp not supported yet", bpp)
	}
	if err != nil {
		return Rect{}, err
	}

	return Rect{
		DestLeft: int(destLeft),
		DestTop:  int(destTop),
		Width:    w,
		Height:   h,
		Bpp:      int(bpp),
		RGBA:     rgba,
	}, nil
}

// rawPixels32 reads an uncompressed 32bpp bitmap (BGRX/BGRA, bottom-up).
func rawPixels32(data []byte, w, h int) ([]byte, error) {
	if len(data) < w*h*4 {
		return nil, fmt.Errorf("bitmap: raw 32bpp data %d bytes, want %d", len(data), w*h*4)
	}
	out := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		srcRow := (h - 1 - y) * w * 4
		for x := 0; x < w; x++ {
			off := srcRow + x*4
			dst := (y*w + x) * 4
			out[dst] = data[off+2]   // R
			out[dst+1] = data[off+1] // G
			out[dst+2] = data[off]   // B
			out[dst+3] = 0xFF
		}
	}
	return out, nil
}

// rawPixels16 reads an uncompressed 16bpp bitmap (stored bottom-up).
func rawPixels16(data []byte, w, h int) ([]uint16, error) {
	if len(data) < w*h*2 {
		return nil, fmt.Errorf("bitmap: raw data %d bytes, want %d", len(data), w*h*2)
	}
	out := make([]uint16, w*h)
	// Flip bottom-up storage into top-down.
	for y := 0; y < h; y++ {
		srcRow := (h - 1 - y) * w * 2
		for x := 0; x < w; x++ {
			off := srcRow + x*2
			out[y*w+x] = uint16(data[off]) | uint16(data[off+1])<<8
		}
	}
	return out, nil
}

// pixels16ToRGBA converts top-down 16bpp pixels to RGBA. rgb555 selects the
// 5-5-5 layout, otherwise 5-6-5 is used.
func pixels16ToRGBA(pixels []uint16, w, h int, rgb555 bool) []byte {
	out := make([]byte, w*h*4)
	for i, p := range pixels {
		var r, g, b byte
		if rgb555 {
			r = scale(uint8((p>>10)&0x1F), 31)
			g = scale(uint8((p>>5)&0x1F), 31)
			b = scale(uint8(p&0x1F), 31)
		} else {
			r = scale(uint8((p>>11)&0x1F), 31)
			g = scale(uint8((p>>5)&0x3F), 63)
			b = scale(uint8(p&0x1F), 31)
		}
		out[i*4] = r
		out[i*4+1] = g
		out[i*4+2] = b
		out[i*4+3] = 0xFF
	}
	return out
}

func scale(v uint8, max uint8) byte {
	return byte(uint16(v) * 255 / uint16(max))
}
