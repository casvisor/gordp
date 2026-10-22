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

// Planar format header bits (MS-RDPEGDI 2.2.2.5.1).
const (
	planarColorLossMask = 0x07
	planarChromaSubsmpl = 0x08
	planarRLE           = 0x10
	planarNoAlpha       = 0x20
)

// decodePlanar32 decodes a 32bpp RDP 6.0 planar-compressed bitmap into top-down
// RGBA. It handles the lossless case (no color loss, no chroma subsampling),
// which is what Windows sends for a 32bpp desktop, with either raw or
// RLE-compressed colour planes.
func decodePlanar32(src []byte, w, h int) ([]byte, error) {
	return DecodePlanar(src, w, h, true)
}

// DecodePlanar decodes an RDP 6.0 planar bitmap into top-down RGBA. Bitmap
// updates store the planes bottom-up; the graphics pipeline (MS-RDPEGFX)
// stores them top-down.
func DecodePlanar(src []byte, w, h int, bottomUp bool) ([]byte, error) {
	if len(src) < 1 {
		return nil, errShort
	}
	format := src[0]
	s := 1

	if format&planarColorLossMask != 0 || format&planarChromaSubsmpl != 0 {
		return nil, fmt.Errorf("bitmap: planar color loss / chroma subsampling not supported")
	}
	rle := format&planarRLE != 0
	noAlpha := format&planarNoAlpha != 0

	planeCount := 4
	if noAlpha {
		planeCount = 3
	}

	planes := make([][]byte, planeCount)
	for i := 0; i < planeCount; i++ {
		var (
			plane []byte
			used  int
			err   error
		)
		if rle {
			plane, used, err = decodePlanarRLEPlane(src[s:], w, h)
		} else {
			plane, used, err = rawPlane(src[s:], w, h)
		}
		if err != nil {
			return nil, err
		}
		planes[i] = plane
		s += used
	}

	// Plane order is alpha (optional), red, green, blue.
	var rp, gp, bp []byte
	if noAlpha {
		rp, gp, bp = planes[0], planes[1], planes[2]
	} else {
		rp, gp, bp = planes[1], planes[2], planes[3]
	}

	out := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		srcRow := y * w
		if bottomUp {
			srcRow = (h - 1 - y) * w
		}
		for x := 0; x < w; x++ {
			i := srcRow + x
			dst := (y*w + x) * 4
			out[dst] = rp[i]
			out[dst+1] = gp[i]
			out[dst+2] = bp[i]
			out[dst+3] = 0xFF
		}
	}
	return out, nil
}

func rawPlane(src []byte, w, h int) ([]byte, int, error) {
	n := w * h
	if len(src) < n {
		return nil, 0, errShort
	}
	plane := make([]byte, n)
	copy(plane, src[:n])
	return plane, n, nil
}

// decodePlanarRLEPlane decompresses one RLE-encoded colour plane (MS-RDPEGDI
// 3.1.9.2). It is a two-step process: a plain byte RLE (a control byte giving
// some raw bytes then a run that repeats the last raw byte) yields a plane of
// zig-zag deltas, then a vertical pass turns each scanline's deltas into
// absolute bytes relative to the scanline above.
func decodePlanarRLEPlane(src []byte, w, h int) ([]byte, int, error) {
	plane := make([]byte, w*h)
	s := 0

	for y := 0; y < h; y++ {
		rowStart := y * w
		x := 0
		var last byte
		for x < w {
			if s >= len(src) {
				return nil, 0, errShort
			}
			control := src[s]
			s++
			runLength := int(control & 0x0F)
			rawBytes := int((control >> 4) & 0x0F)
			switch runLength {
			case 1:
				runLength = rawBytes + 16
				rawBytes = 0
			case 2:
				runLength = rawBytes + 32
				rawBytes = 0
			}

			for i := 0; i < rawBytes && x < w; i++ {
				if s >= len(src) {
					return nil, 0, errShort
				}
				last = src[s]
				s++
				plane[rowStart+x] = last
				x++
			}
			for i := 0; i < runLength && x < w; i++ {
				plane[rowStart+x] = last
				x++
			}
		}
	}

	// Vertical un-delta: row 0 is absolute, each later row is the row above
	// plus the zig-zag signed delta.
	for y := 1; y < h; y++ {
		for x := 0; x < w; x++ {
			plane[y*w+x] = plane[(y-1)*w+x] + zigzagDelta(plane[y*w+x])
		}
	}
	return plane, s, nil
}

// zigzagDelta decodes a planar delta byte into a signed value (as a byte so the
// caller's addition wraps mod 256): even encodes +d/2, odd encodes -(d/2+1).
func zigzagDelta(d byte) byte {
	if d&1 != 0 {
		return byte(-int((d >> 1) + 1))
	}
	return d >> 1
}
