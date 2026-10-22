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

package clear

import (
	"encoding/binary"
	"fmt"
)

// DecodeNSCodec decodes an NSCodec bitmap (MS-RDPNSC): four RLE-coded planes
// (luma, orange and green chroma, alpha) in YCoCg with optional chroma
// subsampling and color loss. It returns top-down RGBA.
func DecodeNSCodec(src []byte, w, h int) ([]byte, error) {
	if len(src) < 20 {
		return nil, errShort
	}
	var planeSizes [4]int
	total := 0
	for i := range planeSizes {
		planeSizes[i] = int(binary.LittleEndian.Uint32(src[i*4:]))
		total += planeSizes[i]
	}
	colorLoss := int(src[16])
	subsampled := src[17] != 0
	if colorLoss < 1 || colorLoss > 7 {
		return nil, fmt.Errorf("clear: nscodec color loss %d", colorLoss)
	}
	data := src[20:]
	if total > len(data) {
		return nil, errShort
	}

	rw := (w + 7) &^ 7
	rh := (h + 1) &^ 1
	var orig [4]int
	for i := range orig {
		orig[i] = w * h
	}
	if subsampled {
		orig[0] = rw * h
		orig[1] = (rw / 2) * (rh / 2)
		orig[2] = orig[1]
	}

	var planes [4][]byte
	for i := 0; i < 4; i++ {
		size := planeSizes[i]
		plane := make([]byte, rw*rh)
		switch {
		case size == 0:
			for k := 0; k < orig[i]; k++ {
				plane[k] = 0xFF
			}
		case size < orig[i]:
			if err := nscRLE(data[:size], plane, orig[i]); err != nil {
				return nil, err
			}
		default:
			if orig[i] > len(data) {
				return nil, errShort
			}
			copy(plane, data[:orig[i]])
		}
		planes[i] = plane
		data = data[size:]
	}

	shift := uint(colorLoss - 1)
	out := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var yv, co, cg byte
			if subsampled {
				yv = planes[0][y*rw+x]
				co = planes[1][(y/2)*(rw/2)+x/2]
				cg = planes[2][(y/2)*(rw/2)+x/2]
			} else {
				yv = planes[0][y*w+x]
				co = planes[1][y*w+x]
				cg = planes[2][y*w+x]
			}
			coV := int(int8(co << shift))
			cgV := int(int8(cg << shift))
			yy := int(yv)
			o := (y*w + x) * 4
			out[o] = clamp(yy + coV - cgV)
			out[o+1] = clamp(yy + cgV)
			out[o+2] = clamp(yy - coV - cgV)
			out[o+3] = 0xFF
		}
	}
	return out, nil
}

func clamp(v int) byte {
	if v < 0 {
		return 0
	}
	if v > 0xFF {
		return 0xFF
	}
	return byte(v)
}

// nscRLE expands one RLE plane: a repeated byte is followed by a run length,
// and the last four bytes are stored raw.
func nscRLE(in, out []byte, size int) error {
	left := size
	o := 0
	i := 0
	for left > 4 {
		if i >= len(in) {
			return errShort
		}
		value := in[i]
		i++
		switch {
		case left == 5:
			out[o] = value
			o++
			left--
		case i >= len(in):
			return errShort
		case value == in[i]:
			i++
			if i >= len(in) {
				return errShort
			}
			var n int
			if in[i] < 0xFF {
				n = int(in[i]) + 2
				i++
			} else {
				if i+5 > len(in) {
					return errShort
				}
				n = int(binary.LittleEndian.Uint32(in[i+1:]))
				i += 5
			}
			if n > left || o+n > len(out) {
				return fmt.Errorf("clear: nscodec run overflows the plane")
			}
			for k := 0; k < n; k++ {
				out[o+k] = value
			}
			o += n
			left -= n
		default:
			out[o] = value
			o++
			left--
		}
	}
	if i+4 > len(in) || o+4 > len(out) {
		return errShort
	}
	copy(out[o:o+4], in[i:i+4])
	return nil
}
