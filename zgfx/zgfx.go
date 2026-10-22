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

// Package zgfx decompresses RDP8 bulk-compressed data (MS-RDPEGFX 2.2.5,
// RDP_SEGMENTED_DATA), which wraps every PDU on the graphics pipeline channel.
// The decoder keeps a 2.5 MB history shared by all PDUs of a channel, so one
// Decompressor is used per channel, in order.
package zgfx

import (
	"encoding/binary"
	"errors"
)

const (
	segmentedSingle    = 0xE0
	segmentedMultipart = 0xE1
	packetCompressed   = 0x20

	historySize   = 2500000
	maxSegmentOut = 65536
)

var errCorrupt = errors.New("zgfx: corrupt data")

type token struct {
	prefixLength int
	prefixCode   uint32
	valueBits    int
	match        bool
	valueBase    uint32
}

// tokens is the prefix code table of MS-RDPEGFX 3.1.9.1.4: literals carry
// valueBase+bits as the byte, matches carry the distance.
var tokens = []token{
	{1, 0, 8, false, 0},
	{5, 17, 5, true, 0},
	{5, 18, 7, true, 32},
	{5, 19, 9, true, 160},
	{5, 20, 10, true, 672},
	{5, 21, 12, true, 1696},
	{5, 24, 0, false, 0x00},
	{5, 25, 0, false, 0x01},
	{6, 44, 14, true, 5792},
	{6, 45, 15, true, 22176},
	{6, 52, 0, false, 0x02},
	{6, 53, 0, false, 0x03},
	{6, 54, 0, false, 0xFF},
	{7, 92, 18, true, 54944},
	{7, 93, 20, true, 317088},
	{7, 110, 0, false, 0x04},
	{7, 111, 0, false, 0x05},
	{7, 112, 0, false, 0x06},
	{7, 113, 0, false, 0x07},
	{7, 114, 0, false, 0x08},
	{7, 115, 0, false, 0x09},
	{7, 116, 0, false, 0x0A},
	{7, 117, 0, false, 0x0B},
	{7, 118, 0, false, 0x3A},
	{7, 119, 0, false, 0x3B},
	{7, 120, 0, false, 0x3C},
	{7, 121, 0, false, 0x3D},
	{7, 122, 0, false, 0x3E},
	{7, 123, 0, false, 0x3F},
	{7, 124, 0, false, 0x40},
	{7, 125, 0, false, 0x80},
	{8, 188, 20, true, 1365664},
	{8, 189, 21, true, 2414240},
	{8, 252, 0, false, 0x0C},
	{8, 253, 0, false, 0x38},
	{8, 254, 0, false, 0x39},
	{8, 255, 0, false, 0x66},
	{9, 380, 22, true, 4511392},
	{9, 381, 23, true, 8705696},
	{9, 382, 24, true, 17094304},
}

// Decompressor holds the history of one compressed stream.
type Decompressor struct {
	history []byte
	index   int

	in      []byte
	pos     int
	end     int
	bits    uint32
	remain  int
	cur     uint32
	curBits int

	out []byte
}

// New returns a decompressor with an empty history.
func New() *Decompressor {
	return &Decompressor{history: make([]byte, historySize), out: make([]byte, 0, maxSegmentOut)}
}

// Decompress decodes one RDP_SEGMENTED_DATA block.
func (z *Decompressor) Decompress(src []byte) ([]byte, error) {
	if len(src) < 1 {
		return nil, errCorrupt
	}
	switch src[0] {
	case segmentedSingle:
		if err := z.segment(src[1:]); err != nil {
			return nil, err
		}
		return append([]byte(nil), z.out...), nil
	case segmentedMultipart:
		if len(src) < 7 {
			return nil, errCorrupt
		}
		count := int(binary.LittleEndian.Uint16(src[1:]))
		size := int(binary.LittleEndian.Uint32(src[3:]))
		if size > 64<<20 {
			return nil, errCorrupt
		}
		data := src[7:]
		result := make([]byte, 0, size)
		for i := 0; i < count; i++ {
			if len(data) < 4 {
				return nil, errCorrupt
			}
			n := int(binary.LittleEndian.Uint32(data))
			data = data[4:]
			if n > len(data) {
				return nil, errCorrupt
			}
			if err := z.segment(data[:n]); err != nil {
				return nil, err
			}
			data = data[n:]
			if len(result)+len(z.out) > size {
				return nil, errCorrupt
			}
			result = append(result, z.out...)
		}
		if len(result) != size {
			return nil, errCorrupt
		}
		return result, nil
	default:
		return nil, errCorrupt
	}
}

func (z *Decompressor) getBits(n int) {
	for z.curBits < n {
		z.cur <<= 8
		if z.pos < z.end {
			z.cur += uint32(z.in[z.pos])
			z.pos++
		}
		z.curBits += 8
	}
	z.remain -= n
	z.curBits -= n
	z.bits = z.cur >> z.curBits
	z.cur &= (1 << z.curBits) - 1
}

func (z *Decompressor) historyWrite(src []byte) {
	if len(src) > historySize {
		src = src[len(src)-historySize:]
	}
	n := copy(z.history[z.index:], src)
	if n < len(src) {
		copy(z.history, src[n:])
	}
	z.index = (z.index + len(src)) % historySize
}

func (z *Decompressor) segment(seg []byte) error {
	if len(seg) < 2 {
		return errCorrupt
	}
	flags := seg[0]
	body := seg[1:]
	z.out = z.out[:0]
	if flags&packetCompressed == 0 {
		if len(body) > maxSegmentOut {
			return errCorrupt
		}
		z.historyWrite(body)
		z.out = append(z.out, body...)
		return nil
	}

	// The last byte gives the number of padding bits at the end.
	z.in = body
	z.pos = 0
	z.end = len(body) - 1
	pad := int(body[z.end])
	z.remain = 8*z.end - pad
	if z.remain < 0 {
		return errCorrupt
	}
	z.cur, z.curBits = 0, 0

	for z.remain > 0 {
		have, prefix := 0, uint32(0)
		matched := false
		for i := range tokens {
			t := &tokens[i]
			for have < t.prefixLength {
				z.getBits(1)
				prefix = prefix<<1 + z.bits
				have++
			}
			if prefix != t.prefixCode {
				continue
			}
			matched = true
			if !t.match {
				z.getBits(t.valueBits)
				c := byte(t.valueBase + z.bits)
				z.history[z.index] = c
				if z.index++; z.index == historySize {
					z.index = 0
				}
				if len(z.out) >= maxSegmentOut {
					return errCorrupt
				}
				z.out = append(z.out, c)
				break
			}
			z.getBits(t.valueBits)
			distance := int(t.valueBase + z.bits)
			if distance != 0 {
				z.getBits(1)
				count := 3
				if z.bits != 0 {
					count = 4
					extra := 2
					z.getBits(1)
					for z.bits == 1 {
						count *= 2
						extra++
						z.getBits(1)
					}
					z.getBits(extra)
					count += int(z.bits)
				}
				if count > maxSegmentOut-len(z.out) || distance > historySize {
					return errCorrupt
				}
				start := len(z.out)
				z.out = z.out[:start+count]
				z.historyRead(distance, z.out[start:])
				z.historyWrite(z.out[start:])
			} else {
				// Unencoded run of bytes, byte-aligned.
				z.getBits(15)
				count := int(z.bits)
				z.remain -= z.curBits
				z.curBits, z.cur = 0, 0
				if count > maxSegmentOut-len(z.out) || count > z.remain/8 || z.pos+count > z.end {
					return errCorrupt
				}
				run := z.in[z.pos : z.pos+count]
				z.out = append(z.out, run...)
				z.historyWrite(run)
				z.pos += count
				z.remain -= 8 * count
			}
			break
		}
		if !matched {
			return errCorrupt
		}
	}
	return nil
}

// historyRead copies count bytes starting distance bytes back. A match may
// overlap the bytes it produces, which repeats the pattern.
func (z *Decompressor) historyRead(distance int, dst []byte) {
	idx := (z.index + historySize - distance) % historySize
	n := min(len(dst), distance)
	for i := 0; i < n; i++ {
		dst[i] = z.history[(idx+i)%historySize]
	}
	for i := n; i < len(dst); i++ {
		dst[i] = dst[i-n]
	}
}
