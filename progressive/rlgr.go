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

package progressive

import "math/bits"

// bitReader reads bits most significant first. Reading past the end yields
// zeros, as the RemoteFX bit streams expect.
type bitReader struct {
	b     []byte
	pos   int
	total int
}

func newBitReader(b []byte) *bitReader {
	return &bitReader{b: b, total: len(b) * 8}
}

func (r *bitReader) remaining() int {
	return r.total - r.pos
}

// peek returns the next n (at most 32) bits without consuming them.
func (r *bitReader) peek(n int) uint32 {
	if n == 0 {
		return 0
	}
	idx := r.pos >> 3
	var v uint64
	for k := 0; k < 5; k++ {
		v <<= 8
		if idx+k >= 0 && idx+k < len(r.b) {
			v |= uint64(r.b[idx+k])
		}
	}
	shift := 40 - (r.pos & 7) - n
	return uint32(v>>uint(shift)) & uint32(1<<uint(n)-1)
}

func (r *bitReader) read(n int) uint32 {
	v := r.peek(n)
	r.pos += n
	return v
}

func (r *bitReader) skip(n int) {
	r.pos += n
}

// run counts how many of the next bits equal bit, without going past the end.
func (r *bitReader) run(bit uint32) int {
	n := 0
	for {
		left := r.remaining() - n
		if left <= 0 {
			return n
		}
		save := r.pos
		r.pos += n
		w := r.peek(32)
		r.pos = save
		if bit == 1 {
			w = ^w
		}
		c := bits.LeadingZeros32(w)
		if c > left {
			c = left
		}
		n += c
		if c < 32 {
			return n
		}
	}
}

// RLGR modes (MS-RDPRFX 3.1.8.1.7.1).
const (
	rlgr1 = 1
	rlgr3 = 3
)

const (
	kpMax = 80
	lsGR  = 3
	upGR  = 4
	dnGR  = 6
	uqGR  = 3
	dqGR  = 3
)

// rlgrDecode decodes adaptive run-length Golomb-Rice coded coefficients into
// dst, zero-filling what the stream does not cover. It follows FreeRDP's
// rfx_rlgr_decode bit for bit.
func rlgrDecode(mode int, src []byte, dst []int16) {
	k, kp := 1, 1<<lsGR
	kr, krp := 1, 1<<lsGR
	r := newBitReader(src)
	out := 0
	n := len(dst)

	readCode := func() (uint16, int, bool) {
		vk := r.run(1)
		r.skip(vk)
		if r.remaining() < 1 {
			return 0, 0, false
		}
		r.skip(1)
		if r.remaining() < kr {
			return 0, 0, false
		}
		code := uint16(0)
		if kr > 0 {
			code = uint16(r.read(kr))
		}
		code |= uint16(vk << uint(kr))
		if vk == 0 {
			krp = max(krp-2, 0)
			kr = krp >> lsGR
		} else if vk != 1 {
			krp = min(krp+vk, kpMax)
			kr = krp >> lsGR
		}
		return code, vk, true
	}

	for r.remaining() > 0 && out < n {
		if k != 0 {
			// Run-length mode.
			vk := r.run(0)
			r.skip(vk)
			if r.remaining() < 1 {
				break
			}
			r.skip(1)
			run := 0
			for ; vk > 0; vk-- {
				run += 1 << uint(k)
				kp = min(kp+upGR, kpMax)
				k = kp >> lsGR
			}
			if r.remaining() < k {
				break
			}
			run += int(r.read(k))
			if r.remaining() < 1 {
				break
			}
			sign := r.read(1)
			code, _, ok := readCode()
			if !ok {
				break
			}
			kp = max(kp-dnGR, 0)
			k = kp >> lsGR
			mag := int16(code + 1)
			if sign != 0 {
				mag = -mag
			}
			run = min(run, n-out)
			for i := 0; i < run; i++ {
				dst[out+i] = 0
			}
			out += run
			if out < n {
				dst[out] = mag
				out++
			}
			continue
		}

		// Golomb-Rice mode.
		code, _, ok := readCode()
		if !ok {
			break
		}
		if mode == rlgr1 {
			var mag int16
			if code == 0 {
				kp = min(kp+uqGR, kpMax)
				k = kp >> lsGR
			} else {
				kp = max(kp-dqGR, 0)
				k = kp >> lsGR
				if c := int(code); c&1 != 0 {
					mag = int16(-((c + 1) >> 1))
				} else {
					mag = int16(c >> 1)
				}
			}
			dst[out] = mag
			out++
			continue
		}

		// RLGR3: the code splits into two values.
		nIdx := 0
		if code != 0 {
			nIdx = 32 - bits.LeadingZeros32(uint32(code))
		}
		if r.remaining() < nIdx {
			break
		}
		val1 := uint32(0)
		if nIdx > 0 {
			val1 = r.read(nIdx)
		}
		val2 := uint32(code) - val1
		if val1 != 0 && val2 != 0 {
			kp = max(kp-2*dqGR, 0)
			k = kp >> lsGR
		} else if val1 == 0 && val2 == 0 {
			kp = min(kp+2*uqGR, kpMax)
			k = kp >> lsGR
		}
		for _, v := range []uint32{val1, val2} {
			var mag int16
			if v&1 != 0 {
				mag = -int16((v + 1) >> 1)
			} else {
				mag = int16(v >> 1)
			}
			if out < n {
				dst[out] = mag
				out++
			}
		}
	}
	for ; out < n; out++ {
		dst[out] = 0
	}
}
