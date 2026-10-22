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

// The inverse discrete wavelet transforms of RemoteFX. Both work on int16
// coefficients with C's truncating division, as FreeRDP does, so the output
// matches it exactly.

// dwtDecode is the classic RemoteFX inverse DWT (MS-RDPRFX 3.1.8.1.4) over a
// 64x64 tile laid out as HL1, LH1, HH1 (32x32 each), HL2, LH2, HH2 (16x16),
// HL3, LH3, HH3, LL3 (8x8).
func dwtDecode(buf []int16, tmp []int16) {
	dwtDecodeBlock(buf[3840:], tmp, 8)
	dwtDecodeBlock(buf[3072:], tmp, 16)
	dwtDecodeBlock(buf[0:], tmp, 32)
}

func dwtDecodeBlock(buffer []int16, idwt []int16, sw int) {
	tw := sw << 1
	ll := buffer[sw*sw*3:]
	hl := buffer
	lh := buffer[sw*sw:]
	hh := buffer[sw*sw*2:]
	lDst := idwt
	hDst := idwt[sw*sw*2:]

	for y := 0; y < sw; y++ {
		llr, hlr, lhr, hhr := ll[y*sw:], hl[y*sw:], lh[y*sw:], hh[y*sw:]
		l, h := lDst[y*tw:], hDst[y*tw:]
		l[0] = int16(int(llr[0]) - ((int(hlr[0]) + int(hlr[0]) + 1) >> 1))
		h[0] = int16(int(lhr[0]) - ((int(hhr[0]) + int(hhr[0]) + 1) >> 1))
		for n := 1; n < sw; n++ {
			x := n << 1
			l[x] = int16(int(llr[n]) - ((int(hlr[n-1]) + int(hlr[n]) + 1) >> 1))
			h[x] = int16(int(lhr[n]) - ((int(hhr[n-1]) + int(hhr[n]) + 1) >> 1))
		}
		n := 0
		for ; n < sw-1; n++ {
			x := n << 1
			l[x+1] = int16((int(hlr[n]) << 1) + ((int(l[x]) + int(l[x+2])) >> 1))
			h[x+1] = int16((int(hhr[n]) << 1) + ((int(h[x]) + int(h[x+2])) >> 1))
		}
		x := n << 1
		l[x+1] = int16((int(hlr[n]) << 1) + int(l[x]))
		h[x+1] = int16((int(hhr[n]) << 1) + int(h[x]))
	}

	for x := 0; x < tw; x++ {
		li := x
		hi := x + sw*tw
		d := x
		buffer[d] = int16(int(idwt[li]) - ((int(idwt[hi])*2 + 1) >> 1))
		for n := 1; n < sw; n++ {
			li += tw
			hi += tw
			buffer[d+2*tw] = int16(int(idwt[li]) - ((int(idwt[hi-tw]) + int(idwt[hi]) + 1) >> 1))
			buffer[d+tw] = int16((int(idwt[hi-tw]) << 1) + ((int(buffer[d]) + int(buffer[d+2*tw])) >> 1))
			d += 2 * tw
		}
		buffer[d+tw] = int16((int(idwt[hi]) << 1) + ((int(buffer[d]) * 2) >> 1))
	}
}

// dwtExtrapolateDecode is the "reduce extrapolate" inverse DWT of the
// progressive codec (MS-RDPEGFX 3.2.8.1.2.1), whose bands are not powers of
// two: levels are laid out from HL1 at 0 to LL3 at 4015.
func dwtExtrapolateDecode(buf []int16, tmp []int16) {
	extrapolateBlock(buf[3807:], tmp, 3)
	extrapolateBlock(buf[3007:], tmp, 2)
	extrapolateBlock(buf[0:], tmp, 1)
}

func bandL(level int) int { return (64 >> uint(level)) + 1 }

func bandH(level int) int {
	if level == 1 {
		return (64 >> 1) - 1
	}
	return (64 + (1 << uint(level-1))) >> uint(level)
}

func extrapolateBlock(buffer []int16, temp []int16, level int) {
	nL, nH := bandL(level), bandH(level)
	off := 0
	hl := buffer[off:]
	off += nH * nL
	lh := buffer[off:]
	off += nL * nH
	hh := buffer[off:]
	off += nH * nH
	ll := buffer[off:]
	step := nL + nH
	l := temp
	h := temp[nL*step:]

	idwtX(ll, nL, hl, nH, l, step, nL, nH, nL)
	idwtX(lh, nL, hh, nH, h, step, nL, nH, nH)
	idwtY(l, step, h, step, buffer, step, nL, nH, nL+nH)
}

// div2 is C's int division by 2, truncating toward zero.
func div2(v int) int { return v / 2 }

func idwtX(low []int16, lowStep int, high []int16, highStep int, dst []int16, dstStep int, lowCount, highCount, dstCount int) {
	for i := 0; i < dstCount; i++ {
		pL := low[i*lowStep:]
		pH := high[i*highStep:]
		pX := dst[i*dstStep:]
		li, hi, xi := 0, 0, 0
		h0 := int(pH[hi])
		hi++
		l0 := int(pL[li])
		li++
		x0 := int(int16(l0 - h0))
		x2 := x0
		for j := 0; j < highCount-1; j++ {
			h1 := int(pH[hi])
			hi++
			l0 = int(pL[li])
			li++
			x2 = int(int16(l0 - div2(h0+h1)))
			x1 := int(int16(div2(x0+x2) + 2*h0))
			pX[xi] = int16(x0)
			pX[xi+1] = int16(x1)
			xi += 2
			x0 = x2
			h0 = h1
		}
		if lowCount <= highCount+1 {
			if lowCount <= highCount {
				pX[xi] = int16(x2)
				pX[xi+1] = int16(x2 + 2*h0)
			} else {
				l0 = int(pL[li])
				x0 = int(int16(l0 - h0))
				pX[xi] = int16(x2)
				pX[xi+1] = int16(div2(x0+x2) + 2*h0)
				pX[xi+2] = int16(x0)
			}
		} else {
			l0 = int(pL[li])
			li++
			x0 = int(int16(l0 - div2(h0)))
			pX[xi] = int16(x2)
			pX[xi+1] = int16(div2(x0+x2) + 2*h0)
			pX[xi+2] = int16(x0)
			l0 = int(pL[li])
			pX[xi+3] = int16(div2(x0 + l0))
		}
	}
}

func idwtY(low []int16, lowStep int, high []int16, highStep int, dst []int16, dstStep int, lowCount, highCount, dstCount int) {
	for i := 0; i < dstCount; i++ {
		li, hi, xi := i, i, i
		h0 := int(high[hi])
		hi += highStep
		l0 := int(low[li])
		li += lowStep
		x0 := int(int16(l0 - h0))
		x2 := x0
		for j := 0; j < highCount-1; j++ {
			h1 := int(high[hi])
			hi += highStep
			l0 = int(low[li])
			li += lowStep
			x2 = int(int16(l0 - div2(h0+h1)))
			x1 := int(int16(div2(x0+x2) + 2*h0))
			dst[xi] = int16(x0)
			xi += dstStep
			dst[xi] = int16(x1)
			xi += dstStep
			x0 = x2
			h0 = h1
		}
		if lowCount <= highCount+1 {
			if lowCount <= highCount {
				dst[xi] = int16(x2)
				xi += dstStep
				dst[xi] = int16(x2 + 2*h0)
			} else {
				l0 = int(low[li])
				x0 = int(int16(l0 - h0))
				dst[xi] = int16(x2)
				xi += dstStep
				dst[xi] = int16(div2(x0+x2) + 2*h0)
				xi += dstStep
				dst[xi] = int16(x0)
			}
		} else {
			l0 = int(low[li])
			li += lowStep
			x0 = int(int16(l0 - div2(h0)))
			dst[xi] = int16(x2)
			xi += dstStep
			dst[xi] = int16(div2(x0+x2) + 2*h0)
			xi += dstStep
			dst[xi] = int16(x0)
			xi += dstStep
			l0 = int(low[li])
			dst[xi] = int16(div2(x0 + l0))
		}
	}
}
