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

// Package progressive decodes the RemoteFX Progressive codec (MS-RDPEGFX
// 2.2.4.2), which Windows uses on the graphics pipeline for images: each 64x64
// tile arrives first at low quality and is then upgraded pass by pass until it
// is exact. The decoder keeps every tile's coefficients per surface.
//
// The arithmetic follows FreeRDP's progressive decoder, so the output is the
// same pixel for pixel.
package progressive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"runtime"
	"sync"
)

// Block types (MS-RDPEGFX 2.2.4.2.1).
const (
	wbtSync        = 0xCCC0
	wbtFrameBegin  = 0xCCC1
	wbtFrameEnd    = 0xCCC2
	wbtContext     = 0xCCC3
	wbtRegion      = 0xCCC4
	wbtTileSimple  = 0xCCC5
	wbtTileFirst   = 0xCCC6
	wbtTileUpgrade = 0xCCC7

	tileDifference     = 0x01
	reduceExtrapolate  = 0x01
	coefficientsLength = 4096
)

var errShort = errors.New("progressive: data too short")

// quant holds one 4-bit value per subband, in the wire order LL3, HL3, LH3,
// HH3, HL2, LH2, HH2, HL1, LH1, HH1. Like FreeRDP's it is bytes, so it wraps.
type quant [10]uint8

const (
	qLL3 = iota
	qHL3
	qLH3
	qHH3
	qHL2
	qLH2
	qHH2
	qHL1
	qLH1
	qHH1
)

func readQuant(b []byte) quant {
	var q quant
	for i := 0; i < 5; i++ {
		q[2*i] = b[i] & 0x0F
		q[2*i+1] = b[i] >> 4
	}
	return q
}

func (q quant) add(o quant) quant {
	for i := range q {
		q[i] += o[i]
	}
	return q
}

func (q quant) sub(o quant) quant {
	for i := range q {
		q[i] -= o[i]
	}
	return q
}

func (q quant) minus(v uint8) quant {
	for i := range q {
		q[i] -= v
	}
	return q
}

type progQuant struct {
	y, cb, cr quant
}

// Tile is a decoded part of a surface.
type Tile struct {
	Rect image.Rectangle
	// RGBA holds Rect.Dx()*Rect.Dy() opaque pixels.
	RGBA []byte
}

type tile struct {
	xIdx, yIdx int
	flags      byte
	quality    byte
	quantY     byte
	quantCb    byte
	quantCr    byte
	blockType  uint16

	// first / simple data
	data [3][]byte
	// upgrade data: srl and raw per component
	srl, raw [3][]byte

	pixels  []byte // 64x64 RGBA
	sign    [3][]int16
	current [3][]int16
	bitPos  [3]quant
	pass    int
}

func newTile() *tile {
	t := &tile{pixels: make([]byte, 64*64*4)}
	for i := range t.pixels {
		t.pixels[i] = 0xFF
	}
	for c := 0; c < 3; c++ {
		t.sign[c] = make([]int16, coefficientsLength)
		t.current[c] = make([]int16, coefficientsLength)
	}
	return t
}

type surface struct {
	width, height int
	gridWidth     int
	tiles         map[int]*tile
}

// Decoder decodes the progressive codec for all surfaces of a session.
type Decoder struct {
	surfaces map[uint16]*surface
	ctxFlags byte
}

// NewDecoder returns a decoder with no surfaces.
func NewDecoder() *Decoder {
	return &Decoder{surfaces: map[uint16]*surface{}}
}

// CreateSurface starts tracking tiles for a surface.
func (d *Decoder) CreateSurface(id uint16, width, height int) {
	d.surfaces[id] = &surface{
		width:     width,
		height:    height,
		gridWidth: (width + (64 - width%64)) / 64,
		tiles:     map[int]*tile{},
	}
}

// DeleteSurface drops a surface's tiles.
func (d *Decoder) DeleteSurface(id uint16) {
	delete(d.surfaces, id)
}

type region struct {
	rects    []image.Rectangle
	quants   []quant
	progs    []progQuant
	flags    byte
	numTiles int
	tiles    []*tile
}

// Decode decodes one progressive bitmap for a surface and returns the parts of
// the surface it changed.
func (d *Decoder) Decode(id uint16, src []byte) ([]Tile, error) {
	s := d.surfaces[id]
	if s == nil {
		return nil, fmt.Errorf("progressive: unknown surface %d", id)
	}
	var out []Tile
	frameBegun := false
	for len(src) > 0 {
		if len(src) < 6 {
			return nil, errShort
		}
		blockType := binary.LittleEndian.Uint16(src)
		blockLen := int(binary.LittleEndian.Uint32(src[2:]))
		if blockLen < 6 || blockLen > len(src) {
			return nil, fmt.Errorf("progressive: bad block length %d", blockLen)
		}
		body := src[6:blockLen]
		src = src[blockLen:]
		switch blockType {
		case wbtSync:
			if len(body) != 6 || binary.LittleEndian.Uint32(body) != 0xCACCACCA {
				return nil, fmt.Errorf("progressive: bad sync block")
			}
		case wbtFrameBegin:
			frameBegun = true
		case wbtFrameEnd:
		case wbtContext:
			if len(body) != 4 {
				return nil, fmt.Errorf("progressive: bad context block")
			}
			if binary.LittleEndian.Uint16(body[1:]) != 64 {
				return nil, fmt.Errorf("progressive: tile size must be 64")
			}
			d.ctxFlags = body[3]
		case wbtRegion:
			if !frameBegun {
				continue
			}
			reg, err := s.parseRegion(body)
			if err != nil {
				return nil, err
			}
			if err := reg.decodeTiles(); err != nil {
				return nil, err
			}
			out = append(out, s.output(reg)...)
		default:
			return nil, fmt.Errorf("progressive: unknown block 0x%04x", blockType)
		}
	}
	return out, nil
}

func (s *surface) parseRegion(b []byte) (*region, error) {
	if len(b) < 12 {
		return nil, errShort
	}
	if b[0] != 64 {
		return nil, fmt.Errorf("progressive: tile size must be 64")
	}
	numRects := int(binary.LittleEndian.Uint16(b[1:]))
	numQuant := int(b[3])
	numProg := int(b[4])
	reg := &region{flags: b[5], numTiles: int(binary.LittleEndian.Uint16(b[6:]))}
	tileDataSize := int(binary.LittleEndian.Uint32(b[8:]))
	if numRects < 1 || numQuant > 7 {
		return nil, fmt.Errorf("progressive: bad region header")
	}
	p := 12
	if len(b) < p+numRects*8+numQuant*5+numProg*16+tileDataSize {
		return nil, errShort
	}
	for i := 0; i < numRects; i++ {
		x := int(binary.LittleEndian.Uint16(b[p:]))
		y := int(binary.LittleEndian.Uint16(b[p+2:]))
		w := int(binary.LittleEndian.Uint16(b[p+4:]))
		h := int(binary.LittleEndian.Uint16(b[p+6:]))
		reg.rects = append(reg.rects, image.Rect(x, y, x+w, y+h))
		p += 8
	}
	for i := 0; i < numQuant; i++ {
		q := readQuant(b[p:])
		for _, v := range q {
			if v < 6 || v > 15 {
				return nil, fmt.Errorf("progressive: quantization value %d out of range", v)
			}
		}
		reg.quants = append(reg.quants, q)
		p += 5
	}
	for i := 0; i < numProg; i++ {
		reg.progs = append(reg.progs, progQuant{y: readQuant(b[p+1:]), cb: readQuant(b[p+6:]), cr: readQuant(b[p+11:])})
		p += 16
	}

	tiles := b[p : p+tileDataSize]
	for len(tiles) > 0 {
		if len(tiles) < 6 {
			return nil, errShort
		}
		blockType := binary.LittleEndian.Uint16(tiles)
		blockLen := int(binary.LittleEndian.Uint32(tiles[2:]))
		if blockLen < 6 || blockLen > len(tiles) {
			return nil, fmt.Errorf("progressive: bad tile length %d", blockLen)
		}
		body := tiles[6:blockLen]
		tiles = tiles[blockLen:]
		if err := s.readTile(reg, blockType, body); err != nil {
			return nil, err
		}
	}
	if len(reg.tiles) != reg.numTiles {
		return nil, fmt.Errorf("progressive: %d tiles, expected %d", len(reg.tiles), reg.numTiles)
	}
	return reg, nil
}

func (s *surface) readTile(reg *region, blockType uint16, b []byte) error {
	var hdr []byte
	var lengths []int
	switch blockType {
	case wbtTileSimple, wbtTileFirst:
		n := 16
		if blockType == wbtTileFirst {
			n = 17
		}
		if len(b) < n {
			return errShort
		}
		hdr = b[:n]
		lengths = make([]int, 4)
		for i := range lengths {
			lengths[i] = int(binary.LittleEndian.Uint16(b[n-8+2*i:]))
		}
		b = b[n:]
	case wbtTileUpgrade:
		if len(b) < 20 {
			return errShort
		}
		hdr = b[:20]
		lengths = make([]int, 6)
		for i := range lengths {
			lengths[i] = int(binary.LittleEndian.Uint16(b[8+2*i:]))
		}
		b = b[20:]
	default:
		return fmt.Errorf("progressive: unknown tile block 0x%04x", blockType)
	}
	parts := make([][]byte, len(lengths))
	for i, n := range lengths {
		if n > len(b) {
			return errShort
		}
		parts[i] = b[:n]
		b = b[n:]
	}
	if len(b) != 0 {
		return fmt.Errorf("progressive: %d bytes left in a tile block", len(b))
	}

	xIdx := int(binary.LittleEndian.Uint16(hdr[3:]))
	yIdx := int(binary.LittleEndian.Uint16(hdr[5:]))
	key := yIdx*s.gridWidth + xIdx
	t := s.tiles[key]
	if t == nil {
		t = newTile()
		s.tiles[key] = t
	}
	t.blockType = blockType
	t.quantY, t.quantCb, t.quantCr = hdr[0], hdr[1], hdr[2]
	t.xIdx, t.yIdx = xIdx, yIdx
	switch blockType {
	case wbtTileSimple:
		t.flags = hdr[7]
		t.quality = 0xFF
		t.data = [3][]byte{parts[0], parts[1], parts[2]}
	case wbtTileFirst:
		t.flags = hdr[7]
		t.quality = hdr[8]
		t.data = [3][]byte{parts[0], parts[1], parts[2]}
	case wbtTileUpgrade:
		t.flags = 0
		t.quality = hdr[7]
		t.srl = [3][]byte{parts[0], parts[2], parts[4]}
		t.raw = [3][]byte{parts[1], parts[3], parts[5]}
	}
	reg.tiles = append(reg.tiles, t)
	return nil
}

// decodeTiles decodes the region's tiles in parallel; each tile's state is its
// own.
func (reg *region) decodeTiles() error {
	errs := make([]error, len(reg.tiles))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i, t := range reg.tiles {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t *tile) {
			defer func() { <-sem; wg.Done() }()
			if t.blockType == wbtTileUpgrade {
				errs[i] = reg.upgradeTile(t)
			} else {
				errs[i] = reg.firstTile(t)
			}
		}(i, t)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (reg *region) quantsFor(t *tile) ([3]quant, progQuant, error) {
	var q [3]quant
	for c, idx := range []byte{t.quantY, t.quantCb, t.quantCr} {
		if int(idx) >= len(reg.quants) {
			return q, progQuant{}, fmt.Errorf("progressive: quant index %d out of range", idx)
		}
		q[c] = reg.quants[idx]
	}
	if t.quality == 0xFF {
		return q, progQuant{}, nil
	}
	if int(t.quality) >= len(reg.progs) {
		return q, progQuant{}, fmt.Errorf("progressive: quality %d out of range", t.quality)
	}
	return q, reg.progs[t.quality], nil
}

func (p progQuant) component(c int) quant {
	switch c {
	case 0:
		return p.y
	case 1:
		return p.cb
	default:
		return p.cr
	}
}

func (reg *region) firstTile(t *tile) error {
	q, prog, err := reg.quantsFor(t)
	if err != nil {
		return err
	}
	t.pass = 1
	diff := t.flags&tileDifference != 0
	extrapolate := reg.flags&reduceExtrapolate != 0
	var planes [3][]int16
	temp := make([]int16, coefficientsLength*2)
	for c := 0; c < 3; c++ {
		pq := prog.component(c)
		t.bitPos[c] = q[c].add(pq)
		shift := q[c].add(pq).minus(1)
		buf := make([]int16, coefficientsLength)
		rlgrDecode(rlgr1, t.data[c], buf)
		copy(t.sign[c], buf)
		if !extrapolate {
			differential(buf[4032:4096])
			shiftBand(buf[0:1024], shift[qHL1])
			shiftBand(buf[1024:2048], shift[qLH1])
			shiftBand(buf[2048:3072], shift[qHH1])
			shiftBand(buf[3072:3328], shift[qHL2])
			shiftBand(buf[3328:3584], shift[qLH2])
			shiftBand(buf[3584:3840], shift[qHH2])
			shiftBand(buf[3840:3904], shift[qHL3])
			shiftBand(buf[3904:3968], shift[qLH3])
			shiftBand(buf[3968:4032], shift[qHH3])
			shiftBand(buf[4032:4096], shift[qLL3])
		} else {
			shiftBand(buf[0:1023], shift[qHL1])
			shiftBand(buf[1023:2046], shift[qLH1])
			shiftBand(buf[2046:3007], shift[qHH1])
			shiftBand(buf[3007:3279], shift[qHL2])
			shiftBand(buf[3279:3551], shift[qLH2])
			shiftBand(buf[3551:3807], shift[qHH2])
			shiftBand(buf[3807:3879], shift[qHL3])
			shiftBand(buf[3879:3951], shift[qLH3])
			shiftBand(buf[3951:4015], shift[qHH3])
			differential(buf[4015:4096])
			shiftBand(buf[4015:4096], shift[qLL3])
		}
		if diff {
			for i := range buf {
				v := buf[i] + t.current[c][i]
				buf[i], t.current[c][i] = v, v
			}
		} else {
			copy(t.current[c], buf)
		}
		if extrapolate {
			dwtExtrapolateDecode(buf, temp)
		} else {
			dwtDecode(buf, temp)
		}
		planes[c] = buf
	}
	ycbcrToRGBA(planes, t.pixels)
	return nil
}

// Subband lengths and offsets of the extrapolated layout, in upgrade order.
var upgradeBands = []struct {
	q, off, n int
	nonLL     bool
}{
	{qHL1, 0, 1023, true},
	{qLH1, 1023, 1023, true},
	{qHH1, 2046, 961, true},
	{qHL2, 3007, 272, true},
	{qLH2, 3279, 272, true},
	{qHH2, 3551, 256, true},
	{qHL3, 3807, 72, true},
	{qLH3, 3879, 72, true},
	{qHH3, 3951, 64, true},
	{qLL3, 4015, 81, false},
}

func (reg *region) upgradeTile(t *tile) error {
	q, prog, err := reg.quantsFor(t)
	if err != nil {
		return err
	}
	t.pass++
	extrapolate := reg.flags&reduceExtrapolate != 0
	var planes [3][]int16
	temp := make([]int16, coefficientsLength*2)
	for c := 0; c < 3; c++ {
		pq := prog.component(c)
		bitPos := q[c].add(pq)
		numBits := t.bitPos[c].sub(bitPos)
		shift := q[c].add(pq).minus(1)
		t.bitPos[c] = bitPos

		st := &upgradeState{kp: 8, srl: newBitReader(t.srl[c]), raw: newBitReader(t.raw[c])}
		cur, sign := t.current[c], t.sign[c]
		for _, band := range upgradeBands {
			st.nonLL = band.nonLL
			st.upgradeBlock(cur[band.off:band.off+band.n], sign[band.off:band.off+band.n], int(shift[band.q]), int(numBits[band.q]))
		}
		// Both streams must be used up exactly, after padding to a byte.
		if pad := st.raw.pos % 8; pad != 0 {
			st.raw.skip(8 - pad)
		}
		if pad := st.srl.pos % 8; pad != 0 {
			st.srl.skip(8 - pad)
		}
		if st.srl.remaining() == 8 {
			st.srl.skip(8)
		}
		if (st.raw.pos+7)/8 != len(t.raw[c]) || (st.srl.pos+7)/8 != len(t.srl[c]) {
			return fmt.Errorf("progressive: upgrade streams not used up")
		}

		buf := make([]int16, coefficientsLength)
		copy(buf, cur)
		if extrapolate {
			dwtExtrapolateDecode(buf, temp)
		} else {
			dwtDecode(buf, temp)
		}
		planes[c] = buf
	}
	ycbcrToRGBA(planes, t.pixels)
	return nil
}

type upgradeState struct {
	nonLL    bool
	srl, raw *bitReader
	kp       int
	nz       int
	mode     bool
}

func (st *upgradeState) upgradeBlock(buf, sign []int16, shift, numBits int) {
	if numBits == 0 {
		return
	}
	if !st.nonLL {
		for i := range buf {
			input := int16(st.raw.read(numBits))
			buf[i] += input << uint(shift)
		}
		return
	}
	for i := range buf {
		var input int16
		switch {
		case sign[i] > 0:
			input = int16(st.raw.read(numBits))
		case sign[i] < 0:
			input = -int16(st.raw.read(numBits))
		default:
			input = st.srlRead(numBits)
			sign[i] = input
		}
		buf[i] += int16(uint32(input) << uint(shift))
	}
}

// srlRead reads one value of the "simplified run-length" coding used for
// coefficients that were zero so far.
func (st *upgradeState) srlRead(numBits int) int16 {
	if st.nz > 0 {
		st.nz--
		return 0
	}
	k := st.kp / 8
	if !st.mode {
		if st.srl.read(1) == 0 {
			st.nz = 1 << uint(k)
			st.kp = min(st.kp+4, 80)
			st.nz--
			return 0
		}
		st.nz = 0
		st.mode = true
		if k > 0 {
			st.nz = int(st.srl.read(k))
		}
		if st.nz > 0 {
			st.nz--
			return 0
		}
	}
	st.mode = false
	sign := st.srl.read(1)
	if st.kp < 6 {
		st.kp = 0
	} else {
		st.kp -= 6
	}
	if numBits == 1 {
		if sign != 0 {
			return -1
		}
		return 1
	}
	mag := 1
	limit := 1<<uint(numBits) - 1
	for mag < limit {
		if st.srl.read(1) != 0 {
			break
		}
		mag++
	}
	if mag > 32767 {
		mag = 32767
	}
	if sign != 0 {
		return int16(-mag)
	}
	return int16(mag)
}

func differential(b []int16) {
	for i := 1; i < len(b); i++ {
		b[i] += b[i-1]
	}
}

func shiftBand(b []int16, shift uint8) {
	if shift == 0 {
		return
	}
	for i := range b {
		b[i] <<= shift
	}
}

// YCbCr to RGB with FreeRDP's fixed-point constants.
var (
	crR = fixed16(1.402525)
	crG = fixed16(0.714401)
	cbG = fixed16(0.343730)
	cbB = fixed16(1.769905)
)

// fixed16 truncates f * 2^16 the way C converts the float product.
func fixed16(f float32) int64 {
	return int64(f * 65536)
}

func ycbcrToRGBA(p [3][]int16, out []byte) {
	for i := 0; i < 64*64; i++ {
		y := int64(int32(uint32(int32(p[0][i])+4096) << 16))
		cb := int64(p[1][i])
		cr := int64(p[2][i])
		r := int16((cr*crR+y)>>16) >> 5
		g := int16((y-cb*cbG-cr*crG)>>16) >> 5
		b := int16((cb*cbB+y)>>16) >> 5
		o := i * 4
		out[o] = clip(r)
		out[o+1] = clip(g)
		out[o+2] = clip(b)
		out[o+3] = 0xFF
	}
}

func clip(v int16) byte {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return byte(v)
}

// output cuts the region's tiles to its rectangles and the surface.
func (s *surface) output(reg *region) []Tile {
	bounds := image.Rect(0, 0, s.width, s.height)
	var out []Tile
	seen := map[*tile]bool{}
	for _, t := range reg.tiles {
		if seen[t] {
			continue
		}
		seen[t] = true
		tr := image.Rect(t.xIdx*64, t.yIdx*64, t.xIdx*64+64, t.yIdx*64+64)
		for _, rr := range clipRects(reg.rects, tr.Intersect(bounds)) {
			w, h := rr.Dx(), rr.Dy()
			px := make([]byte, w*h*4)
			for y := 0; y < h; y++ {
				src := ((rr.Min.Y-tr.Min.Y+y)*64 + rr.Min.X - tr.Min.X) * 4
				copy(px[y*w*4:(y+1)*w*4], t.pixels[src:src+w*4])
			}
			out = append(out, Tile{Rect: rr, RGBA: px})
		}
	}
	return out
}

// clipRects intersects the rectangles with r and removes overlaps between
// them, so every pixel is sent once.
func clipRects(rects []image.Rectangle, r image.Rectangle) []image.Rectangle {
	var out []image.Rectangle
	for _, rect := range rects {
		pieces := []image.Rectangle{rect.Intersect(r)}
		for _, prev := range out {
			var next []image.Rectangle
			for _, p := range pieces {
				next = append(next, subtract(p, prev)...)
			}
			pieces = next
		}
		for _, p := range pieces {
			if !p.Empty() {
				out = append(out, p)
			}
		}
	}
	return out
}

// subtract returns a minus b as up to four rectangles.
func subtract(a, b image.Rectangle) []image.Rectangle {
	if a.Empty() {
		return nil
	}
	i := a.Intersect(b)
	if i.Empty() {
		return []image.Rectangle{a}
	}
	var out []image.Rectangle
	if i.Min.Y > a.Min.Y {
		out = append(out, image.Rect(a.Min.X, a.Min.Y, a.Max.X, i.Min.Y))
	}
	if i.Max.Y < a.Max.Y {
		out = append(out, image.Rect(a.Min.X, i.Max.Y, a.Max.X, a.Max.Y))
	}
	if i.Min.X > a.Min.X {
		out = append(out, image.Rect(a.Min.X, i.Min.Y, i.Min.X, i.Max.Y))
	}
	if i.Max.X < a.Max.X {
		out = append(out, image.Rect(i.Max.X, i.Min.Y, a.Max.X, i.Max.Y))
	}
	return out
}
