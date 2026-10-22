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
	"errors"
	"fmt"
	"image"

	"github.com/casvisor/gordp/bitmap"
	"github.com/casvisor/gordp/clear"
	"github.com/casvisor/gordp/core"
	"github.com/casvisor/gordp/progressive"
	"github.com/casvisor/gordp/zgfx"
)

// The graphics pipeline (MS-RDPEGFX) is how current Windows clients receive
// the screen: the server draws into surfaces with codecs (H.264 among them),
// caches and copies, and marks frames that the client acknowledges, which is
// also its flow control. It rides the Microsoft::Windows::RDS::Graphics dynamic
// channel and replaces the bitmap updates.

const gfxChannelName = "Microsoft::Windows::RDS::Graphics"

var errShortPDU = errors.New("gordp: gfx pdu too short")

// RDPGFX_CMDID values (MS-RDPEGFX 2.2.1.5).
const (
	gfxCmdWireToSurface1   = 0x0001
	gfxCmdWireToSurface2   = 0x0002
	gfxCmdDeleteEncoding   = 0x0003
	gfxCmdSolidFill        = 0x0004
	gfxCmdSurfaceToSurface = 0x0005
	gfxCmdSurfaceToCache   = 0x0006
	gfxCmdCacheToSurface   = 0x0007
	gfxCmdEvictCache       = 0x0008
	gfxCmdCreateSurface    = 0x0009
	gfxCmdDeleteSurface    = 0x000A
	gfxCmdStartFrame       = 0x000B
	gfxCmdEndFrame         = 0x000C
	gfxCmdFrameAck         = 0x000D
	gfxCmdResetGraphics    = 0x000E
	gfxCmdMapSurface       = 0x000F
	gfxCmdCacheImportReply = 0x0011
	gfxCmdCapsAdvertise    = 0x0012
	gfxCmdCapsConfirm      = 0x0013
)

// Capability versions (MS-RDPEGFX 2.2.3).
const (
	gfxCapVersion8  = 0x00080004
	gfxCapVersion81 = 0x00080105
)

// RDPGFX_CODECID values (MS-RDPEGFX 2.2.1.4.1).
const (
	GFXCodecUncompressed = 0x0000
	GFXCodecCAVideo      = 0x0003
	GFXCodecClear        = 0x0008
	GFXCodecProgressive  = 0x0009
	GFXCodecPlanar       = 0x000A
	GFXCodecAVC420       = 0x000B
	GFXCodecAlpha        = 0x000C
	GFXCodecAVC444       = 0x000E
	GFXCodecAVC444v2     = 0x000F
)

// GFXHandler receives the graphics pipeline commands in order, with the codecs
// already decoded into Bitmap calls. The handler owns the surfaces and caches:
// the commands copy pixels between them, so it is the viewer that applies them.
type GFXHandler interface {
	ResetGraphics(width, height int)
	CreateSurface(id uint16, width, height int)
	DeleteSurface(id uint16)
	MapSurfaceToOutput(id uint16, x, y int)
	StartFrame(frameID uint32)
	// EndFrame marks the end of a frame. Unless the client was created with
	// manual acknowledgement, gordp acknowledges the frame after it returns.
	EndFrame(frameID uint32)
	SolidFill(id uint16, rgba [4]byte, rects []image.Rectangle)
	SurfaceToSurface(src, dst uint16, rect image.Rectangle, points []image.Point)
	SurfaceToCache(id uint16, rect image.Rectangle, slot uint16)
	CacheToSurface(slot uint16, id uint16, points []image.Point)
	EvictCache(slot uint16)
	// Bitmap draws decoded, non-premultiplied RGBA pixels at rect. Pixels
	// with alpha 0 are not part of the bitmap and keep the surface's pixels.
	Bitmap(id uint16, rect image.Rectangle, rgba []byte)
	// StoreGlyph saves rect of the surface, as it is after drawing, in the
	// ClearCodec glyph cache under index.
	StoreGlyph(index uint16, id uint16, rect image.Rectangle)
	// DrawGlyph draws the glyph saved under index at rect.
	DrawGlyph(index uint16, id uint16, rect image.Rectangle)
}

// GFXOptions configure the graphics pipeline.
type GFXOptions struct {
	// ManualAck leaves frame acknowledgement to the caller (AckFrame), so the
	// server is paced by how fast the viewer really draws.
	ManualAck bool
}

// WithGFX enables the graphics pipeline with h receiving its commands. The
// server only uses it for a 32bpp session; otherwise bitmap updates continue.
func WithGFX(h GFXHandler, opts GFXOptions) Option {
	return func(c *Client) {
		c.gfx = &gfxState{dec: NewGFXDecoder(h), opts: opts, zgfx: zgfx.New()}
	}
}

type gfxState struct {
	dec     *GFXDecoder
	opts    GFXOptions
	zgfx    *zgfx.Decompressor
	decoded uint32
}

// GFXDecoder turns decompressed graphics pipeline PDUs into handler calls,
// decoding every codec but H.264. A client uses one per connection; it can
// also replay PDUs recorded with OnGFXPDU.
type GFXDecoder struct {
	handler     GFXHandler
	clear       *clear.Decoder
	progressive *progressive.Decoder

	caps        uint32
	unsupported map[uint16]int
}

// NewGFXDecoder returns a decoder that calls h.
func NewGFXDecoder(h GFXHandler) *GFXDecoder {
	return &GFXDecoder{handler: h, clear: clear.NewDecoder(), progressive: progressive.NewDecoder()}
}

// Unsupported returns how many commands used codecs it could not decode, by
// codec ID.
func (d *GFXDecoder) Unsupported() map[uint16]int {
	return d.unsupported
}

// GFXActive reports whether the server has confirmed the graphics pipeline.
func (c *Client) GFXActive() bool {
	return c.gfx != nil && c.gfx.dec.caps != 0
}

// GFXUnsupported returns how many commands used codecs gordp could not decode,
// by codec ID.
func (c *Client) GFXUnsupported() map[uint16]int {
	if c.gfx == nil {
		return nil
	}
	return c.gfx.dec.Unsupported()
}

// gfxSendCaps advertises the capability sets once the server opens the
// channel. Versions 8.0 and 8.1 without H.264 keep the server on ClearCodec,
// planar and RemoteFX Progressive, which gordp decodes; Windows only encodes
// H.264 when a group policy enables it, and then as AVC444.
func (c *Client) gfxSendCaps() {
	type capSet struct{ version, flags uint32 }
	sets := []capSet{{gfxCapVersion8, 0}, {gfxCapVersion81, 0}}
	w := core.NewWriter()
	w.WriteUint16LE(gfxCmdCapsAdvertise)
	w.WriteUint16LE(0)
	w.WriteUint32LE(uint32(8 + 2 + 12*len(sets)))
	w.WriteUint16LE(uint16(len(sets)))
	for _, s := range sets {
		w.WriteUint32LE(s.version)
		w.WriteUint32LE(4)
		w.WriteUint32LE(s.flags)
	}
	_ = c.dvcSend(gfxChannelName, w.Bytes())
}

// AckFrame acknowledges a frame the viewer has drawn. queueDepth is the number
// of frames still waiting to be drawn; the server slows down as it grows.
func (c *Client) AckFrame(frameID uint32, queueDepth uint32) error {
	if c.gfx == nil {
		return nil
	}
	c.gfx.decoded++
	w := core.NewWriter()
	w.WriteUint16LE(gfxCmdFrameAck)
	w.WriteUint16LE(0)
	w.WriteUint32LE(8 + 12)
	w.WriteUint32LE(queueDepth)
	w.WriteUint32LE(frameID)
	w.WriteUint32LE(c.gfx.decoded)
	return c.dvcSend(gfxChannelName, w.Bytes())
}

// handleGFX decompresses one channel message and dispatches the PDUs in it.
func (c *Client) handleGFX(data []byte) error {
	if c.gfx == nil {
		return nil
	}
	plain, err := c.gfx.zgfx.Decompress(data)
	if err != nil {
		return err
	}
	for len(plain) >= 8 {
		cmd := uint16(plain[0]) | uint16(plain[1])<<8
		length := int(uint32(plain[4]) | uint32(plain[5])<<8 | uint32(plain[6])<<16 | uint32(plain[7])<<24)
		if length < 8 || length > len(plain) {
			return fmt.Errorf("gordp: bad gfx pdu length %d", length)
		}
		if c.OnGFXPDU != nil {
			c.OnGFXPDU(plain[:length])
		}
		if err := c.gfx.dec.Decode(plain[:length]); err != nil {
			return err
		}
		if cmd == gfxCmdEndFrame && !c.gfx.opts.ManualAck && length >= 12 {
			frameID := uint32(plain[8]) | uint32(plain[9])<<8 | uint32(plain[10])<<16 | uint32(plain[11])<<24
			if err := c.AckFrame(frameID, 0); err != nil {
				return err
			}
		}
		plain = plain[length:]
	}
	return nil
}

// Decode handles one PDU, header included.
func (d *GFXDecoder) Decode(pdu []byte) error {
	if len(pdu) < 8 {
		return errShortPDU
	}
	cmd := uint16(pdu[0]) | uint16(pdu[1])<<8
	if err := d.pdu(cmd, pdu[8:]); err != nil {
		return fmt.Errorf("gordp: gfx command 0x%04x: %w", cmd, err)
	}
	return nil
}

func readRect16(r *core.Reader) (image.Rectangle, error) {
	var v [4]uint16
	for i := range v {
		x, err := r.ReadUint16LE()
		if err != nil {
			return image.Rectangle{}, err
		}
		v[i] = x
	}
	return image.Rect(int(v[0]), int(v[1]), int(v[2]), int(v[3])), nil
}

func readPoints(r *core.Reader, n int) ([]image.Point, error) {
	points := make([]image.Point, 0, n)
	for i := 0; i < n; i++ {
		x, err := r.ReadUint16LE()
		if err != nil {
			return nil, err
		}
		y, err := r.ReadUint16LE()
		if err != nil {
			return nil, err
		}
		points = append(points, image.Pt(int(x), int(y)))
	}
	return points, nil
}

func (d *GFXDecoder) pdu(cmd uint16, body []byte) error {
	h := d.handler
	r := core.NewReader(body)
	u16 := func() uint16 { v, _ := r.ReadUint16LE(); return v }
	u32 := func() uint32 { v, _ := r.ReadUint32LE(); return v }

	switch cmd {
	case gfxCmdCapsConfirm:
		if len(body) < 12 {
			return errShortPDU
		}
		d.caps = u32()
	case gfxCmdResetGraphics:
		if len(body) < 12 {
			return errShortPDU
		}
		w, hh := u32(), u32()
		h.ResetGraphics(int(w), int(hh))
	case gfxCmdCreateSurface:
		if len(body) < 7 {
			return errShortPDU
		}
		id, w, hh := u16(), u16(), u16()
		d.progressive.CreateSurface(id, int(w), int(hh))
		h.CreateSurface(id, int(w), int(hh))
	case gfxCmdDeleteSurface:
		if len(body) < 2 {
			return errShortPDU
		}
		id := u16()
		d.progressive.DeleteSurface(id)
		h.DeleteSurface(id)
	case gfxCmdMapSurface:
		if len(body) < 12 {
			return errShortPDU
		}
		id := u16()
		u16()
		x, y := u32(), u32()
		h.MapSurfaceToOutput(id, int(x), int(y))
	case gfxCmdStartFrame:
		if len(body) < 8 {
			return errShortPDU
		}
		u32()
		h.StartFrame(u32())
	case gfxCmdEndFrame:
		if len(body) < 4 {
			return errShortPDU
		}
		h.EndFrame(u32())
	case gfxCmdSolidFill:
		if len(body) < 8 {
			return errShortPDU
		}
		id := u16()
		b, g, rr, _ := body[2], body[3], body[4], body[5]
		_ = r.Skip(4)
		n := int(u16())
		rects := make([]image.Rectangle, 0, n)
		for i := 0; i < n; i++ {
			rect, err := readRect16(r)
			if err != nil {
				return err
			}
			rects = append(rects, rect)
		}
		h.SolidFill(id, [4]byte{rr, g, b, 0xFF}, rects)
	case gfxCmdSurfaceToSurface:
		if len(body) < 14 {
			return errShortPDU
		}
		src, dst := u16(), u16()
		rect, err := readRect16(r)
		if err != nil {
			return err
		}
		points, err := readPoints(r, int(u16()))
		if err != nil {
			return err
		}
		h.SurfaceToSurface(src, dst, rect, points)
	case gfxCmdSurfaceToCache:
		if len(body) < 20 {
			return errShortPDU
		}
		id := u16()
		_ = r.Skip(8) // cacheKey
		slot := u16()
		rect, err := readRect16(r)
		if err != nil {
			return err
		}
		h.SurfaceToCache(id, rect, slot)
	case gfxCmdCacheToSurface:
		if len(body) < 6 {
			return errShortPDU
		}
		slot, id := u16(), u16()
		points, err := readPoints(r, int(u16()))
		if err != nil {
			return err
		}
		h.CacheToSurface(slot, id, points)
	case gfxCmdEvictCache:
		if len(body) < 2 {
			return errShortPDU
		}
		h.EvictCache(u16())
	case gfxCmdWireToSurface1:
		if len(body) < 17 {
			return errShortPDU
		}
		id, codec := u16(), u16()
		_ = r.Skip(1) // pixelFormat
		rect, err := readRect16(r)
		if err != nil {
			return err
		}
		n := int(u32())
		data, err := r.ReadBytes(n)
		if err != nil {
			return err
		}
		return d.wireToSurface(id, codec, rect, data)
	case gfxCmdWireToSurface2:
		if len(body) < 13 {
			return errShortPDU
		}
		id, codec := u16(), u16()
		_ = r.Skip(5) // codecContextId, pixelFormat
		data, err := r.ReadBytes(int(u32()))
		if err != nil {
			return err
		}
		if codec != GFXCodecProgressive {
			d.countUnsupported(codec)
			return nil
		}
		tiles, err := d.progressive.Decode(id, data)
		if err != nil {
			return err
		}
		for _, t := range tiles {
			h.Bitmap(id, t.Rect, t.RGBA)
		}
	case gfxCmdDeleteEncoding, gfxCmdCacheImportReply:
	}
	return nil
}

func (d *GFXDecoder) countUnsupported(codec uint16) {
	if d.unsupported == nil {
		d.unsupported = map[uint16]int{}
	}
	d.unsupported[codec]++
}

func (d *GFXDecoder) wireToSurface(id, codec uint16, rect image.Rectangle, data []byte) error {
	h := d.handler
	w, hh := rect.Dx(), rect.Dy()
	if w <= 0 || hh <= 0 || w > 8192 || hh > 8192 {
		return fmt.Errorf("bad destination %v", rect)
	}
	switch codec {
	case GFXCodecUncompressed:
		if len(data) < w*hh*4 {
			return errShortPDU
		}
		rgba := make([]byte, w*hh*4)
		for i := 0; i < w*hh; i++ {
			rgba[i*4] = data[i*4+2]
			rgba[i*4+1] = data[i*4+1]
			rgba[i*4+2] = data[i*4]
			rgba[i*4+3] = 0xFF
		}
		h.Bitmap(id, rect, rgba)
	case GFXCodecPlanar:
		rgba, err := bitmap.DecodePlanar(data, w, hh, false)
		if err != nil {
			return err
		}
		h.Bitmap(id, rect, rgba)
	case GFXCodecClear:
		res, err := d.clear.Decode(data, w, hh)
		if err != nil {
			return err
		}
		if res.DrawGlyph >= 0 {
			h.DrawGlyph(uint16(res.DrawGlyph), id, rect)
		}
		if res.RGBA != nil {
			h.Bitmap(id, rect, res.RGBA)
		}
		if res.StoreGlyph >= 0 {
			h.StoreGlyph(uint16(res.StoreGlyph), id, rect)
		}
	default:
		d.countUnsupported(codec)
	}
	return nil
}
