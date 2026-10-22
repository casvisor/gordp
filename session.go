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
	"image"
	"time"

	"github.com/casvisor/gordp/bitmap"
	"github.com/casvisor/gordp/pdu"
	"github.com/casvisor/gordp/tpkt"
)

// Framebuffer returns the current desktop image. It is updated in place by
// PumpUpdates, so callers should copy it if they need a stable snapshot.
func (c *Client) Framebuffer() *image.RGBA {
	return c.fb
}

func (c *Client) initFramebuffer() {
	w, h := int(c.width), int(c.height)
	if w == 0 {
		w = 1024
	}
	if h == 0 {
		h = 768
	}
	c.fb = image.NewRGBA(image.Rect(0, 0, w, h))
}

// received is one PDU (or the read error that ended the stream) from the
// background reader.
type received struct {
	channelID uint16
	msg       *tpkt.PDU
	err       error
}

// startReader reads PDUs in the background once the session is up, so the pump
// can wait on them with a timeout. Read deadlines on the TLS connection would
// abandon a PDU that is half read when the deadline hits and desync the stream.
func (c *Client) startReader() {
	c.recv = make(chan received, 256)
	c.done = make(chan struct{})
	go func() {
		for {
			channelID, msg, err := c.mcs.Receive()
			select {
			case c.recv <- received{channelID, msg, err}:
			case <-c.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
}

// next returns the next PDU, waiting up to d. ok is false on timeout.
func (c *Client) next(d time.Duration) (r received, ok bool) {
	if d <= 0 {
		select {
		case r = <-c.recv:
			return r, true
		default:
			return r, false
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case r = <-c.recv:
		return r, true
	case <-timer.C:
		return r, false
	}
}

// PumpUpdates reads server updates for up to d and applies bitmap updates to the
// framebuffer. It returns the number of rectangles applied.
func (c *Client) PumpUpdates(d time.Duration) (int, error) {
	if c.fb == nil {
		c.initFramebuffer()
	}
	deadline := time.Now().Add(d)
	rects := 0
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return rects, nil
		}
		r, ok := c.next(left)
		if !ok {
			return rects, nil
		}
		n, err := c.process(r)
		rects += n
		if err != nil {
			return rects, err
		}
	}
}

// Frame pacing for PumpFrame: a burst of updates that arrive less than
// frameIdle apart is one frame, but a frame is cut after frameMax so a steady
// stream (a video playing) still reaches the viewer.
const (
	frameIdle = 12 * time.Millisecond
	frameMax  = 80 * time.Millisecond
)

// PumpFrame waits up to wait for the server to send something, then applies
// updates until the server pauses, so that everything Windows sends for one
// change (a window being repainted tile by tile) is applied together; the
// caller then sends the accumulated changes to its viewer at once. It returns the number of rectangles
// applied, 0 when nothing arrived within wait.
func (c *Client) PumpFrame(wait time.Duration) (int, error) {
	if c.fb == nil {
		c.initFramebuffer()
	}
	r, ok := c.next(wait)
	if !ok {
		return 0, nil
	}
	cut := time.Now().Add(frameMax)
	rects := 0
	for {
		n, err := c.process(r)
		rects += n
		if err != nil {
			return rects, err
		}
		idle := min(frameIdle, time.Until(cut))
		if idle <= 0 {
			return rects, nil
		}
		if r, ok = c.next(idle); !ok {
			return rects, nil
		}
	}
}

// process applies one received PDU.
func (c *Client) process(r received) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	channelID, msg := r.channelID, r.msg
	if !msg.FastPath && c.handleChannelData(channelID, msg.Payload) {
		return 0, nil
	}
	if !msg.FastPath {
		return c.handleSlowPath(msg.Payload)
	}

	updates, err := c.fpReasm.Parse(msg.Payload)
	if err != nil {
		return 0, err
	}
	rects := 0
	for _, u := range updates {
		if c.OnFastPath != nil {
			c.OnFastPath(u.Code, u.Data)
		}
		switch u.Code {
		case pdu.FastPathUpdateBitmap:
			n, err := c.applyBitmapUpdate(u.Data)
			if err != nil {
				return rects, err
			}
			rects += n
		case pdu.FastPathUpdatePointerNull, pdu.FastPathUpdatePointerDef, pdu.FastPathUpdateColor,
			pdu.FastPathUpdateCached, pdu.FastPathUpdatePointer, pdu.FastPathUpdateLargePointer:
			if err := c.handlePointerUpdate(u.Code, u.Data); err != nil {
				return rects, err
			}
		}
	}
	return rects, nil
}

func (c *Client) handleSlowPath(payload []byte) (int, error) {
	sc, err := pdu.ReadShareControl(c.stripSecHeader(payload))
	if err != nil {
		return 0, err
	}
	if sc.PduType == pdu.PdutypeDemandActive {
		// The server re-sends Demand Active to reactivate the session, which is
		// how it applies a desktop resize requested over the DisplayControl
		// channel. Re-run the capability exchange at the new size.
		return 0, c.reactivate(sc.Body)
	}
	if sc.PduType != pdu.PdutypeData {
		return 0, nil
	}
	sd, err := pdu.ReadShareData(sc.Body)
	if err != nil {
		return 0, err
	}
	if sd.PduType2 != pdu.Pdutype2Update {
		return 0, nil
	}
	// Slow-path update: updateType then, for bitmap, the rectangles.
	if len(sd.Body) < 2 {
		return 0, nil
	}
	updateType := uint16(sd.Body[0]) | uint16(sd.Body[1])<<8
	if updateType != 0x0001 { // UPDATETYPE_BITMAP
		return 0, nil
	}
	return c.applyBitmapUpdate(sd.Body)
}

func (c *Client) applyBitmapUpdate(data []byte) (int, error) {
	rects, err := bitmap.ParseBitmapUpdate(data)
	if err != nil {
		return 0, err
	}
	for _, rect := range rects {
		c.lastBpp = rect.Bpp
		c.blit(rect)
	}
	if c.OnBitmap != nil && len(rects) > 0 {
		c.OnBitmap(rects)
	}
	return len(rects), nil
}

// LastBpp returns the bits-per-pixel of the most recent bitmap rectangle, which
// reports the color depth the server actually chose.
func (c *Client) LastBpp() int {
	return c.lastBpp
}

// DesktopSize returns the negotiated desktop size.
func (c *Client) DesktopSize() (width, height int) {
	w, h := int(c.width), int(c.height)
	if w == 0 {
		w = 1024
	}
	if h == 0 {
		h = 768
	}
	return w, h
}

func (c *Client) blit(rect bitmap.Rect) {
	bounds := c.fb.Bounds()
	for y := 0; y < rect.Height; y++ {
		dy := rect.DestTop + y
		if dy < 0 || dy >= bounds.Dy() {
			continue
		}
		for x := 0; x < rect.Width; x++ {
			dx := rect.DestLeft + x
			if dx < 0 || dx >= bounds.Dx() {
				continue
			}
			src := (y*rect.Width + x) * 4
			dst := c.fb.PixOffset(dx, dy)
			copy(c.fb.Pix[dst:dst+4], rect.RGBA[src:src+4])
		}
	}
}
