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
	"image"
	"net"
	"time"

	"github.com/casvisor/gordp/bitmap"
	"github.com/casvisor/gordp/pdu"
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

// PumpUpdates reads server updates for up to d and applies bitmap updates to the
// framebuffer. It returns the number of rectangles applied. A read timeout ends
// the loop normally.
func (c *Client) PumpUpdates(d time.Duration) (int, error) {
	if c.fb == nil {
		c.initFramebuffer()
	}
	deadline := time.Now().Add(d)
	_ = c.conn.SetReadDeadline(deadline)
	defer c.conn.SetReadDeadline(time.Time{})

	rects := 0
	for time.Now().Before(deadline) {
		_, msg, err := c.mcs.Receive()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return rects, nil
			}
			return rects, err
		}

		if msg.FastPath {
			updates, err := c.fpReasm.Parse(msg.Payload)
			if err != nil {
				return rects, err
			}
			for _, u := range updates {
				if u.Code == pdu.FastPathUpdateBitmap {
					n, err := c.applyBitmapUpdate(u.Data)
					if err != nil {
						return rects, err
					}
					rects += n
				}
			}
			continue
		}

		n, err := c.handleSlowPath(msg.Payload)
		if err != nil {
			return rects, err
		}
		rects += n
	}
	return rects, nil
}

func (c *Client) handleSlowPath(payload []byte) (int, error) {
	sc, err := pdu.ReadShareControl(c.stripSecHeader(payload))
	if err != nil {
		return 0, err
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
		c.blit(rect)
	}
	return len(rects), nil
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
