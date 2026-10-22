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
	"fmt"
	"strings"

	"github.com/casvisor/gordp/core"
)

// drdynvc (MS-RDPEDYC) is the dynamic virtual channel multiplexer. Modern
// Windows servers carry display control (resize) and, when the client presents
// as a current client, clipboard as dynamic channels over the static drdynvc
// channel rather than as static channels, so the client must speak this protocol
// to get them.

// DVC command codes, the high nibble of the first PDU byte (MS-RDPEDYC 2.2).
const (
	dvcCmdCreate       = 0x01
	dvcCmdDataFirst    = 0x02
	dvcCmdData         = 0x03
	dvcCmdClose        = 0x04
	dvcCmdCapabilities = 0x05
)

// dvcState holds the dynamic virtual channels opened by the server.
type dvcState struct {
	byID   map[uint32]*dvChannel
	byName map[string]*dvChannel
}

// dvChannel is one open dynamic virtual channel and its reassembly buffer.
type dvChannel struct {
	id    uint32
	name  string
	buf   []byte
	total int
}

func newDVCState() *dvcState {
	return &dvcState{byID: map[uint32]*dvChannel{}, byName: map[string]*dvChannel{}}
}

// handleDrdynvc processes one reassembled PDU from the static drdynvc channel.
func (c *Client) handleDrdynvc(data []byte) {
	if len(data) < 1 {
		return
	}
	if c.vc.dvc == nil {
		c.vc.dvc = newDVCState()
	}
	b0 := data[0]
	cmd := b0 >> 4
	sp := (b0 >> 2) & 0x03
	cbChId := b0 & 0x03
	switch cmd {
	case dvcCmdCapabilities:
		c.dvcSendCapsResponse()
	case dvcCmdCreate:
		c.dvcHandleCreate(data, cbChId)
	case dvcCmdData:
		c.dvcHandleData(data, cbChId, false, 0)
	case dvcCmdDataFirst:
		c.dvcHandleData(data, cbChId, true, sp)
	case dvcCmdClose:
		id, _ := dvcReadChannelID(data[1:], cbChId)
		if ch := c.vc.dvc.byID[id]; ch != nil {
			delete(c.vc.dvc.byID, id)
			delete(c.vc.dvc.byName, strings.ToLower(ch.name))
		}
	}
}

// dvcSendCapsResponse replies to the server Capabilities Request, matching the
// version the Windows client reports (3, RDP 8.1).
func (c *Client) dvcSendCapsResponse() {
	w := core.NewWriter()
	w.PutByte(dvcCmdCapabilities << 4) // caps PDU, cbChId/Sp = 0
	w.PutByte(0x00)                    // pad
	w.WriteUint16LE(0x0003)            // Version 3
	_ = c.sendChannel(channelDrdynvc, w.Bytes())
}

// dvcHandleCreate accepts a dynamic channel we handle (clipboard and display
// control) and rejects the rest, which keeps the server on the legacy paths
// gordp supports.
func (c *Client) dvcHandleCreate(data []byte, cbChId byte) {
	id, rest := dvcReadChannelID(data[1:], cbChId)
	name := dvcReadName(rest)
	want := c.dvcWantChannel(name)
	status := uint32(0xC0000001) // rejected
	if want {
		status = 0
		ch := &dvChannel{id: id, name: name}
		c.vc.dvc.byID[id] = ch
		c.vc.dvc.byName[strings.ToLower(name)] = ch
	}
	w := core.NewWriter()
	w.PutByte(dvcCmdCreate<<4 | cbChId)
	dvcWriteChannelID(w, id, cbChId)
	w.WriteUint32LE(status)
	_ = c.sendChannel(channelDrdynvc, w.Bytes())
	if want && strings.EqualFold(name, gfxChannelName) {
		c.gfxSendCaps()
	}
}

// dvcHandleData reassembles a (possibly fragmented) data PDU and dispatches a
// complete payload to the channel's handler.
func (c *Client) dvcHandleData(data []byte, cbChId byte, first bool, sp byte) {
	id, rest := dvcReadChannelID(data[1:], cbChId)
	ch := c.vc.dvc.byID[id]
	if first {
		// DataFirst carries a Length field (size encoded by Sp) = total length.
		total, r2 := dvcReadVarLen(rest, sp)
		rest = r2
		if ch != nil {
			ch.total = total
			ch.buf = make([]byte, 0, total)
		}
	}
	if ch == nil {
		return // data for a channel we rejected; ignore
	}
	ch.buf = append(ch.buf, rest...)
	if ch.total == 0 || len(ch.buf) >= ch.total {
		payload := ch.buf
		ch.buf = nil
		ch.total = 0
		switch {
		case isCliprdrName(ch.name):
			c.handleCliprdr(payload)
		case isDisplayControlName(ch.name):
			c.handleDisplayControl(payload)
		case strings.EqualFold(ch.name, gfxChannelName):
			if err := c.handleGFX(payload); err != nil && c.channelErr == nil {
				c.channelErr = err
			}
		}
	}
}

// dvcSend sends a payload on a named dynamic channel, fragmenting into
// DataFirst/Data PDUs when it exceeds one chunk.
func (c *Client) dvcSend(name string, payload []byte) error {
	if c.vc == nil || c.vc.dvc == nil {
		return nil
	}
	ch := c.vc.dvc.byName[strings.ToLower(name)]
	if ch == nil {
		return fmt.Errorf("drdynvc: channel %q not open", name)
	}
	// Reserve room in each chunk for the DVC header (cmd + channel id + length).
	const maxData = channelChunkLength - 16
	if len(payload) <= maxData {
		w := core.NewWriter()
		w.PutByte(dvcCmdData<<4 | dvcChIdSize(ch.id))
		dvcWriteChannelID(w, ch.id, dvcChIdSize(ch.id))
		w.Write(payload)
		return c.sendChannel(channelDrdynvc, w.Bytes())
	}
	// First fragment carries the total length.
	first := core.NewWriter()
	first.PutByte(dvcCmdDataFirst<<4 | dvcLenSize(len(payload))<<2 | dvcChIdSize(ch.id))
	dvcWriteChannelID(first, ch.id, dvcChIdSize(ch.id))
	dvcWriteVarLen(first, len(payload))
	n := maxData
	first.Write(payload[:n])
	if err := c.sendChannel(channelDrdynvc, first.Bytes()); err != nil {
		return err
	}
	for off := n; off < len(payload); {
		end := off + maxData
		if end > len(payload) {
			end = len(payload)
		}
		w := core.NewWriter()
		w.PutByte(dvcCmdData<<4 | dvcChIdSize(ch.id))
		dvcWriteChannelID(w, ch.id, dvcChIdSize(ch.id))
		w.Write(payload[off:end])
		if err := c.sendChannel(channelDrdynvc, w.Bytes()); err != nil {
			return err
		}
		off = end
	}
	return nil
}

// dvcChannelOpen reports whether a dynamic channel with the given name is open.
func (c *Client) dvcChannelOpen(name string) bool {
	return c.vc != nil && c.vc.dvc != nil && c.vc.dvc.byName[strings.ToLower(name)] != nil
}

// dvcCliprdrOpen reports whether the clipboard dynamic channel is open.
func (c *Client) dvcCliprdrOpen() bool {
	if c.vc == nil || c.vc.dvc == nil {
		return false
	}
	for _, ch := range c.vc.dvc.byID {
		if isCliprdrName(ch.name) {
			return true
		}
	}
	return false
}

// dvcCliprdrName returns the open clipboard dynamic channel's name, or "".
func (c *Client) dvcCliprdrName() string {
	if c.vc == nil || c.vc.dvc == nil {
		return ""
	}
	for _, ch := range c.vc.dvc.byID {
		if isCliprdrName(ch.name) {
			return ch.name
		}
	}
	return ""
}

func (c *Client) dvcWantChannel(name string) bool {
	return isCliprdrName(name) || isDisplayControlName(name) || (c.gfx != nil && strings.EqualFold(name, gfxChannelName))
}

func isCliprdrName(name string) bool {
	return strings.EqualFold(name, "cliprdr") || strings.EqualFold(name, "clipboard")
}

// displayControlChannelName is the MS-RDPEDISP dynamic channel the server opens
// for client-driven desktop resizing.
const displayControlChannelName = "Microsoft::Windows::RDS::DisplayControl"

func isDisplayControlName(name string) bool {
	return strings.EqualFold(name, displayControlChannelName)
}

// dvcReadChannelID reads a ChannelId of the size encoded by cbChId.
func dvcReadChannelID(b []byte, cbChId byte) (uint32, []byte) {
	switch cbChId {
	case 0:
		if len(b) < 1 {
			return 0, nil
		}
		return uint32(b[0]), b[1:]
	case 1:
		if len(b) < 2 {
			return 0, nil
		}
		return uint32(b[0]) | uint32(b[1])<<8, b[2:]
	default: // 2 -> 4 bytes
		if len(b) < 4 {
			return 0, nil
		}
		return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, b[4:]
	}
}

// dvcChIdSize returns the cbChId code for a channel id.
func dvcChIdSize(id uint32) byte {
	switch {
	case id <= 0xFF:
		return 0
	case id <= 0xFFFF:
		return 1
	default:
		return 2
	}
}

func dvcWriteChannelID(w *core.Writer, id uint32, cbChId byte) {
	switch cbChId {
	case 0:
		w.PutByte(byte(id))
	case 1:
		w.WriteUint16LE(uint16(id))
	default:
		w.WriteUint32LE(id)
	}
}

// dvcReadName reads a null-terminated ASCII channel name.
func dvcReadName(b []byte) string {
	for i, ch := range b {
		if ch == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// dvcLenSize returns the Sp code for a DataFirst Length field.
func dvcLenSize(n int) byte {
	switch {
	case n <= 0xFF:
		return 0
	case n <= 0xFFFF:
		return 1
	default:
		return 2
	}
}

func dvcWriteVarLen(w *core.Writer, n int) {
	switch dvcLenSize(n) {
	case 0:
		w.PutByte(byte(n))
	case 1:
		w.WriteUint16LE(uint16(n))
	default:
		w.WriteUint32LE(uint32(n))
	}
}

// dvcReadVarLen reads a Length field of the size encoded by sp.
func dvcReadVarLen(b []byte, sp byte) (int, []byte) {
	switch sp {
	case 0:
		if len(b) < 1 {
			return 0, nil
		}
		return int(b[0]), b[1:]
	case 1:
		if len(b) < 2 {
			return 0, nil
		}
		return int(b[0]) | int(b[1])<<8, b[2:]
	default:
		if len(b) < 4 {
			return 0, nil
		}
		return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24, b[4:]
	}
}
