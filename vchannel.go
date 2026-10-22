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
	"github.com/casvisor/gordp/core"
	"github.com/casvisor/gordp/mcs"
)

// Static virtual channel names and options (MS-RDPBCGR 2.2.1.3.4.1).
const (
	channelCliprdr = "cliprdr"
	channelRdpsnd  = "rdpsnd"
	channelRdpdr   = "rdpdr"
	channelDrdynvc = "drdynvc"

	channelOptionInitialized  = 0x80000000
	channelOptionEncryptRDP   = 0x40000000
	channelOptionCompressRDP  = 0x00800000
	channelOptionShowProtocol = 0x00200000
)

// CHANNEL_PDU_HEADER flags (MS-RDPBCGR 2.2.6.1.1).
const (
	channelFlagFirst = 0x00000001
	channelFlagLast  = 0x00000002

	// channelChunkLength is the maximum virtual channel chunk the client sends
	// per PDU; larger payloads are split across CHANNEL_FLAG_FIRST/LAST frames.
	channelChunkLength = 1600
)

// vchannel is one joined static virtual channel and its reassembly buffer.
type vchannel struct {
	name string
	id   uint16
	buf  []byte
}

// vcState holds all virtual channel state: the joined static channels, the
// dynamic channel multiplexer, and the clipboard sub-protocol state. It lives in
// one Client field so the channel plumbing stays out of client.go.
type vcState struct {
	requested []mcs.ChannelDef
	byID      map[uint16]*vchannel
	byName    map[string]*vchannel

	// Dynamic virtual channels (MS-RDPEDYC). Modern servers carry clipboard and
	// display control here rather than as static channels.
	dvc *dvcState

	// Clipboard (MS-RDPECLIP) state.
	clipUseLong     bool   // long format names negotiated with the server
	clipReady       bool   // the monitor-ready handshake completed
	clipCapsSent    bool   // client capabilities PDU has been sent
	clipPending     string // text offered to the remote host
	clipHavePending bool
}

// requestedChannels is the static virtual channel list the client asks for:
// clipboard, sound, device redirection, and the dynamic channel multiplexer
// (drdynvc), which carries display control and, on modern servers, clipboard.
func requestedChannels() []mcs.ChannelDef {
	return []mcs.ChannelDef{
		{Name: channelRdpdr, Options: channelOptionInitialized | channelOptionCompressRDP},
		{Name: channelRdpsnd, Options: channelOptionInitialized | channelOptionEncryptRDP},
		{Name: channelCliprdr, Options: channelOptionInitialized | channelOptionEncryptRDP | channelOptionCompressRDP | channelOptionShowProtocol},
		{Name: channelDrdynvc, Options: channelOptionInitialized | channelOptionEncryptRDP | channelOptionCompressRDP},
	}
}

// initChannels maps the server-assigned channel IDs (returned in request order)
// onto the names the client requested.
func (c *Client) initChannels() {
	if c.vc == nil {
		return
	}
	c.vc.byID = make(map[uint16]*vchannel)
	c.vc.byName = make(map[string]*vchannel)
	ids := c.mcs.Server.ChannelIDs
	for i, def := range c.vc.requested {
		if i >= len(ids) {
			break
		}
		vc := &vchannel{name: def.Name, id: ids[i]}
		c.vc.byID[ids[i]] = vc
		c.vc.byName[def.Name] = vc
	}
}

// sendChannel sends data on a named static virtual channel, splitting it into
// CHANNEL_PDU_HEADER-framed chunks.
func (c *Client) sendChannel(name string, data []byte) error {
	vc := c.vc.byName[name]
	if vc == nil {
		return nil // channel not joined; drop silently
	}
	total := len(data)
	for off := 0; ; {
		end := off + channelChunkLength
		if end > total {
			end = total
		}
		flags := uint32(0)
		if off == 0 {
			flags |= channelFlagFirst
		}
		if end == total {
			flags |= channelFlagLast
		}
		w := core.NewWriter()
		w.WriteUint32LE(uint32(total))
		w.WriteUint32LE(flags)
		w.Write(data[off:end])
		if err := c.mcs.Send(vc.id, w.Bytes()); err != nil {
			return err
		}
		off = end
		if off >= total {
			return nil
		}
	}
}

// handleChannelData processes a Send Data Indication on a virtual channel. It
// reassembles the CHANNEL_PDU_HEADER frames and dispatches a complete payload.
// It returns false if channelID is not a joined virtual channel, so the caller
// can fall back to the normal I/O-channel path.
func (c *Client) handleChannelData(channelID uint16, payload []byte) bool {
	if c.vc == nil {
		return false
	}
	vc := c.vc.byID[channelID]
	if vc == nil {
		return false
	}
	r := core.NewReader(payload)
	total, err := r.ReadUint32LE()
	if err != nil {
		return true
	}
	flags, err := r.ReadUint32LE()
	if err != nil {
		return true
	}
	body, _ := r.ReadBytes(r.Remaining())
	if flags&channelFlagFirst != 0 {
		vc.buf = make([]byte, 0, total)
	}
	vc.buf = append(vc.buf, body...)
	if flags&channelFlagLast != 0 {
		complete := vc.buf
		vc.buf = nil
		c.dispatchChannel(vc.name, complete)
	}
	return true
}

// dispatchChannel routes a reassembled channel payload to its handler.
func (c *Client) dispatchChannel(name string, data []byte) {
	switch name {
	case channelCliprdr:
		c.handleCliprdr(data)
	case channelDrdynvc:
		c.handleDrdynvc(data)
	}
}

// sendCliprdr sends a clipboard PDU over the dynamic channel when the server
// opened one, falling back to the static cliprdr channel otherwise.
func (c *Client) sendCliprdr(data []byte) error {
	if c.dvcCliprdrOpen() {
		return c.dvcSend(c.dvcCliprdrName(), data)
	}
	return c.sendChannel(channelCliprdr, data)
}
