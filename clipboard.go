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
	"github.com/casvisor/gordp/cliprdr"
)

// handleCliprdr advances the clipboard (MS-RDPECLIP) state machine for one
// reassembled cliprdr PDU. It runs in the PumpUpdates read goroutine.
func (c *Client) handleCliprdr(data []byte) {
	msg, err := cliprdr.Parse(data)
	if err != nil {
		return
	}
	switch msg.Type {
	case cliprdr.MsgMonitorReady:
		c.vc.clipReady = true
		// The Windows client sends its capabilities in response to the server's
		// Capabilities PDU (which precedes Monitor Ready); Monitor Ready then
		// triggers the format list. If the server sent no capabilities, send ours
		// here as a fallback.
		if !c.vc.clipCapsSent {
			c.sendClipboardCaps()
		}
		c.sendOfferedFormatList()

	case cliprdr.MsgClipCaps:
		// Long format names are used only if both ends advertise them. Reply with
		// our capabilities now, the way the Windows client does.
		c.vc.clipUseLong = cliprdr.ServerSupportsLongFormat(msg.Body)
		c.sendClipboardCaps()

	case cliprdr.MsgFormatList:
		// The remote clipboard changed. Acknowledge, then, if it offers text and a
		// reader is registered, ask for the text.
		_ = c.sendCliprdr(cliprdr.BuildFormatListResponse(true))
		if c.OnClipboard == nil {
			return
		}
		for _, id := range cliprdr.ParseFormatList(msg.Body, c.vc.clipUseLong) {
			if id == cliprdr.CfUnicodeText {
				_ = c.sendCliprdr(cliprdr.BuildFormatDataRequest(cliprdr.CfUnicodeText))
				return
			}
		}

	case cliprdr.MsgFormatListResponse:
		// Acknowledgement of a format list we sent; nothing to do.

	case cliprdr.MsgFormatDataRequest:
		// The remote host wants the data for a format we offered.
		id, err := cliprdr.ParseFormatDataRequest(msg.Body)
		if err != nil {
			return
		}
		if id == cliprdr.CfUnicodeText && c.vc.clipHavePending {
			_ = c.sendCliprdr(cliprdr.BuildFormatDataResponse(true, cliprdr.EncodeText(c.vc.clipPending)))
		} else {
			_ = c.sendCliprdr(cliprdr.BuildFormatDataResponse(false, nil))
		}

	case cliprdr.MsgFormatDataResponse:
		// The remote clipboard text we requested.
		if msg.Flags&cliprdr.FlagResponseOK != 0 && c.OnClipboard != nil {
			c.OnClipboard(cliprdr.DecodeText(msg.Body))
		}
	}
}

// sendClipboardCaps sends the client clipboard capabilities PDU.
func (c *Client) sendClipboardCaps() {
	_ = c.sendCliprdr(cliprdr.BuildCaps(c.vc.clipUseLong))
	c.vc.clipCapsSent = true
}

// sendOfferedFormatList sends a Format List announcing CF_UNICODETEXT when text
// is being offered, or an empty list otherwise.
func (c *Client) sendOfferedFormatList() {
	var ids []uint32
	if c.vc.clipHavePending {
		ids = []uint32{cliprdr.CfUnicodeText}
	}
	_ = c.sendCliprdr(cliprdr.BuildFormatList(ids, c.vc.clipUseLong))
}

// SetClipboard offers text to the remote host's clipboard. The remote host sees
// new clipboard content and pulls the text when it pastes. It is valid to call
// before or after the clipboard channel finishes initializing.
func (c *Client) SetClipboard(text string) error {
	if c.vc == nil {
		return nil
	}
	c.vc.clipPending = text
	c.vc.clipHavePending = true
	if !c.vc.clipReady {
		return nil // the format list goes out once monitor-ready arrives
	}
	c.sendOfferedFormatList()
	return nil
}

// ClipboardReady reports whether the clipboard channel finished its handshake.
func (c *Client) ClipboardReady() bool {
	return c.vc != nil && c.vc.clipReady
}

// RequestClipboard asks the remote host for its clipboard text. The reply is
// delivered to OnClipboard. Normally this is driven automatically by the
// server's format list.
func (c *Client) RequestClipboard() error {
	if c.vc == nil {
		return nil
	}
	return c.sendCliprdr(cliprdr.BuildFormatDataRequest(cliprdr.CfUnicodeText))
}
