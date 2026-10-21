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

import "github.com/casvisor/gordp/pdu"

// MouseButton identifies a mouse button.
type MouseButton int

const (
	ButtonLeft MouseButton = iota
	ButtonRight
	ButtonMiddle
)

func (b MouseButton) flag() uint16 {
	switch b {
	case ButtonRight:
		return pdu.PtrFlagsButton2
	case ButtonMiddle:
		return pdu.PtrFlagsButton3
	default:
		return pdu.PtrFlagsButton1
	}
}

// sendInput writes a fast-path input PDU directly to the transport.
func (c *Client) sendInput(events ...[]byte) error {
	_, err := c.conn.Write(pdu.BuildFastPathInput(events))
	return err
}

// MouseMove moves the pointer to (x, y).
func (c *Client) MouseMove(x, y uint16) error {
	return c.sendInput(pdu.MouseEvent(pdu.PtrFlagsMove, x, y))
}

// MouseButton presses or releases a button at (x, y).
func (c *Client) MouseButton(button MouseButton, down bool, x, y uint16) error {
	flags := button.flag()
	if down {
		flags |= pdu.PtrFlagsDown
	}
	return c.sendInput(pdu.MouseEvent(flags, x, y))
}

// Click performs a full left-button click at (x, y).
func (c *Client) Click(x, y uint16) error {
	return c.sendInput(
		pdu.MouseEvent(pdu.PtrFlagsMove, x, y),
		pdu.MouseEvent(pdu.PtrFlagsDown|pdu.PtrFlagsButton1, x, y),
		pdu.MouseEvent(pdu.PtrFlagsButton1, x, y),
	)
}

// MouseWheel scrolls the wheel; a positive amount scrolls up.
func (c *Client) MouseWheel(x, y uint16, amount int16) error {
	flags := uint16(pdu.PtrFlagsWheel) | uint16(amount&0x01FF)
	return c.sendInput(pdu.MouseEvent(flags, x, y))
}

// KeyScancode presses or releases a key by its PC/XT scancode.
func (c *Client) KeyScancode(code byte, down, extended bool) error {
	return c.sendInput(pdu.ScancodeEvent(code, down, extended))
}

// KeyUnicode presses and releases a character by its code point. It is the
// simplest way to send text; it bypasses keyboard-layout scancode mapping.
func (c *Client) KeyUnicode(ch rune) error {
	u := uint16(ch)
	return c.sendInput(
		pdu.UnicodeEvent(u, true),
		pdu.UnicodeEvent(u, false),
	)
}

// TypeUnicode sends a string as unicode key events.
func (c *Client) TypeUnicode(s string) error {
	for _, ch := range s {
		if err := c.KeyUnicode(ch); err != nil {
			return err
		}
	}
	return nil
}

// PressKey presses and releases a key by scancode.
func (c *Client) PressKey(code byte, extended bool) error {
	if err := c.KeyScancode(code, true, extended); err != nil {
		return err
	}
	return c.KeyScancode(code, false, extended)
}
