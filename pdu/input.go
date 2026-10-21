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

package pdu

import "github.com/casvisor/gordp/core"

// Fast-path input event codes (MS-RDPBCGR 2.2.8.1.2.2), in bits 5-7 of the
// event header.
const (
	inputEventScancode = 0x0
	inputEventMouse    = 0x1
	inputEventMouseX   = 0x2
	inputEventSync     = 0x3
	inputEventUnicode  = 0x4
)

// Keyboard event flags (MS-RDPBCGR 2.2.8.1.2.2.1).
const (
	kbdFlagRelease  = 0x01
	kbdFlagExtended = 0x02
)

// Mouse pointer flags (MS-RDPBCGR 2.2.8.1.2.2.3).
const (
	PtrFlagsMove    = 0x0800
	PtrFlagsDown    = 0x8000
	PtrFlagsButton1 = 0x1000 // left
	PtrFlagsButton2 = 0x2000 // right
	PtrFlagsButton3 = 0x4000 // middle
	PtrFlagsWheel   = 0x0200
)

// ScancodeEvent builds a fast-path keyboard event.
func ScancodeEvent(code byte, down, extended bool) []byte {
	header := byte(inputEventScancode << 5)
	if !down {
		header |= kbdFlagRelease
	}
	if extended {
		header |= kbdFlagExtended
	}
	return []byte{header, code}
}

// UnicodeEvent builds a fast-path unicode keyboard event.
func UnicodeEvent(ch uint16, down bool) []byte {
	header := byte(inputEventUnicode << 5)
	if !down {
		header |= kbdFlagRelease
	}
	return []byte{header, byte(ch), byte(ch >> 8)}
}

// MouseEvent builds a fast-path mouse event with the given pointer flags.
func MouseEvent(flags, x, y uint16) []byte {
	w := core.NewWriter()
	w.PutByte(byte(inputEventMouse << 5))
	w.WriteUint16LE(flags)
	w.WriteUint16LE(x)
	w.WriteUint16LE(y)
	return w.Bytes()
}

// SyncEvent builds a fast-path synchronize event carrying the lock-key state.
func SyncEvent(toggleFlags uint32) []byte {
	w := core.NewWriter()
	w.PutByte(byte(inputEventSync << 5))
	w.WriteUint16LE(uint16(toggleFlags))
	return w.Bytes()
}

// BuildFastPathInput wraps up to 15 input events in a fast-path input PDU. The
// result is written directly to the transport, not through MCS.
func BuildFastPathInput(events [][]byte) []byte {
	var body []byte
	for _, e := range events {
		body = append(body, e...)
	}

	header := byte(len(events) << 2) // action 0, numberEvents in bits 2-5

	if total := 2 + len(body); total < 0x80 {
		out := []byte{header, byte(total)}
		return append(out, body...)
	}
	total := 3 + len(body)
	out := []byte{header, byte(0x80 | (total >> 8)), byte(total & 0xff)}
	return append(out, body...)
}
