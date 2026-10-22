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

// Package cliprdr builds and parses the clipboard virtual channel protocol
// (MS-RDPECLIP) carried on the "cliprdr" static virtual channel. It covers the
// text path a bastion needs: the capability/monitor handshake, format-list
// exchange and format-data request/response for CF_UNICODETEXT.
package cliprdr

import (
	"unicode/utf16"

	"github.com/casvisor/gordp/core"
)

// CLIPRDR_HEADER message types (MS-RDPECLIP 2.2.1).
const (
	MsgMonitorReady       = 0x0001
	MsgFormatList         = 0x0002
	MsgFormatListResponse = 0x0003
	MsgFormatDataRequest  = 0x0004
	MsgFormatDataResponse = 0x0005
	MsgClipCaps           = 0x0007
)

// CLIPRDR_HEADER message flags.
const (
	FlagResponseOK   = 0x0001
	FlagResponseFail = 0x0002
	FlagAsciiNames   = 0x0004
)

// Standard Windows clipboard format IDs.
const (
	CfText        = 1
	CfUnicodeText = 13
)

// General capability flags (CLIPRDR_GENERAL_CAPABILITY.generalFlags).
const (
	capUseLongFormatNames = 0x00000002
)

const (
	capsTypeGeneral = 0x0001
	capsVersion2    = 0x00000002
)

// Message is a parsed CLIPRDR PDU: its type, flags and body (the bytes after
// the 8-byte CLIPRDR_HEADER).
type Message struct {
	Type  uint16
	Flags uint16
	Body  []byte
}

// Parse reads one CLIPRDR PDU from a reassembled channel payload.
func Parse(data []byte) (*Message, error) {
	r := core.NewReader(data)
	msgType, err := r.ReadUint16LE()
	if err != nil {
		return nil, err
	}
	flags, err := r.ReadUint16LE()
	if err != nil {
		return nil, err
	}
	length, err := r.ReadUint32LE()
	if err != nil {
		return nil, err
	}
	body, err := r.ReadBytes(int(length))
	if err != nil {
		// Some servers pad; fall back to whatever remains.
		body = data[8:]
	}
	return &Message{Type: msgType, Flags: flags, Body: body}, nil
}

func build(msgType, flags uint16, body []byte) []byte {
	w := core.NewWriter()
	w.WriteUint16LE(msgType)
	w.WriteUint16LE(flags)
	w.WriteUint32LE(uint32(len(body)))
	w.Write(body)
	return w.Bytes()
}

// BuildCaps builds a Clipboard Capabilities PDU advertising the general
// capability set. When longFormat is set, CB_USE_LONG_FORMAT_NAMES is offered.
func BuildCaps(longFormat bool) []byte {
	var flags uint32
	if longFormat {
		flags = capUseLongFormatNames
	}
	body := core.NewWriter()
	body.WriteUint16LE(1) // cCapabilitiesSets
	body.WriteUint16LE(0) // pad
	// CLIPRDR_CAPS_SET: type, length (12), then the general capability.
	body.WriteUint16LE(capsTypeGeneral)
	body.WriteUint16LE(12)
	body.WriteUint32LE(capsVersion2)
	body.WriteUint32LE(flags)
	return build(MsgClipCaps, 0, body.Bytes())
}

// ServerSupportsLongFormat reads a server Clipboard Capabilities PDU body and
// reports whether it advertised CB_USE_LONG_FORMAT_NAMES.
func ServerSupportsLongFormat(body []byte) bool {
	r := core.NewReader(body)
	count, err := r.ReadUint16LE()
	if err != nil {
		return false
	}
	if _, err := r.ReadUint16LE(); err != nil { // pad
		return false
	}
	for i := 0; i < int(count); i++ {
		setType, err := r.ReadUint16LE()
		if err != nil {
			return false
		}
		setLen, err := r.ReadUint16LE()
		if err != nil || setLen < 4 {
			return false
		}
		setBody, err := r.ReadBytes(int(setLen) - 4)
		if err != nil {
			return false
		}
		if setType == capsTypeGeneral && len(setBody) >= 8 {
			flags := core.NewReader(setBody[4:8])
			f, _ := flags.ReadUint32LE()
			return f&capUseLongFormatNames != 0
		}
	}
	return false
}

// BuildFormatList builds a Format List PDU announcing the given format IDs. It
// uses long or short format names depending on longFormat; format names are
// left empty, which is valid for the standard formats.
func BuildFormatList(formatIDs []uint32, longFormat bool) []byte {
	body := core.NewWriter()
	if longFormat {
		for _, id := range formatIDs {
			body.WriteUint32LE(id)
			body.WriteUint16LE(0) // empty UTF-16 name, null terminator only
		}
	} else {
		for _, id := range formatIDs {
			body.WriteUint32LE(id)
			body.Write(make([]byte, 32)) // 32-byte fixed name field, empty
		}
	}
	return build(MsgFormatList, 0, body.Bytes())
}

// ParseFormatList returns the format IDs in a Format List PDU body.
func ParseFormatList(body []byte, longFormat bool) []uint32 {
	var ids []uint32
	r := core.NewReader(body)
	if longFormat {
		for r.Remaining() >= 4 {
			id, err := r.ReadUint32LE()
			if err != nil {
				break
			}
			ids = append(ids, id)
			// Skip the null-terminated UTF-16 name.
			for {
				u, err := r.ReadUint16LE()
				if err != nil || u == 0 {
					break
				}
			}
		}
	} else {
		for r.Remaining() >= 36 {
			id, err := r.ReadUint32LE()
			if err != nil {
				break
			}
			if err := r.Skip(32); err != nil {
				break
			}
			ids = append(ids, id)
		}
	}
	return ids
}

// BuildFormatListResponse builds a Format List Response PDU.
func BuildFormatListResponse(ok bool) []byte {
	flags := uint16(FlagResponseFail)
	if ok {
		flags = FlagResponseOK
	}
	return build(MsgFormatListResponse, flags, nil)
}

// BuildFormatDataRequest builds a Format Data Request PDU for one format ID.
func BuildFormatDataRequest(formatID uint32) []byte {
	body := core.NewWriter()
	body.WriteUint32LE(formatID)
	return build(MsgFormatDataRequest, 0, body.Bytes())
}

// ParseFormatDataRequest returns the requested format ID.
func ParseFormatDataRequest(body []byte) (uint32, error) {
	return core.NewReader(body).ReadUint32LE()
}

// BuildFormatDataResponse builds a Format Data Response PDU carrying data.
func BuildFormatDataResponse(ok bool, data []byte) []byte {
	flags := uint16(FlagResponseFail)
	if ok {
		flags = FlagResponseOK
	}
	return build(MsgFormatDataResponse, flags, data)
}

// EncodeText encodes s as a CF_UNICODETEXT payload: UTF-16LE with a trailing
// null unit, the form Windows expects in a Format Data Response.
func EncodeText(s string) []byte {
	units := utf16.Encode([]rune(s))
	w := core.NewWriter()
	for _, u := range units {
		w.WriteUint16LE(u)
	}
	w.WriteUint16LE(0) // null terminator
	return w.Bytes()
}

// DecodeText decodes a CF_UNICODETEXT payload (UTF-16LE, possibly null
// terminated) into a Go string.
func DecodeText(data []byte) string {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		u := uint16(data[i]) | uint16(data[i+1])<<8
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}
