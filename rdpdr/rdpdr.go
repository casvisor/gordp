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

// Package rdpdr implements the device redirection virtual channel protocol
// (MS-RDPEFS) carried on the "rdpdr" static virtual channel: the core
// initialization handshake and file system (drive) redirection, which exposes a
// local directory to the remote session as \\tsclient\<name>.
package rdpdr

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// RDPDR_HEADER component and packet IDs (MS-RDPEFS 2.2.1.1).
const (
	ComponentCore = 0x4472

	PacketServerAnnounce     = 0x496E
	PacketClientIDConfirm    = 0x4343
	PacketClientName         = 0x434E
	PacketDeviceListAnnounce = 0x4441
	PacketDeviceReply        = 0x6472
	PacketDeviceIORequest    = 0x4952
	PacketDeviceIOCompletion = 0x4943
	PacketServerCapability   = 0x5350
	PacketClientCapability   = 0x4350
	PacketUserLoggedOn       = 0x554C
)

const (
	versionMajor    = 0x0001
	maxVersionMinor = 0x000D

	capGeneralType = 0x0001
	capDriveType   = 0x0004

	generalCapVersion02 = 0x00000002
	driveCapVersion02   = 0x00000002

	// extendedPDU: device remove, client display name and user logged-on PDUs.
	extendedPDU = 0x00000001 | 0x00000002 | 0x00000004

	deviceTypeFilesystem = 0x00000008
)

// Message is a parsed RDPDR PDU: its component, packet ID and the bytes after
// the 4-byte RDPDR_HEADER.
type Message struct {
	Component uint16
	PacketID  uint16
	Body      []byte
}

// Parse reads one RDPDR PDU from a reassembled channel payload.
func Parse(data []byte) (*Message, error) {
	if len(data) < 4 {
		return nil, errors.New("rdpdr: short header")
	}
	return &Message{
		Component: binary.LittleEndian.Uint16(data[0:]),
		PacketID:  binary.LittleEndian.Uint16(data[2:]),
		Body:      data[4:],
	}, nil
}

// builder accumulates a little-endian PDU.
type builder struct{ b []byte }

func newPDU(packetID uint16) *builder {
	p := &builder{}
	p.u16(ComponentCore)
	p.u16(packetID)
	return p
}

func (p *builder) u8(v byte)     { p.b = append(p.b, v) }
func (p *builder) u16(v uint16)  { p.b = binary.LittleEndian.AppendUint16(p.b, v) }
func (p *builder) u32(v uint32)  { p.b = binary.LittleEndian.AppendUint32(p.b, v) }
func (p *builder) u64(v uint64)  { p.b = binary.LittleEndian.AppendUint64(p.b, v) }
func (p *builder) raw(v []byte)  { p.b = append(p.b, v...) }
func (p *builder) zero(n int)    { p.b = append(p.b, make([]byte, n)...) }
func (p *builder) bytes() []byte { return p.b }

// ServerAnnounce is the server's opening PDU.
type ServerAnnounce struct {
	VersionMinor uint16
	ClientID     uint32
}

// ParseServerAnnounce parses a Server Announce Request body.
func ParseServerAnnounce(body []byte) (ServerAnnounce, error) {
	if len(body) < 8 {
		return ServerAnnounce{}, errors.New("rdpdr: short server announce")
	}
	return ServerAnnounce{
		VersionMinor: binary.LittleEndian.Uint16(body[2:]),
		ClientID:     binary.LittleEndian.Uint32(body[4:]),
	}, nil
}

// ClientVersionMinor picks the protocol minor version to reply with.
func ClientVersionMinor(serverMinor uint16) uint16 {
	if serverMinor < maxVersionMinor {
		return serverMinor
	}
	return maxVersionMinor
}

// BuildClientIDConfirm builds the Client Announce Reply.
func BuildClientIDConfirm(versionMinor uint16, clientID uint32) []byte {
	p := newPDU(PacketClientIDConfirm)
	p.u16(versionMajor)
	p.u16(versionMinor)
	p.u32(clientID)
	return p.bytes()
}

// BuildClientName builds the Client Name Request with a Unicode computer name.
func BuildClientName(name string) []byte {
	n := encodeUTF16(name, true)
	p := newPDU(PacketClientName)
	p.u32(1) // UnicodeFlag
	p.u32(0) // CodePage
	p.u32(uint32(len(n)))
	p.raw(n)
	return p.bytes()
}

// BuildClientCapability builds the Client Core Capability Response: the general
// capability set, plus the drive capability set when drives are redirected.
func BuildClientCapability(versionMinor uint16, drives bool) []byte {
	p := newPDU(PacketClientCapability)
	if drives {
		p.u16(2)
	} else {
		p.u16(1)
	}
	p.u16(0) // padding
	p.u16(capGeneralType)
	p.u16(44)
	p.u32(generalCapVersion02)
	p.u32(0) // osType
	p.u32(0) // osVersion
	p.u16(versionMajor)
	p.u16(versionMinor)
	p.u32(0x0000FFFF) // ioCode1: all I/O requests
	p.u32(0)          // ioCode2
	p.u32(extendedPDU)
	p.u32(0) // extraFlags1
	p.u32(0) // extraFlags2
	p.u32(0) // SpecialTypeDeviceCap
	if drives {
		p.u16(capDriveType)
		p.u16(8)
		p.u32(driveCapVersion02)
	}
	return p.bytes()
}

// BuildDeviceListAnnounce builds a Client Device List Announce for drives,
// numbered from 1 in order.
func BuildDeviceListAnnounce(names []string) []byte {
	p := newPDU(PacketDeviceListAnnounce)
	p.u32(uint32(len(names)))
	for i, name := range names {
		ascii := asciiName(name)
		dos := make([]byte, 8)
		copy(dos, ascii)
		p.u32(deviceTypeFilesystem)
		p.u32(uint32(i + 1))
		p.raw(dos)
		p.u32(uint32(len(ascii) + 1))
		p.raw(ascii)
		p.u8(0)
	}
	return p.bytes()
}

// asciiName replaces non-ASCII bytes, which PreferredDosName cannot carry.
func asciiName(name string) []byte {
	b := []byte(name)
	for i, c := range b {
		if c > 0x7F {
			b[i] = '_'
		}
	}
	return b
}

// IORequest is a parsed Device I/O Request (DR_DEVICE_IOREQUEST).
type IORequest struct {
	DeviceID      uint32
	FileID        uint32
	CompletionID  uint32
	MajorFunction uint32
	MinorFunction uint32
	Body          []byte
}

// ParseIORequest parses a Device I/O Request body.
func ParseIORequest(body []byte) (*IORequest, error) {
	if len(body) < 20 {
		return nil, errors.New("rdpdr: short I/O request")
	}
	le := binary.LittleEndian
	return &IORequest{
		DeviceID:      le.Uint32(body[0:]),
		FileID:        le.Uint32(body[4:]),
		CompletionID:  le.Uint32(body[8:]),
		MajorFunction: le.Uint32(body[12:]),
		MinorFunction: le.Uint32(body[16:]),
		Body:          body[20:],
	}, nil
}

// buildCompletion builds a Device I/O Response with its function-specific tail.
func buildCompletion(req *IORequest, status uint32, tail []byte) []byte {
	p := newPDU(PacketDeviceIOCompletion)
	p.u32(req.DeviceID)
	p.u32(req.CompletionID)
	p.u32(status)
	p.raw(tail)
	return p.bytes()
}

func encodeUTF16(s string, nul bool) []byte {
	units := utf16.Encode([]rune(s))
	if nul {
		units = append(units, 0)
	}
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func decodeUTF16(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}
