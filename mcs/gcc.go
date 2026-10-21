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

package mcs

import (
	"fmt"
	"unicode/utf16"

	"github.com/casvisor/gordp/core"
	"github.com/casvisor/gordp/core/per"
)

// GCC user data block types (MS-RDPBCGR 2.2.1.3).
const (
	csCore     = 0xC001
	csSecurity = 0xC002
	csNet      = 0xC003
	csCluster  = 0xC004

	scCore     = 0x0C01
	scSecurity = 0x0C02
	scNet      = 0x0C03
)

// gccOID is the t124 object identifier {0 0 20 124 0 1}.
var gccOID = [6]byte{0, 0, 20, 124, 0, 1}

// ClientConfig carries the few GCC client-core fields that matter to the
// session: the desktop size and the security protocol X.224 selected (the
// server checks the latter matches).
type ClientConfig struct {
	DesktopWidth     uint16
	DesktopHeight    uint16
	SelectedProtocol uint32
	Name             string
}

// buildClientData assembles the TS_UD_CS_* blocks that go in the GCC userData.
func buildClientData(cfg ClientConfig) []byte {
	w := core.NewWriter()
	writeClientCoreData(w, cfg)
	writeClientSecurityData(w)
	writeClientNetworkData(w)
	writeClientClusterData(w)
	return w.Bytes()
}

func writeUserDataHeader(w *core.Writer, blockType uint16, length uint16) {
	w.WriteUint16LE(blockType)
	w.WriteUint16LE(length)
}

func writeClientCoreData(w *core.Writer, cfg ClientConfig) {
	const length = 216
	writeUserDataHeader(w, csCore, length)
	w.WriteUint32LE(0x00080004) // version: RDP 5.0+
	w.WriteUint16LE(cfg.DesktopWidth)
	w.WriteUint16LE(cfg.DesktopHeight)
	w.WriteUint16LE(0xCA01) // colorDepth: 8bpp (legacy, superseded by highColorDepth)
	w.WriteUint16LE(0xAA03) // SASSequence
	w.WriteUint32LE(0x409)  // keyboardLayout: US
	w.WriteUint32LE(0x1DB0) // clientBuild
	w.Write(fixedUTF16(cfg.Name, 32))
	w.WriteUint32LE(0x4)      // keyboardType: IBM enhanced
	w.WriteUint32LE(0x0)      // keyboardSubType
	w.WriteUint32LE(0xC)      // keyboardFunctionKey
	w.Write(make([]byte, 64)) // imeFileName
	w.WriteUint16LE(0xCA01)   // postBeta2ColorDepth
	w.WriteUint16LE(0x1)      // clientProductId
	w.WriteUint32LE(0x0)      // serialNumber
	w.WriteUint16LE(0x0018)   // highColorDepth: 24bpp
	w.WriteUint16LE(0x0007)   // supportedColorDepths
	w.WriteUint16LE(0x0001)   // earlyCapabilityFlags: RNS_UD_CS_SUPPORT_ERRINFO_PDU
	w.Write(make([]byte, 64)) // clientDigProductId
	w.PutByte(0x0)            // connectionType
	w.PutByte(0x0)            // pad1octet
	w.WriteUint32LE(cfg.SelectedProtocol)
}

func writeClientSecurityData(w *core.Writer) {
	const length = 12
	writeUserDataHeader(w, csSecurity, length)
	// We run over TLS/CredSSP, so no RDP-level encryption.
	w.WriteUint32LE(0) // encryptionMethods
	w.WriteUint32LE(0) // extEncryptionMethods
}

func writeClientNetworkData(w *core.Writer) {
	const length = 8
	writeUserDataHeader(w, csNet, length)
	w.WriteUint32LE(0) // channelCount: no virtual channels yet
}

func writeClientClusterData(w *core.Writer) {
	const length = 12
	writeUserDataHeader(w, csCluster, length)
	w.WriteUint32LE(0x0D) // flags: REDIRECTION_SUPPORTED | version 3
	w.WriteUint32LE(0)    // redirectedSessionID
}

// buildConferenceCreateRequest wraps the client data in the GCC CCR envelope
// (MS-RDPBCGR 2.2.1.3.1).
func buildConferenceCreateRequest(userData []byte) []byte {
	w := core.NewWriter()
	per.WriteChoice(w, 0)
	per.WriteObjectIdentifier(w, gccOID)
	per.WriteLength(w, len(userData)+14)
	per.WriteChoice(w, 0)
	per.WriteSelection(w, 0x08)
	// ConferenceName "1" as a numeric string.
	per.WriteLength(w, 0)
	w.PutByte(0x10)
	w.PutByte(0x00) // padding
	per.WriteNumberOfSet(w, 1)
	per.WriteChoice(w, 0xC0)
	per.WriteOctetStream(w, []byte("Duca"), 4)
	per.WriteOctetStream(w, userData, 0)
	return w.Bytes()
}

// ServerData holds the parts of the GCC server response the session needs.
type ServerData struct {
	// IOChannelID is the MCS channel for the main graphics/input stream.
	IOChannelID uint16
	// ChannelIDs are the virtual channel IDs, in request order.
	ChannelIDs []uint16
}

// parseConferenceCreateResponse walks the GCC CCResp header and returns the
// server data blocks (MS-RDPBCGR 2.2.1.4).
func parseConferenceCreateResponse(data []byte) (*ServerData, error) {
	r := core.NewReader(data)

	if _, err := per.ReadChoice(r); err != nil { // choice
		return nil, err
	}
	// Object identifier: length(5) then 5 bytes.
	if _, err := per.ReadLength(r); err != nil {
		return nil, err
	}
	if err := r.Skip(5); err != nil {
		return nil, err
	}
	if _, err := per.ReadLength(r); err != nil { // connectPDU length
		return nil, err
	}
	if _, err := per.ReadChoice(r); err != nil { // choice
		return nil, err
	}
	if _, err := per.ReadInteger16(r, 1001); err != nil { // nodeID
		return nil, err
	}
	// tag: PER integer (length-prefixed).
	if tagLen, err := per.ReadLength(r); err != nil {
		return nil, err
	} else if err := r.Skip(tagLen); err != nil {
		return nil, err
	}
	if _, err := r.ReadByte(); err != nil { // result (enumerated)
		return nil, err
	}
	if _, err := r.ReadByte(); err != nil { // number of set
		return nil, err
	}
	if _, err := r.ReadByte(); err != nil { // choice (0xC0)
		return nil, err
	}
	// Server H.221 key "McDn": octet stream, length prefix then 4 bytes.
	if _, err := per.ReadLength(r); err != nil {
		return nil, err
	}
	if err := r.Skip(4); err != nil {
		return nil, err
	}
	if _, err := per.ReadLength(r); err != nil { // userData length
		return nil, err
	}

	return parseServerDataBlocks(r)
}

func parseServerDataBlocks(r *core.Reader) (*ServerData, error) {
	sd := &ServerData{}
	for r.Remaining() >= 4 {
		blockType, err := r.ReadUint16LE()
		if err != nil {
			return nil, err
		}
		length, err := r.ReadUint16LE()
		if err != nil {
			return nil, err
		}
		if length < 4 {
			return nil, fmt.Errorf("gcc: bad server data block length %d", length)
		}
		body, err := r.ReadBytes(int(length) - 4)
		if err != nil {
			return nil, err
		}
		if blockType == scNet {
			if err := parseServerNetworkData(body, sd); err != nil {
				return nil, err
			}
		}
	}
	if sd.IOChannelID == 0 {
		return nil, fmt.Errorf("gcc: server did not provide an I/O channel")
	}
	return sd, nil
}

func parseServerNetworkData(body []byte, sd *ServerData) error {
	r := core.NewReader(body)
	ioChannel, err := r.ReadUint16LE()
	if err != nil {
		return err
	}
	sd.IOChannelID = ioChannel
	count, err := r.ReadUint16LE()
	if err != nil {
		return err
	}
	for i := 0; i < int(count); i++ {
		id, err := r.ReadUint16LE()
		if err != nil {
			return err
		}
		sd.ChannelIDs = append(sd.ChannelIDs, id)
	}
	return nil
}

// fixedUTF16 encodes s as little-endian UTF-16 padded or truncated to size
// bytes (including a trailing null when it fits).
func fixedUTF16(s string, size int) []byte {
	out := make([]byte, size)
	units := utf16.Encode([]rune(s))
	for i, u := range units {
		if (i+1)*2 > size {
			break
		}
		out[i*2] = byte(u)
		out[i*2+1] = byte(u >> 8)
	}
	return out
}
