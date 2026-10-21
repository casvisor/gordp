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

import (
	"fmt"

	"github.com/casvisor/gordp/core"
)

// Share control header PDU types (MS-RDPBCGR 2.2.8.1.1.1.1).
const (
	PdutypeDemandActive  = 0x1
	PdutypeConfirmActive = 0x3
	PdutypeDeactivateAll = 0x6
	PdutypeData          = 0x7

	protocolVersion = 0x10 // TS_PROTOCOL_VERSION, high nibble of pduType
)

// Share data header PDU types (TS_SHAREDATAHEADER.pduType2, MS-RDPBCGR
// 2.2.8.1.1.1.2).
const (
	Pdutype2Update      = 0x02
	Pdutype2Control     = 0x14
	Pdutype2Pointer     = 0x1B
	Pdutype2Synchronize = 0x1F
	Pdutype2FontList    = 0x27
	Pdutype2FontMap     = 0x28
	Pdutype2SetError    = 0x2F
)

const streamLow = 0x01

// ShareControl is a parsed share control header.
type ShareControl struct {
	PduType   uint16
	PduSource uint16
	Body      []byte
}

// writeShareControl wraps body in a share control header.
func writeShareControl(w *core.Writer, pduType uint16, pduSource uint16, body []byte) {
	w.WriteUint16LE(uint16(len(body) + 6))
	w.WriteUint16LE(pduType | (protocolVersion << 4))
	w.WriteUint16LE(pduSource)
	w.Write(body)
}

// ReadShareControl parses a share control header from a PDU payload.
func ReadShareControl(payload []byte) (*ShareControl, error) {
	r := core.NewReader(payload)
	totalLength, err := r.ReadUint16LE()
	if err != nil {
		return nil, err
	}
	pduType, err := r.ReadUint16LE()
	if err != nil {
		return nil, err
	}
	pduSource, err := r.ReadUint16LE()
	if err != nil {
		return nil, err
	}
	if int(totalLength) < 6 {
		return nil, fmt.Errorf("pdu: bad share control length %d", totalLength)
	}
	body, err := r.ReadBytes(int(totalLength) - 6)
	if err != nil {
		return nil, err
	}
	return &ShareControl{
		PduType:   pduType & 0x0F,
		PduSource: pduSource,
		Body:      body,
	}, nil
}

// writeShareData wraps body in a share data header on top of a share control
// header, used for all the finalization and update data PDUs.
func writeShareData(w *core.Writer, pduSource uint16, shareID uint32, pduType2 byte, body []byte) {
	data := core.NewWriter()
	data.WriteUint32LE(shareID)
	data.PutByte(0) // pad1
	data.PutByte(streamLow)
	data.WriteUint16LE(uint16(len(body) + 4)) // uncompressedLength: data + this header's tail
	data.PutByte(pduType2)
	data.PutByte(0)       // compressedType
	data.WriteUint16LE(0) // compressedLength
	data.Write(body)
	writeShareControl(w, PdutypeData, pduSource, data.Bytes())
}

// ShareData is a parsed share data header body.
type ShareData struct {
	PduType2 byte
	Body     []byte
}

// ReadShareData parses a share data header from a share control body.
func ReadShareData(body []byte) (*ShareData, error) {
	r := core.NewReader(body)
	if _, err := r.ReadUint32LE(); err != nil { // shareID
		return nil, err
	}
	if _, err := r.ReadByte(); err != nil { // pad1
		return nil, err
	}
	if _, err := r.ReadByte(); err != nil { // streamID
		return nil, err
	}
	if _, err := r.ReadUint16LE(); err != nil { // uncompressedLength
		return nil, err
	}
	pduType2, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if _, err := r.ReadByte(); err != nil { // compressedType
		return nil, err
	}
	if _, err := r.ReadUint16LE(); err != nil { // compressedLength
		return nil, err
	}
	rest, err := r.ReadBytes(r.Remaining())
	if err != nil {
		return nil, err
	}
	return &ShareData{PduType2: pduType2, Body: rest}, nil
}
