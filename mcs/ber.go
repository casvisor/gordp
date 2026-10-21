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

	"github.com/casvisor/gordp/core"
)

// BER tags used by the MCS Connect PDUs (T.125 uses BER for these two, PER for
// everything after).
const (
	berBoolean     = 0x01
	berInteger     = 0x02
	berOctetString = 0x04
	berEnumerated  = 0x0A
	berSequence    = 0x30

	berConnectInitial  = 0x7f65 // [APPLICATION 101]
	berConnectResponse = 0x7f66 // [APPLICATION 102]
)

func berWriteLength(w *core.Writer, length int) {
	if length > 0x7f {
		w.PutByte(0x82)
		w.WriteUint16BE(uint16(length))
	} else {
		w.PutByte(byte(length))
	}
}

func berWriteApplicationTag(w *core.Writer, tag uint16, length int) {
	w.WriteUint16BE(tag)
	berWriteLength(w, length)
}

func berWriteUniversal(w *core.Writer, tag byte, value []byte) {
	w.PutByte(tag)
	berWriteLength(w, len(value))
	w.Write(value)
}

func berWriteInteger(w *core.Writer, value uint32) {
	v := core.NewWriter()
	switch {
	case value <= 0xff:
		v.PutByte(byte(value))
	case value <= 0xffff:
		v.WriteUint16BE(uint16(value))
	default:
		v.WriteUint32BE(value)
	}
	berWriteUniversal(w, berInteger, v.Bytes())
}

func berWriteBoolean(w *core.Writer, value bool) {
	b := byte(0)
	if value {
		b = 0xff
	}
	berWriteUniversal(w, berBoolean, []byte{b})
}

// domainParameters is one DomainParameters SEQUENCE.
func domainParameters(maxChannels, maxUsers, maxTokens, maxPDUSize uint32) []byte {
	w := core.NewWriter()
	berWriteInteger(w, maxChannels)
	berWriteInteger(w, maxUsers)
	berWriteInteger(w, maxTokens)
	berWriteInteger(w, 1) // numPriorities
	berWriteInteger(w, 0) // minThroughput
	berWriteInteger(w, 1) // maxHeight
	berWriteInteger(w, maxPDUSize)
	berWriteInteger(w, 2) // protocolVersion
	out := core.NewWriter()
	berWriteUniversal(out, berSequence, w.Bytes())
	return out.Bytes()
}

// buildConnectInitial builds the MCS Connect-Initial PDU carrying the GCC
// conference create request (MS-RDPBCGR 2.2.1.3).
func buildConnectInitial(gcc []byte) []byte {
	body := core.NewWriter()
	berWriteUniversal(body, berOctetString, []byte{0x01})        // callingDomainSelector
	berWriteUniversal(body, berOctetString, []byte{0x01})        // calledDomainSelector
	berWriteBoolean(body, true)                                  // upwardFlag
	body.Write(domainParameters(34, 2, 0, 0xffff))               // target
	body.Write(domainParameters(1, 1, 1, 0x420))                 // minimum
	body.Write(domainParameters(0xffff, 0xfc17, 0xffff, 0xffff)) // maximum
	berWriteUniversal(body, berOctetString, gcc)                 // userData

	out := core.NewWriter()
	berWriteApplicationTag(out, berConnectInitial, body.Len())
	out.Write(body.Bytes())
	return out.Bytes()
}

// parseConnectResponse reads the MCS Connect-Response and returns the server
// data from the embedded GCC conference create response.
func parseConnectResponse(data []byte) (*ServerData, error) {
	r := core.NewReader(data)

	tag, err := r.ReadUint16BE()
	if err != nil {
		return nil, err
	}
	if tag != berConnectResponse {
		return nil, fmt.Errorf("mcs: expected connect-response tag, got 0x%04x", tag)
	}
	if _, err := berReadLength(r); err != nil {
		return nil, err
	}
	if _, err := berReadUniversal(r, berEnumerated); err != nil { // result
		return nil, err
	}
	if _, err := berReadUniversal(r, berInteger); err != nil { // calledConnectId
		return nil, err
	}
	if err := berSkipUniversal(r, berSequence); err != nil { // domainParameters
		return nil, err
	}
	userData, err := berReadUniversal(r, berOctetString) // userData = GCC CCResp
	if err != nil {
		return nil, err
	}
	return parseConferenceCreateResponse(userData)
}

func berReadLength(r *core.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b&0x80 == 0 {
		return int(b), nil
	}
	numBytes := int(b & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, fmt.Errorf("mcs: unsupported BER length form (%d bytes)", numBytes)
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		length = length<<8 | int(c)
	}
	return length, nil
}

func berReadUniversal(r *core.Reader, tag byte) ([]byte, error) {
	got, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if got != tag {
		return nil, fmt.Errorf("mcs: expected BER tag 0x%02x, got 0x%02x", tag, got)
	}
	length, err := berReadLength(r)
	if err != nil {
		return nil, err
	}
	return r.ReadBytes(length)
}

func berSkipUniversal(r *core.Reader, tag byte) error {
	_, err := berReadUniversal(r, tag)
	return err
}
