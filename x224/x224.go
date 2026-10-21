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

// Package x224 runs the X.224 (ITU-T) connection layer that sits directly on
// top of TPKT. Its job during the handshake is the RDP negotiation: the client
// asks for a security protocol (here TLS or CredSSP/NLA) and the server answers
// with the one it picked. After that, X.224 just wraps every PDU in a 3-byte
// data header.
package x224

import (
	"fmt"

	"github.com/casvisor/gordp/core"
	"github.com/casvisor/gordp/tpkt"
)

// Security protocols advertised in the RDP negotiation request (MS-RDPBCGR
// 2.2.1.1.1). We never offer PROTOCOL_RDP (standard RDP security) because it
// keeps credentials in weak RC4 and has no server authentication.
const (
	ProtocolSSL      uint32 = 0x00000001
	ProtocolHybrid   uint32 = 0x00000002
	ProtocolHybridEx uint32 = 0x00000008
)

const (
	tpduConnectionRequest = 0xE0
	tpduConnectionConfirm = 0xD0
	tpduData              = 0xF0

	negTypeRequest  = 0x01
	negTypeResponse = 0x02
	negTypeFailure  = 0x03
)

// Layer wraps a TPKT layer with the X.224 framing.
type Layer struct {
	tpkt *tpkt.Layer
	// SelectedProtocol is the security protocol the server chose, valid
	// after Connect returns.
	SelectedProtocol uint32
}

func New(t *tpkt.Layer) *Layer {
	return &Layer{tpkt: t}
}

// Connect sends the X.224 connection request offering requestedProtocols and
// reads the server's connection confirm. It returns the protocol the server
// selected.
func (l *Layer) Connect(requestedProtocols uint32) error {
	if err := l.sendConnectionRequest(requestedProtocols); err != nil {
		return err
	}
	return l.readConnectionConfirm()
}

func (l *Layer) sendConnectionRequest(requestedProtocols uint32) error {
	neg := core.NewWriter()
	neg.PutByte(negTypeRequest)
	neg.PutByte(0) // flags
	neg.WriteUint16LE(8)
	neg.WriteUint32LE(requestedProtocols)

	// X.224 Connection Request header. The length indicator counts the
	// bytes that follow it.
	body := core.NewWriter()
	body.PutByte(byte(6 + neg.Len())) // LI
	body.PutByte(tpduConnectionRequest)
	body.WriteUint16BE(0) // DST-REF
	body.WriteUint16BE(0) // SRC-REF
	body.PutByte(0)       // class option
	body.Write(neg.Bytes())

	return l.tpkt.Write(body.Bytes())
}

func (l *Layer) readConnectionConfirm() error {
	pdu, err := l.tpkt.Read()
	if err != nil {
		return err
	}
	if pdu.FastPath {
		return fmt.Errorf("x224: unexpected fast-path pdu during negotiation")
	}

	r := core.NewReader(pdu.Payload)
	if _, err := r.ReadByte(); err != nil { // LI
		return err
	}
	code, err := r.ReadByte()
	if err != nil {
		return err
	}
	if code != tpduConnectionConfirm {
		return fmt.Errorf("x224: expected connection confirm, got 0x%02x", code)
	}
	if err := r.Skip(5); err != nil { // DST-REF, SRC-REF, class
		return err
	}

	// The negotiation response/failure is optional but Windows always sends
	// it when the client asked for something other than standard RDP.
	if r.Remaining() == 0 {
		l.SelectedProtocol = 0
		return nil
	}

	negType, err := r.ReadByte()
	if err != nil {
		return err
	}
	if _, err := r.ReadByte(); err != nil { // flags
		return err
	}
	if _, err := r.ReadUint16LE(); err != nil { // length
		return err
	}
	value, err := r.ReadUint32LE()
	if err != nil {
		return err
	}

	switch negType {
	case negTypeResponse:
		l.SelectedProtocol = value
		return nil
	case negTypeFailure:
		return fmt.Errorf("x224: server rejected negotiation: %s", failureReason(value))
	default:
		return fmt.Errorf("x224: unexpected negotiation type 0x%02x", negType)
	}
}

// Send wraps payload in an X.224 data header and sends it.
func (l *Layer) Send(payload []byte) error {
	w := core.NewWriter()
	w.PutByte(2) // LI
	w.PutByte(tpduData)
	w.PutByte(0x80) // EOT
	w.Write(payload)
	return l.tpkt.Write(w.Bytes())
}

// Receive reads an X.224 data PDU and returns its payload.
func (l *Layer) Receive() (*tpkt.PDU, error) {
	pdu, err := l.tpkt.Read()
	if err != nil {
		return nil, err
	}
	if pdu.FastPath {
		return pdu, nil
	}
	r := core.NewReader(pdu.Payload)
	if err := r.Skip(3); err != nil { // LI, DT, EOT
		return nil, err
	}
	rest, err := r.ReadBytes(r.Remaining())
	if err != nil {
		return nil, err
	}
	pdu.Payload = rest
	return pdu, nil
}

func failureReason(code uint32) string {
	switch code {
	case 0x00000001:
		return "SSL_REQUIRED_BY_SERVER"
	case 0x00000002:
		return "SSL_NOT_ALLOWED_BY_SERVER"
	case 0x00000003:
		return "SSL_CERT_NOT_ON_SERVER"
	case 0x00000004:
		return "INCONSISTENT_FLAGS"
	case 0x00000005:
		return "HYBRID_REQUIRED_BY_SERVER"
	case 0x00000006:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	default:
		return fmt.Sprintf("unknown(0x%08x)", code)
	}
}
