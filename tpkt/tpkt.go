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

// Package tpkt frames RDP PDUs. During the connection handshake every PDU is
// wrapped in a TPKT header (RFC 1006). Once the session is up the server may
// also send fast-path update PDUs, whose first byte is not the TPKT version
// 0x03, so the reader tells the two apart by that first byte.
package tpkt

import (
	"fmt"
	"io"

	"github.com/casvisor/gordp/core"
)

const (
	version = 0x03
	// FastPath marks a PDU read as a fast-path update rather than a
	// TPKT-framed slow-path PDU.
	actionFastPath = 0x00
)

// Layer reads and writes framed PDUs over an underlying connection. The
// underlying io.ReadWriter is swapped for a *tls.Conn after the X.224
// negotiation upgrades the transport.
type Layer struct {
	conn io.ReadWriter
}

func New(conn io.ReadWriter) *Layer {
	return &Layer{conn: conn}
}

// SetConn replaces the transport, used to switch to TLS after negotiation.
func (l *Layer) SetConn(conn io.ReadWriter) {
	l.conn = conn
}

// Conn returns the current transport.
func (l *Layer) Conn() io.ReadWriter {
	return l.conn
}

// Write wraps payload in a TPKT header and sends it.
func (l *Layer) Write(payload []byte) error {
	total := len(payload) + 4
	if total > 0xffff {
		return fmt.Errorf("tpkt: pdu too large: %d", total)
	}

	w := core.NewWriter()
	w.PutByte(version)
	w.PutByte(0)
	w.WriteUint16BE(uint16(total))
	w.Write(payload)

	_, err := l.conn.Write(w.Bytes())
	return err
}

// PDU is one framed message read from the transport.
type PDU struct {
	// FastPath is true when the PDU is a fast-path update, false when it is
	// a TPKT-framed slow-path PDU.
	FastPath bool
	// Header is the first byte for a fast-path PDU, carrying its flags.
	Header byte
	// Payload is the message body after the framing header.
	Payload []byte
}

// Read reads one framed PDU, blocking until it is complete.
func (l *Layer) Read() (*PDU, error) {
	first, err := l.readFull(1)
	if err != nil {
		return nil, err
	}

	if first[0] == version {
		// TPKT: version(1) reserved(1) length(2, big-endian).
		rest, err := l.readFull(3)
		if err != nil {
			return nil, err
		}
		total := int(rest[1])<<8 | int(rest[2])
		if total < 4 {
			return nil, fmt.Errorf("tpkt: bad length %d", total)
		}
		body, err := l.readFull(total - 4)
		if err != nil {
			return nil, err
		}
		return &PDU{FastPath: false, Payload: body}, nil
	}

	// Fast-path: first byte is flags, then a 1- or 2-byte length. When the
	// top bit of the second byte is set the length is 2 bytes, big-endian
	// style with the high bit as a continuation marker.
	lenByte, err := l.readFull(1)
	if err != nil {
		return nil, err
	}
	var headerLen, total int
	if lenByte[0]&0x80 != 0 {
		second, err := l.readFull(1)
		if err != nil {
			return nil, err
		}
		total = int(lenByte[0]&0x7f)<<8 | int(second[0])
		headerLen = 3
	} else {
		total = int(lenByte[0])
		headerLen = 2
	}
	if total < headerLen {
		return nil, fmt.Errorf("tpkt: bad fast-path length %d", total)
	}
	body, err := l.readFull(total - headerLen)
	if err != nil {
		return nil, err
	}
	_ = actionFastPath
	return &PDU{FastPath: true, Header: first[0], Payload: body}, nil
}

func (l *Layer) readFull(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(l.conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
