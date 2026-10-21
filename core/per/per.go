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

// Package per implements the slice of ALIGNED PER (Packed Encoding Rules,
// ITU-T X.691) that RDP's MCS and GCC layers use. RDP only exercises a handful
// of PER constructs, so this is deliberately small rather than a general codec.
package per

import (
	"fmt"

	"github.com/casvisor/gordp/core"
)

// WriteLength writes a PER length determinant. Values below 128 take one byte;
// larger values take two bytes with the top bit set.
func WriteLength(w *core.Writer, length int) {
	if length >= 0x80 {
		w.WriteUint16BE(uint16(length) | 0x8000)
	} else {
		w.PutByte(byte(length))
	}
}

// ReadLength reads a PER length determinant.
func ReadLength(r *core.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b&0x80 != 0 {
		b2, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return int(b&0x7f)<<8 | int(b2), nil
	}
	return int(b), nil
}

// WriteChoice writes a CHOICE index.
func WriteChoice(w *core.Writer, choice byte) {
	w.PutByte(choice)
}

// WriteSelection writes an enumerated/selection octet (used for bit fields).
func WriteSelection(w *core.Writer, selection byte) {
	w.PutByte(selection)
}

// WriteNumberOfSet writes the count octet used before a set.
func WriteNumberOfSet(w *core.Writer, n byte) {
	w.PutByte(n)
}

// WriteInteger writes a constrained INTEGER as 1, 2 or 4 bytes with a PER
// length prefix, the form MCS uses for channel and user IDs.
func WriteInteger(w *core.Writer, value uint32) {
	switch {
	case value <= 0xff:
		WriteLength(w, 1)
		w.PutByte(byte(value))
	case value <= 0xffff:
		WriteLength(w, 2)
		w.WriteUint16BE(uint16(value))
	default:
		WriteLength(w, 4)
		w.WriteUint32BE(value)
	}
}

// WriteInteger16 writes a 16-bit INTEGER offset by the given base, the form
// used for MCS channel and user IDs on the wire.
func WriteInteger16(w *core.Writer, value uint16, base uint16) {
	w.WriteUint16BE(value - base)
}

// ReadInteger16 reads a 16-bit INTEGER and adds base.
func ReadInteger16(r *core.Reader, base uint16) (uint16, error) {
	v, err := r.ReadUint16BE()
	if err != nil {
		return 0, err
	}
	return v + base, nil
}

// WriteObjectIdentifier writes the fixed 6-byte OID RDP uses for GCC (t124).
func WriteObjectIdentifier(w *core.Writer, oid [6]byte) {
	WriteLength(w, 5)
	w.PutByte(byte(oid[0]<<4) | (oid[1] & 0x0f))
	w.PutByte(oid[2])
	w.PutByte(oid[3])
	w.PutByte(oid[4])
	w.PutByte(oid[5])
}

// WriteOctetStream writes an octet string with a PER length prefix padded to a
// minimum length, used for MCS domain selectors.
func WriteOctetStream(w *core.Writer, stream []byte, minValue int) {
	length := len(stream)
	if length < minValue {
		length = minValue
	}
	WriteLength(w, length-minValue)
	padded := make([]byte, length)
	copy(padded, stream)
	w.Write(padded)
}

// ReadChoice reads a CHOICE index byte.
func ReadChoice(r *core.Reader) (byte, error) {
	return r.ReadByte()
}

// ExpectChoice reads a byte and checks it equals want.
func ExpectChoice(r *core.Reader, want byte) error {
	got, err := r.ReadByte()
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("per: expected choice 0x%02x, got 0x%02x", want, got)
	}
	return nil
}
