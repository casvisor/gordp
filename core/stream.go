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

// Package core holds the low-level helpers shared by the protocol layers:
// little-endian readers and writers over an in-memory buffer. RDP is almost
// entirely little-endian, so these keep the protocol code short.
package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Writer builds a little-endian byte buffer.
type Writer struct {
	buf bytes.Buffer
}

func NewWriter() *Writer {
	return &Writer{}
}

func (w *Writer) Bytes() []byte {
	return w.buf.Bytes()
}

func (w *Writer) Len() int {
	return w.buf.Len()
}

func (w *Writer) PutByte(v byte) {
	w.buf.WriteByte(v)
}

func (w *Writer) Write(p []byte) {
	w.buf.Write(p)
}

func (w *Writer) WriteUint16LE(v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	w.buf.Write(b[:])
}

func (w *Writer) WriteUint16BE(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.buf.Write(b[:])
}

func (w *Writer) WriteUint32LE(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.buf.Write(b[:])
}

func (w *Writer) WriteUint32BE(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.buf.Write(b[:])
}

// Reader consumes a little-endian byte buffer.
type Reader struct {
	data []byte
	pos  int
}

func NewReader(data []byte) *Reader {
	return &Reader{data: data}
}

func (r *Reader) Remaining() int {
	return len(r.data) - r.pos
}

func (r *Reader) ReadByte() (byte, error) {
	if r.Remaining() < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.Remaining() < n {
		return nil, fmt.Errorf("core: want %d bytes, have %d", n, r.Remaining())
	}
	v := r.data[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

func (r *Reader) ReadUint16LE() (uint16, error) {
	b, err := r.ReadBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *Reader) ReadUint16BE() (uint16, error) {
	b, err := r.ReadBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *Reader) ReadUint32LE() (uint32, error) {
	b, err := r.ReadBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// Skip advances the read position by n bytes.
func (r *Reader) Skip(n int) error {
	if r.Remaining() < n {
		return io.ErrUnexpectedEOF
	}
	r.pos += n
	return nil
}
