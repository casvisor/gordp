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

package gordp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Session recording format (little-endian throughout):
//
//	header:
//	  magic     8 bytes  "GORDPRC1"
//	  version   uint16
//	  width     uint16   desktop width  in pixels
//	  height    uint16   desktop height in pixels
//	  startUnix int64    recording start, Unix nanoseconds
//	record (repeated until EOF):
//	  offsetMs  uint32   milliseconds since the recording started
//	  code      uint8    fast-path update code (pdu.FastPathUpdate*)
//	  length    uint32   length of data
//	  data      length bytes  the raw fast-path update body
//
// The stream of code==pdu.FastPathUpdateBitmap records is enough to rebuild the
// screen: each data is a TS_UPDATE_BITMAP body, directly consumable by
// bitmap.ParseBitmapUpdate. Other codes (pointer updates and so on) are recorded
// verbatim and may be ignored on replay.
const (
	recordMagic   = "GORDPRC1"
	recordVersion = 1
)

// Recorder appends fast-path updates to a recording file. Its Record method has
// the signature of Client.OnFastPath, so it is wired in as:
//
//	rec, _ := gordp.NewRecorder(path, w, h)
//	client.OnFastPath = rec.Record
//	// ... client.PumpUpdates(...) ...
//	rec.Close()
//
// Record is called from the PumpUpdates read goroutine; it is guarded by a mutex
// so a Recorder is safe to close from another goroutine.
type Recorder struct {
	mu     sync.Mutex
	f      *os.File
	w      *bufio.Writer
	start  time.Time
	err    error
	closed bool
}

// NewRecorder creates path and writes the recording header for a width x height
// desktop. The recording start time is the moment this returns.
func NewRecorder(path string, width, height int) (*Recorder, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("gordp: create recording %s: %w", path, err)
	}
	w := bufio.NewWriter(f)
	start := time.Now()

	var hdr [8 + 2 + 2 + 2 + 8]byte
	copy(hdr[0:8], recordMagic)
	binary.LittleEndian.PutUint16(hdr[8:10], recordVersion)
	binary.LittleEndian.PutUint16(hdr[10:12], uint16(width))
	binary.LittleEndian.PutUint16(hdr[12:14], uint16(height))
	binary.LittleEndian.PutUint64(hdr[14:22], uint64(start.UnixNano()))
	if _, err := w.Write(hdr[:]); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("gordp: write recording header: %w", err)
	}

	return &Recorder{f: f, w: w, start: start}, nil
}

// Record appends one fast-path update. It never panics: a write error is stored
// and returned by Close. Records after an error or after Close are dropped.
func (r *Recorder) Record(code byte, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	offset := time.Since(r.start).Milliseconds()
	if offset < 0 {
		offset = 0
	}
	var rec [4 + 1 + 4]byte
	binary.LittleEndian.PutUint32(rec[0:4], uint32(offset))
	rec[4] = code
	binary.LittleEndian.PutUint32(rec[5:9], uint32(len(data)))
	if _, err := r.w.Write(rec[:]); err != nil {
		r.err = err
		return
	}
	if _, err := r.w.Write(data); err != nil {
		r.err = err
	}
}

// Close flushes and closes the recording file, returning the first write error
// encountered, if any.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.err
	}
	r.closed = true
	if flushErr := r.w.Flush(); flushErr != nil && r.err == nil {
		r.err = flushErr
	}
	if closeErr := r.f.Close(); closeErr != nil && r.err == nil {
		r.err = closeErr
	}
	return r.err
}

// RecordHeader holds the metadata at the start of a recording.
type RecordHeader struct {
	Version int
	Width   int
	Height  int
	Start   time.Time
}

// RecordEvent is one fast-path update read back from a recording.
type RecordEvent struct {
	OffsetMs uint32 // milliseconds since the recording started
	Code     byte   // fast-path update code (pdu.FastPathUpdate*)
	Data     []byte
}

// RecordReader reads a recording produced by Recorder.
type RecordReader struct {
	Header RecordHeader

	f *os.File
	r *bufio.Reader
}

// OpenRecording opens a recording file and reads its header.
func OpenRecording(path string) (*RecordReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gordp: open recording %s: %w", path, err)
	}
	br := bufio.NewReader(f)

	var hdr [8 + 2 + 2 + 2 + 8]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("gordp: read recording header: %w", err)
	}
	if string(hdr[0:8]) != recordMagic {
		_ = f.Close()
		return nil, fmt.Errorf("gordp: %s is not a gordp recording", path)
	}
	rr := &RecordReader{
		f: f,
		r: br,
		Header: RecordHeader{
			Version: int(binary.LittleEndian.Uint16(hdr[8:10])),
			Width:   int(binary.LittleEndian.Uint16(hdr[10:12])),
			Height:  int(binary.LittleEndian.Uint16(hdr[12:14])),
			Start:   time.Unix(0, int64(binary.LittleEndian.Uint64(hdr[14:22]))),
		},
	}
	return rr, nil
}

// Next reads the next event, returning io.EOF at the end of the recording.
func (rr *RecordReader) Next() (*RecordEvent, error) {
	var rec [4 + 1 + 4]byte
	if _, err := io.ReadFull(rr.r, rec[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	length := binary.LittleEndian.Uint32(rec[5:9])
	data := make([]byte, length)
	if _, err := io.ReadFull(rr.r, data); err != nil {
		return nil, fmt.Errorf("gordp: truncated recording: %w", err)
	}
	return &RecordEvent{
		OffsetMs: binary.LittleEndian.Uint32(rec[0:4]),
		Code:     rec[4],
		Data:     data,
	}, nil
}

// Close closes the recording file.
func (rr *RecordReader) Close() error {
	return rr.f.Close()
}
