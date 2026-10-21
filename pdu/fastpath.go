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

// Fast-path update codes (MS-RDPBCGR 2.2.9.1.2.1).
const (
	FastPathUpdateOrders      = 0x0
	FastPathUpdateBitmap      = 0x1
	FastPathUpdatePalette     = 0x2
	FastPathUpdateSynchronize = 0x3
	FastPathUpdateSurfCmds    = 0x4
	FastPathUpdatePointerNull = 0x5
	FastPathUpdatePointerDef  = 0x6
	FastPathUpdatePointerPos  = 0x8
	FastPathUpdateColor       = 0x9
	FastPathUpdateCached      = 0xA
	FastPathUpdatePointer     = 0xB
)

// Fragmentation (MS-RDPBCGR 2.2.9.1.2.1).
const (
	fragSingle = 0x0
	fragLast   = 0x1
	fragFirst  = 0x2
	fragNext   = 0x3

	fastpathCompressionUsed = 0x2 // FASTPATH_OUTPUT_COMPRESSION_USED
)

// FastPathUpdate is one reassembled fast-path update.
type FastPathUpdate struct {
	Code byte
	Data []byte
}

// FastPathReassembler joins fragmented fast-path updates across PDUs.
type FastPathReassembler struct {
	code byte
	buf  []byte
}

// Parse splits one fast-path PDU payload into complete updates, holding on to
// any fragment that spans PDUs.
func (fp *FastPathReassembler) Parse(payload []byte) ([]FastPathUpdate, error) {
	r := core.NewReader(payload)
	var updates []FastPathUpdate

	for r.Remaining() > 0 {
		header, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		code := header & 0x0F
		fragmentation := (header >> 4) & 0x03
		compression := (header >> 6) & 0x03

		if compression&fastpathCompressionUsed != 0 {
			if _, err := r.ReadByte(); err != nil { // compressionFlags
				return nil, err
			}
		}
		size, err := r.ReadUint16LE()
		if err != nil {
			return nil, err
		}
		data, err := r.ReadBytes(int(size))
		if err != nil {
			return nil, err
		}

		switch fragmentation {
		case fragSingle:
			updates = append(updates, FastPathUpdate{Code: code, Data: data})
		case fragFirst:
			fp.code = code
			fp.buf = append([]byte{}, data...)
		case fragNext:
			fp.buf = append(fp.buf, data...)
		case fragLast:
			fp.buf = append(fp.buf, data...)
			updates = append(updates, FastPathUpdate{Code: fp.code, Data: fp.buf})
			fp.buf = nil
		default:
			return nil, fmt.Errorf("pdu: bad fast-path fragmentation %d", fragmentation)
		}
	}
	return updates, nil
}
