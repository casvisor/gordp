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
	"github.com/casvisor/gordp/core"
)

// Capability set types (MS-RDPBCGR 2.2.1.13.1.1.1).
const (
	capGeneral        = 0x0001
	capBitmap         = 0x0002
	capOrder          = 0x0003
	capBitmapCache    = 0x0004
	capControl        = 0x0005
	capActivation     = 0x0007
	capPointer        = 0x0008
	capShare          = 0x0009
	capColorCache     = 0x000A
	capSound          = 0x000C
	capInput          = 0x000D
	capFont           = 0x000E
	capBrush          = 0x000F
	capGlyphCache     = 0x0010
	capOffscreenCache = 0x0011
	capVirtualChannel = 0x0014
	capMultiFragment  = 0x001A
)

// DemandActive is the part of the Server Demand Active PDU the client needs.
type DemandActive struct {
	ShareID uint32
}

// ParseDemandActive parses a Server Demand Active PDU body (the share control
// body, with the share control header already stripped).
func ParseDemandActive(body []byte) (*DemandActive, error) {
	r := core.NewReader(body)
	shareID, err := r.ReadUint32LE()
	if err != nil {
		return nil, err
	}
	// The rest (source descriptor, server capability sets, session id) is not
	// needed for a bitmap-only client, so we stop at the share id.
	return &DemandActive{ShareID: shareID}, nil
}

// BuildConfirmActive builds the Client Confirm Active PDU with our capability
// sets. We advertise no drawing orders, which makes the server send bitmap
// updates instead of GDI orders, the simplest thing to decode.
func BuildConfirmActive(pduSource uint16, shareID uint32, width, height uint16) []byte {
	caps := buildCapabilitySets(width, height)

	body := core.NewWriter()
	body.WriteUint32LE(shareID)
	body.WriteUint16LE(0x03EA) // originatorID (RNS_UD_SC)
	source := []byte("gordp\x00")
	body.WriteUint16LE(uint16(len(source)))      // lengthSourceDescriptor
	body.WriteUint16LE(uint16(caps.numberLen())) // lengthCombinedCapabilities
	body.Write(source)
	body.WriteUint16LE(uint16(caps.count)) // numberCapabilities
	body.WriteUint16LE(0)                  // pad2octets
	body.Write(caps.data)

	w := core.NewWriter()
	writeShareControl(w, PdutypeConfirmActive, pduSource, body.Bytes())
	return w.Bytes()
}

type capBuffer struct {
	data  []byte
	count int
}

// numberLen is the length of numberCapabilities + pad2octets + the sets, which
// is what lengthCombinedCapabilities counts.
func (c *capBuffer) numberLen() int {
	return 4 + len(c.data)
}

func (c *capBuffer) add(capType uint16, body []byte) {
	w := core.NewWriter()
	w.WriteUint16LE(capType)
	w.WriteUint16LE(uint16(len(body) + 4))
	w.Write(body)
	c.data = append(c.data, w.Bytes()...)
	c.count++
}

func buildCapabilitySets(width, height uint16) *capBuffer {
	c := &capBuffer{}
	c.add(capGeneral, generalCap())
	c.add(capBitmap, bitmapCap(width, height))
	c.add(capOrder, orderCap())
	c.add(capBitmapCache, make([]byte, 36)) // rev1, no cache entries
	c.add(capPointer, pointerCap())
	c.add(capInput, inputCap())
	c.add(capBrush, u32le(0)) // BRUSH_DEFAULT
	c.add(capGlyphCache, glyphCacheCap())
	c.add(capOffscreenCache, make([]byte, 8)) // disabled
	c.add(capVirtualChannel, make([]byte, 4)) // VCCAPS_NO_COMPR
	c.add(capSound, make([]byte, 4))
	c.add(capControl, controlCap())
	c.add(capActivation, make([]byte, 8))
	c.add(capFont, fontCap())
	c.add(capColorCache, colorCacheCap())
	c.add(capShare, make([]byte, 4))
	c.add(capMultiFragment, u32le(0))
	return c
}

func generalCap() []byte {
	w := core.NewWriter()
	w.WriteUint16LE(1)      // osMajorType: WINDOWS
	w.WriteUint16LE(3)      // osMinorType: WINDOWS NT
	w.WriteUint16LE(0x0200) // protocolVersion
	w.WriteUint16LE(0)      // pad2octetsA
	w.WriteUint16LE(0)      // generalCompressionTypes
	w.WriteUint16LE(0x0401) // extraFlags: FASTPATH_OUTPUT_SUPPORTED | NO_BITMAP_COMPRESSION_HDR
	w.WriteUint16LE(0)      // updateCapabilityFlag
	w.WriteUint16LE(0)      // remoteUnshareFlag
	w.WriteUint16LE(0)      // generalCompressionLevel
	w.PutByte(0)            // refreshRectSupport
	w.PutByte(0)            // suppressOutputSupport
	return w.Bytes()
}

func bitmapCap(width, height uint16) []byte {
	w := core.NewWriter()
	w.WriteUint16LE(16) // preferredBitsPerPixel
	w.WriteUint16LE(1)  // receive1BitPerPixel
	w.WriteUint16LE(1)  // receive4BitsPerPixel
	w.WriteUint16LE(1)  // receive8BitsPerPixel
	w.WriteUint16LE(width)
	w.WriteUint16LE(height)
	w.WriteUint16LE(0) // pad2octets
	w.WriteUint16LE(1) // desktopResizeFlag
	w.WriteUint16LE(1) // bitmapCompressionFlag
	w.PutByte(0)       // highColorFlags
	w.PutByte(0)       // drawingFlags
	w.WriteUint16LE(1) // multipleRectangleSupport
	w.WriteUint16LE(0) // pad2octetsB
	return w.Bytes()
}

func orderCap() []byte {
	w := core.NewWriter()
	w.Write(make([]byte, 16)) // terminalDescriptor
	w.WriteUint32LE(0)        // pad4octetsA
	w.WriteUint16LE(1)        // desktopSaveXGranularity
	w.WriteUint16LE(20)       // desktopSaveYGranularity
	w.WriteUint16LE(0)        // pad2octetsA
	w.WriteUint16LE(1)        // maximumOrderLevel
	w.WriteUint16LE(0)        // numberFonts
	w.WriteUint16LE(0x000A)   // orderFlags: NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
	w.Write(make([]byte, 32)) // orderSupport: none, so the server sends bitmaps
	w.WriteUint16LE(0)        // textFlags
	w.WriteUint16LE(0)        // orderSupportExFlags
	w.WriteUint32LE(0)        // pad4octetsB
	w.WriteUint32LE(0x38400)  // desktopSaveSize
	w.WriteUint16LE(0)        // pad2octetsC
	w.WriteUint16LE(0)        // pad2octetsD
	w.WriteUint16LE(0)        // textANSICodePage
	w.WriteUint16LE(0)        // pad2octetsE
	return w.Bytes()
}

func pointerCap() []byte {
	w := core.NewWriter()
	w.WriteUint16LE(1)  // colorPointerFlag
	w.WriteUint16LE(20) // colorPointerCacheSize
	w.WriteUint16LE(21) // pointerCacheSize
	return w.Bytes()
}

func inputCap() []byte {
	w := core.NewWriter()
	w.WriteUint16LE(0x0035)   // inputFlags: SCANCODES | MOUSEX | UNICODE | FASTPATH_INPUT2
	w.WriteUint16LE(0)        // pad2octetsA
	w.WriteUint32LE(0x409)    // keyboardLayout: US
	w.WriteUint32LE(4)        // keyboardType
	w.WriteUint32LE(0)        // keyboardSubType
	w.WriteUint32LE(12)       // keyboardFunctionKey
	w.Write(make([]byte, 64)) // imeFileName
	return w.Bytes()
}

func glyphCacheCap() []byte {
	// 10 cache definitions (4 bytes each) + frag cache (4) + support level (2)
	// + pad (2). Zeroed = GLYPH_SUPPORT_NONE.
	return make([]byte, 48)
}

func controlCap() []byte {
	w := core.NewWriter()
	w.WriteUint16LE(0) // controlFlags
	w.WriteUint16LE(0) // remoteDetachFlag
	w.WriteUint16LE(2) // controlInterest: CONTROLPRIORITY_NEVER
	w.WriteUint16LE(2) // detachInterest
	return w.Bytes()
}

func fontCap() []byte {
	w := core.NewWriter()
	w.WriteUint16LE(0x0001) // fontSupportFlags: FONTSUPPORT_FONTLIST
	w.WriteUint16LE(0)      // pad2octets
	return w.Bytes()
}

func colorCacheCap() []byte {
	w := core.NewWriter()
	w.WriteUint16LE(6) // colorTableCacheSize
	w.WriteUint16LE(0) // pad2octets
	return w.Bytes()
}

func u32le(v uint32) []byte {
	w := core.NewWriter()
	w.WriteUint32LE(v)
	return w.Bytes()
}
