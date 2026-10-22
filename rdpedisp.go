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
	"fmt"

	"github.com/casvisor/gordp/core"
	"github.com/casvisor/gordp/mcs"
)

// MS-RDPEDISP (Display Control Virtual Channel Extension) lets the client ask
// the server to change the desktop resolution at runtime. It rides the
// "Microsoft::Windows::RDS::DisplayControl" dynamic channel, which the server
// opens over drdynvc.

// DISPLAYCONTROL_PDU_TYPE values (MS-RDPEDISP 2.2.2.1).
const (
	dispCtlPduMonitorLayout = 0x00000002 // client -> server
	dispCtlPduCaps          = 0x00000005 // server -> client

	dispCtlMonitorPrimary = 0x00000001 // DISPLAYCONTROL_MONITOR_PRIMARY
)

// handleDisplayControl processes a PDU from the DisplayControl dynamic channel.
// The only server PDU is the capabilities PDU, which bounds the resolutions the
// client may request; resizing itself is driven by Resize.
func (c *Client) handleDisplayControl(data []byte) {
	// The server's capabilities PDU is advisory for us; we clamp requests in
	// Resize. Nothing to process here for now.
	_ = data
}

// Resize asks the server to change the desktop to width x height. It requires
// the DisplayControl dynamic channel the server opens over drdynvc; the server
// answers with a deactivate-reactivate sequence that PumpUpdates applies to the
// framebuffer. Width is rounded down to an even number and both dimensions are
// clamped to the protocol's 200..8192 range.
func (c *Client) Resize(width, height uint16) error {
	if c.vc == nil || !c.dvcChannelOpen(displayControlChannelName) {
		return fmt.Errorf("gordp: display control channel not available")
	}
	width &^= 1 // width must be even
	scale := c.scale
	if scale == 0 {
		scale = 100
	}
	width = clampDim(width)
	height = clampDim(height)

	w := core.NewWriter()
	w.WriteUint32LE(dispCtlPduMonitorLayout) // Type
	w.WriteUint32LE(8 + 8 + 40)              // Length: header + layout header + one monitor
	w.WriteUint32LE(40)                      // MonitorLayoutSize
	w.WriteUint32LE(1)                       // NumMonitors
	// DISPLAYCONTROL_MONITOR_LAYOUT (40 bytes).
	w.WriteUint32LE(dispCtlMonitorPrimary)        // Flags
	w.WriteUint32LE(0)                            // Left
	w.WriteUint32LE(0)                            // Top
	w.WriteUint32LE(uint32(width))                // Width
	w.WriteUint32LE(uint32(height))               // Height
	w.WriteUint32LE(0)                            // PhysicalWidth (ignored when 0)
	w.WriteUint32LE(0)                            // PhysicalHeight
	w.WriteUint32LE(0)                            // Orientation: landscape
	w.WriteUint32LE(scale)                        // DesktopScaleFactor
	w.WriteUint32LE(mcs.DeviceScaleFactor(scale)) // DeviceScaleFactor

	c.pendingWidth = width
	c.pendingHeight = height
	if err := c.dvcSend(displayControlChannelName, w.Bytes()); err != nil {
		return fmt.Errorf("gordp: send monitor layout: %w", err)
	}
	return nil
}

func clampDim(v uint16) uint16 {
	if v < 200 {
		return 200
	}
	if v > 8192 {
		return 8192
	}
	return v
}
