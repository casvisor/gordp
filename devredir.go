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
	"github.com/casvisor/gordp/rdpdr"
)

// rdpdrClientName is the computer name reported on the device redirection
// channel; Windows shows a drive as "<name> on <client name>".
const rdpdrClientName = "gordp"

// Drive is a local directory redirected into the remote session, where it
// appears as \tsclient\<Name>. Name should be short ASCII (at most 7
// characters is safest).
type Drive struct {
	Name string
	Root string
	// ReadOnly stops the remote session from changing the directory.
	ReadOnly bool
	// WriteOnly stops the remote session from reading files it did not write.
	WriteOnly bool
}

// WithDrive redirects a local directory into the remote session. It can be
// given more than once.
func WithDrive(d Drive) Option {
	return func(c *Client) { c.driveConfigs = append(c.driveConfigs, d) }
}

// initDrives opens the configured drives before connecting.
func (c *Client) initDrives() error {
	c.drives = nil
	for _, cfg := range c.driveConfigs {
		d, err := rdpdr.NewDrive(cfg.Name, cfg.Root)
		if err != nil {
			return err
		}
		d.ReadOnly = cfg.ReadOnly
		d.WriteOnly = cfg.WriteOnly
		name := cfg.Name
		d.OnEvent = func(ev rdpdr.Event) {
			if c.OnDriveEvent != nil {
				c.OnDriveEvent(name, ev)
			}
		}
		c.drives = append(c.drives, d)
	}
	return nil
}

func (c *Client) closeDrives() {
	for _, d := range c.drives {
		d.Close()
	}
}

// handleRdpdr runs the device redirection (MS-RDPEFS) client: the core
// initialization, the drive announcement once the user has logged on, and the
// file system I/O requests on the announced drives.
func (c *Client) handleRdpdr(data []byte) {
	msg, err := rdpdr.Parse(data)
	if err != nil || msg.Component != rdpdr.ComponentCore {
		return
	}
	switch msg.PacketID {
	case rdpdr.PacketServerAnnounce:
		ann, err := rdpdr.ParseServerAnnounce(msg.Body)
		if err != nil {
			return
		}
		c.vc.rdpdrMinor = rdpdr.ClientVersionMinor(ann.VersionMinor)
		_ = c.sendChannel(channelRdpdr, rdpdr.BuildClientIDConfirm(c.vc.rdpdrMinor, ann.ClientID))
		_ = c.sendChannel(channelRdpdr, rdpdr.BuildClientName(rdpdrClientName))
	case rdpdr.PacketServerCapability:
		_ = c.sendChannel(channelRdpdr, rdpdr.BuildClientCapability(c.vc.rdpdrMinor, len(c.drives) > 0))
	case rdpdr.PacketUserLoggedOn:
		if len(c.drives) == 0 {
			return
		}
		names := make([]string, len(c.drives))
		for i, d := range c.drives {
			names[i] = d.Name
		}
		_ = c.sendChannel(channelRdpdr, rdpdr.BuildDeviceListAnnounce(names))
	case rdpdr.PacketDeviceIORequest:
		req, err := rdpdr.ParseIORequest(msg.Body)
		if err != nil {
			return
		}
		// Devices are announced with IDs 1..n in order.
		if req.DeviceID == 0 || int(req.DeviceID) > len(c.drives) {
			return
		}
		_ = c.sendChannel(channelRdpdr, c.drives[req.DeviceID-1].Handle(req))
	}
}
