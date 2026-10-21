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

// Package pdu builds and parses the RDP session PDUs that ride on the MCS I/O
// channel: the client info (login) packet, the licensing exchange, and later
// the capability and graphics PDUs.
package pdu

import "github.com/casvisor/gordp/core"

// Basic security header flags (MS-RDPBCGR 2.2.8.1.1.2.1).
const (
	SecExchangePkt   uint16 = 0x0001
	SecEncrypt       uint16 = 0x0008
	SecInfoPkt       uint16 = 0x0040
	SecLicensePkt    uint16 = 0x0080
	SecRedirectonPkt uint16 = 0x0400
)

// writeSecurityHeader writes the basic security header. Under TLS/CredSSP there
// is no RDP-level encryption, so only the flags matter.
func writeSecurityHeader(w *core.Writer, flags uint16) {
	w.WriteUint16LE(flags)
	w.WriteUint16LE(0) // flagsHi
}

// readSecurityHeader reads the basic security header and returns its flags.
func readSecurityHeader(r *core.Reader) (uint16, error) {
	flags, err := r.ReadUint16LE()
	if err != nil {
		return 0, err
	}
	if _, err := r.ReadUint16LE(); err != nil { // flagsHi
		return 0, err
	}
	return flags, nil
}
