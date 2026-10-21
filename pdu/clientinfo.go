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
	"unicode/utf16"

	"github.com/casvisor/gordp/core"
)

// TS_INFO_PACKET flags (MS-RDPBCGR 2.2.1.11.1.1).
const (
	infoMouse             = 0x00000001
	infoDisableCtrlAltDel = 0x00000002
	infoUnicode           = 0x00000010
	infoMaximizeShell     = 0x00000020
	infoLogonNotify       = 0x00000040
	infoEnableWindowsKey  = 0x00000100
	infoLogonErrors       = 0x01000000

	afInet = 0x0002
)

// LoginInfo is the identity and auto-logon settings sent in the Client Info PDU.
type LoginInfo struct {
	Domain   string
	Username string
	Password string
}

// BuildClientInfo builds the Client Info PDU (login). The password is included
// so the host logs the user straight in; it travels inside the TLS channel. It
// is the gateway, not the browser, that holds it.
func BuildClientInfo(info LoginInfo) []byte {
	w := core.NewWriter()
	writeSecurityHeader(w, SecInfoPkt)

	flags := uint32(infoMouse | infoDisableCtrlAltDel | infoUnicode |
		infoMaximizeShell | infoLogonNotify | infoEnableWindowsKey | infoLogonErrors)

	domain := utf16z(info.Domain)
	user := utf16z(info.Username)
	password := utf16z(info.Password)
	shell := utf16z("")
	workingDir := utf16z("")

	w.WriteUint32LE(0) // CodePage
	w.WriteUint32LE(flags)
	// Field lengths exclude the trailing null (2 bytes).
	w.WriteUint16LE(uint16(len(domain) - 2))
	w.WriteUint16LE(uint16(len(user) - 2))
	w.WriteUint16LE(uint16(len(password) - 2))
	w.WriteUint16LE(uint16(len(shell) - 2))
	w.WriteUint16LE(uint16(len(workingDir) - 2))
	w.Write(domain)
	w.Write(user)
	w.Write(password)
	w.Write(shell)
	w.Write(workingDir)

	writeExtendedInfo(w)
	return w.Bytes()
}

// writeExtendedInfo writes TS_EXTENDED_INFO_PACKET (RDP 5+).
func writeExtendedInfo(w *core.Writer) {
	w.WriteUint16LE(afInet)
	clientAddress := utf16z("")
	w.WriteUint16LE(uint16(len(clientAddress)))
	w.Write(clientAddress)
	clientDir := utf16z("")
	w.WriteUint16LE(uint16(len(clientDir)))
	w.Write(clientDir)
	// clientTimeZone (TS_TIME_ZONE_INFORMATION) is 172 bytes; zeros = UTC.
	w.Write(make([]byte, 172))
	w.WriteUint32LE(0) // clientSessionId
	w.WriteUint32LE(0) // performanceFlags
	w.WriteUint16LE(0) // cbAutoReconnectCookie
}

// utf16z encodes s as little-endian UTF-16 with a trailing null unit.
func utf16z(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2+2)
	for i, u := range units {
		out[i*2] = byte(u)
		out[i*2+1] = byte(u >> 8)
	}
	return out
}
