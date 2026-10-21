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

// Licensing message types (MS-RDPELE 2.2.2).
const (
	licenseRequest    = 0x01
	platformChallenge = 0x02
	newLicense        = 0x03
	upgradeLicense    = 0x04
	licenseErrorAlert = 0xFF
)

// Licensing error codes (MS-RDPELE 2.2.2.4).
const (
	errValidClient     = 0x00000007 // STATUS_VALID_CLIENT: no license needed, proceed
	errNoLicenseServer = 0x00000006
	errNoLicense       = 0x00000005
	errInvalidClient   = 0x00000008
)

// State transitions (MS-RDPELE 2.2.2.4).
const stNoTransition = 0x00000002

// ParseLicensing reads a licensing PDU. It returns done=true when the server
// says the session may proceed (the common "valid client" case for admin
// connections). A real licensing negotiation (the server asks for a license)
// is not implemented yet and returns an error naming the message type.
func ParseLicensing(payload []byte) (done bool, err error) {
	r := core.NewReader(payload)
	if _, err := readSecurityHeader(r); err != nil {
		return false, err
	}

	msgType, err := r.ReadByte()
	if err != nil {
		return false, err
	}
	if _, err := r.ReadByte(); err != nil { // flags
		return false, err
	}
	if _, err := r.ReadUint16LE(); err != nil { // wMsgSize
		return false, err
	}

	switch msgType {
	case licenseErrorAlert:
		code, err := r.ReadUint32LE()
		if err != nil {
			return false, err
		}
		if _, err := r.ReadUint32LE(); err != nil { // dwStateTransition
			return false, err
		}
		if code == errValidClient {
			return true, nil
		}
		return false, fmt.Errorf("license: server error 0x%08x (%s)", code, licenseError(code))
	case licenseRequest, platformChallenge, newLicense, upgradeLicense:
		return false, fmt.Errorf("license: server requires a licensing negotiation (message type 0x%02x), which is not implemented yet", msgType)
	default:
		return false, fmt.Errorf("license: unexpected message type 0x%02x", msgType)
	}
}

func licenseError(code uint32) string {
	switch code {
	case errNoLicenseServer:
		return "ERR_NO_LICENSE_SERVER"
	case errNoLicense:
		return "ERR_NO_LICENSE"
	case errInvalidClient:
		return "ERR_INVALID_CLIENT"
	default:
		return "unknown"
	}
}
