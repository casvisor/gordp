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

import "github.com/casvisor/gordp/core"

// Control PDU actions (MS-RDPBCGR 2.2.1.15.1).
const (
	ctrlActionRequestControl = 0x0001
	ctrlActionGrantedControl = 0x0002
	ctrlActionCooperate      = 0x0004
)

// BuildSynchronize builds the Client Synchronize PDU.
func BuildSynchronize(pduSource uint16, shareID uint32, targetUser uint16) []byte {
	body := core.NewWriter()
	body.WriteUint16LE(1) // messageType: SYNCMSGTYPE_SYNC
	body.WriteUint16LE(targetUser)
	w := core.NewWriter()
	writeShareData(w, pduSource, shareID, Pdutype2Synchronize, body.Bytes())
	return w.Bytes()
}

// BuildControlCooperate builds the Client Control PDU (Cooperate).
func BuildControlCooperate(pduSource uint16, shareID uint32) []byte {
	return buildControl(pduSource, shareID, ctrlActionCooperate)
}

// BuildControlRequest builds the Client Control PDU (Request Control).
func BuildControlRequest(pduSource uint16, shareID uint32) []byte {
	return buildControl(pduSource, shareID, ctrlActionRequestControl)
}

func buildControl(pduSource uint16, shareID uint32, action uint16) []byte {
	body := core.NewWriter()
	body.WriteUint16LE(action)
	body.WriteUint16LE(0) // grantId
	body.WriteUint32LE(0) // controlId
	w := core.NewWriter()
	writeShareData(w, pduSource, shareID, Pdutype2Control, body.Bytes())
	return w.Bytes()
}

// BuildFontList builds the Client Font List PDU, the last step of finalization.
func BuildFontList(pduSource uint16, shareID uint32) []byte {
	body := core.NewWriter()
	body.WriteUint16LE(0)      // numberFonts
	body.WriteUint16LE(0)      // totalNumFonts
	body.WriteUint16LE(0x0003) // listFlags: FONTLIST_FIRST | FONTLIST_LAST
	body.WriteUint16LE(0x0032) // entrySize
	w := core.NewWriter()
	writeShareData(w, pduSource, shareID, Pdutype2FontList, body.Bytes())
	return w.Bytes()
}
