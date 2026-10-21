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

// Package mcs runs the T.125 MCS layer on top of X.224: it carries the GCC
// conference create exchange (which carries each side's RDP settings), then
// erects the domain, attaches a user and joins the channels. After that it
// wraps every session PDU in an MCS Send Data Request.
package mcs

import (
	"fmt"

	"github.com/casvisor/gordp/core"
	"github.com/casvisor/gordp/core/per"
	"github.com/casvisor/gordp/tpkt"
	"github.com/casvisor/gordp/x224"
)

// MCS domain PDU types (the high 6 bits of the first byte).
const (
	pduErectDomainRequest = 1
	pduAttachUserRequest  = 10
	pduAttachUserConfirm  = 11
	pduChannelJoinRequest = 14
	pduChannelJoinConfirm = 15
	pduSendDataRequest    = 25
	pduSendDataIndication = 26
	pduDisconnectProvider = 8
)

const userChannelBase = 1001

// Layer drives the MCS connect sequence and then carries session PDUs.
type Layer struct {
	x224 *x224.Layer

	// UserID is the channel assigned to this user by Attach User Confirm.
	UserID uint16
	// Server holds the channel IDs from the GCC response.
	Server *ServerData
}

func New(x *x224.Layer) *Layer {
	return &Layer{x224: x}
}

// Connect runs the full MCS connect sequence: Connect-Initial/Response, erect
// domain, attach user and channel joins.
func (l *Layer) Connect(cfg ClientConfig) error {
	if err := l.sendConnectInitial(cfg); err != nil {
		return err
	}
	if err := l.readConnectResponse(); err != nil {
		return err
	}
	if err := l.x224.Send(buildErectDomainRequest()); err != nil {
		return err
	}
	if err := l.x224.Send(buildAttachUserRequest()); err != nil {
		return err
	}
	if err := l.readAttachUserConfirm(); err != nil {
		return err
	}
	return l.joinChannels()
}

func (l *Layer) sendConnectInitial(cfg ClientConfig) error {
	if cfg.DesktopWidth == 0 {
		cfg.DesktopWidth = 1024
	}
	if cfg.DesktopHeight == 0 {
		cfg.DesktopHeight = 768
	}
	if cfg.Name == "" {
		cfg.Name = "gordp"
	}
	gcc := buildConferenceCreateRequest(buildClientData(cfg))
	return l.x224.Send(buildConnectInitial(gcc))
}

func (l *Layer) readConnectResponse() error {
	pdu, err := l.x224.Receive()
	if err != nil {
		return err
	}
	server, err := parseConnectResponse(pdu.Payload)
	if err != nil {
		return err
	}
	l.Server = server
	return nil
}

func (l *Layer) readAttachUserConfirm() error {
	pdu, err := l.x224.Receive()
	if err != nil {
		return err
	}
	r := core.NewReader(pdu.Payload)
	header, err := r.ReadByte()
	if err != nil {
		return err
	}
	if header>>2 != pduAttachUserConfirm {
		return fmt.Errorf("mcs: expected attach user confirm, got type %d", header>>2)
	}
	result, err := r.ReadByte()
	if err != nil {
		return err
	}
	if result != 0 {
		return fmt.Errorf("mcs: attach user rejected, result %d", result)
	}
	userID, err := per.ReadInteger16(r, userChannelBase)
	if err != nil {
		return err
	}
	l.UserID = userID
	return nil
}

func (l *Layer) joinChannels() error {
	channels := []uint16{l.UserID, l.Server.IOChannelID}
	channels = append(channels, l.Server.ChannelIDs...)
	for _, channel := range channels {
		if err := l.x224.Send(buildChannelJoinRequest(l.UserID, channel)); err != nil {
			return err
		}
		if err := l.readChannelJoinConfirm(channel); err != nil {
			return err
		}
	}
	return nil
}

func (l *Layer) readChannelJoinConfirm(expected uint16) error {
	pdu, err := l.x224.Receive()
	if err != nil {
		return err
	}
	r := core.NewReader(pdu.Payload)
	header, err := r.ReadByte()
	if err != nil {
		return err
	}
	if header>>2 != pduChannelJoinConfirm {
		return fmt.Errorf("mcs: expected channel join confirm, got type %d", header>>2)
	}
	result, err := r.ReadByte()
	if err != nil {
		return err
	}
	if result != 0 {
		return fmt.Errorf("mcs: channel %d join rejected, result %d", expected, result)
	}
	return nil
}

// Send wraps payload in an MCS Send Data Request on the given channel.
func (l *Layer) Send(channelID uint16, payload []byte) error {
	w := core.NewWriter()
	w.PutByte(pduSendDataRequest << 2)
	per.WriteInteger16(w, l.UserID, userChannelBase)
	per.WriteInteger16(w, channelID, 0)
	w.PutByte(0x70) // data priority high, segmentation begin+end
	per.WriteLength(w, len(payload))
	w.Write(payload)
	return l.x224.Send(w.Bytes())
}

// Receive reads one MCS Send Data Indication and returns the channel and
// payload. Fast-path PDUs are returned as-is for the caller to handle.
func (l *Layer) Receive() (channelID uint16, pdu *tpkt.PDU, err error) {
	pdu, err = l.x224.Receive()
	if err != nil {
		return 0, nil, err
	}
	if pdu.FastPath {
		return 0, pdu, nil
	}
	r := core.NewReader(pdu.Payload)
	header, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	switch header >> 2 {
	case pduSendDataIndication:
		if _, err := per.ReadInteger16(r, userChannelBase); err != nil { // initiator
			return 0, nil, err
		}
		channelID, err = per.ReadInteger16(r, 0)
		if err != nil {
			return 0, nil, err
		}
		if _, err := r.ReadByte(); err != nil { // data priority + segmentation
			return 0, nil, err
		}
		length, err := per.ReadLength(r)
		if err != nil {
			return 0, nil, err
		}
		body, err := r.ReadBytes(length)
		if err != nil {
			return 0, nil, err
		}
		pdu.Payload = body
		return channelID, pdu, nil
	case pduDisconnectProvider:
		return 0, nil, fmt.Errorf("mcs: server disconnected (disconnect-provider-ultimatum)")
	default:
		return 0, nil, fmt.Errorf("mcs: unexpected pdu type %d", header>>2)
	}
}

func buildErectDomainRequest() []byte {
	w := core.NewWriter()
	w.PutByte(pduErectDomainRequest << 2)
	per.WriteInteger(w, 0) // subHeight
	per.WriteInteger(w, 0) // subInterval
	return w.Bytes()
}

func buildAttachUserRequest() []byte {
	return []byte{pduAttachUserRequest << 2}
}

func buildChannelJoinRequest(userID, channelID uint16) []byte {
	w := core.NewWriter()
	w.PutByte(pduChannelJoinRequest << 2)
	per.WriteInteger16(w, userID, userChannelBase)
	per.WriteInteger16(w, channelID, 0)
	return w.Bytes()
}
