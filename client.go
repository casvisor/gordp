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

// Package gordp is a pure-Go RDP client, built for the Casvisor gateway to
// connect to Windows hosts without the FreeRDP/guacd C stack. The gateway
// authenticates on the user's behalf and relays the screen to the browser, so
// the password never leaves the gateway.
//
// This is an early build. The connection chain up through CredSSP (NLA) works;
// MCS, capability exchange and the graphics path are being added on top.
package gordp

import (
	"crypto/tls"
	"fmt"
	"image"
	"net"
	"time"

	"github.com/casvisor/gordp/bitmap"
	"github.com/casvisor/gordp/mcs"
	"github.com/casvisor/gordp/nla"
	"github.com/casvisor/gordp/pdu"
	"github.com/casvisor/gordp/tpkt"
	"github.com/casvisor/gordp/x224"
)

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the dial and handshake timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithServerCertFingerprint pins the server's certificate. When set, the TLS
// handshake requires the server certificate to match this SHA-256 fingerprint.
// When empty, the certificate is accepted without verification (RDP hosts
// almost always use self-signed certificates); pin per asset in production.
func WithServerCertFingerprint(sha256hex string) Option {
	return func(c *Client) { c.certFingerprint = sha256hex }
}

// Client is a connection to one RDP host.
type Client struct {
	addr            string
	creds           nla.Credentials
	timeout         time.Duration
	certFingerprint string

	width   uint16
	height  uint16
	active  bool
	shareID uint32

	// pendingWidth/pendingHeight hold a desktop size requested via Resize; the
	// server honors it with a deactivate-reactivate sequence that the pump then
	// applies to width/height and the framebuffer.
	pendingWidth  uint16
	pendingHeight uint16

	conn    *tls.Conn
	tpkt    *tpkt.Layer
	x224    *x224.Layer
	mcs     *mcs.Layer
	vc      *vcState
	fpReasm pdu.FastPathReassembler
	fb      *image.RGBA
	lastBpp int

	// OnBitmap, if set, is called with the decoded rectangles of each bitmap
	// update after they are composited, for streaming changed regions to a
	// viewer.
	OnBitmap func(rects []bitmap.Rect)
	// OnFastPath, if set, is called with the code and raw data of every
	// reassembled fast-path update, for session recording.
	OnFastPath func(code byte, data []byte)
	// OnClipboard, if set, is called with text copied to the remote host's
	// clipboard, for syncing it to the local or browser clipboard.
	OnClipboard func(text string)
}

// WithDesktopSize sets the desktop resolution requested from the server.
func WithDesktopSize(width, height uint16) Option {
	return func(c *Client) {
		c.width = width
		c.height = height
	}
}

// WithSPNEGO carries the NLA/CredSSP authentication inside SPNEGO/Negotiate
// tokens, the way the Windows client does, instead of raw NTLM. Use it for
// servers that require the Negotiate security package; the default raw-NTLM path
// works against standard Windows hosts.
func WithSPNEGO() Option {
	return func(c *Client) {
		c.creds.UseSPNEGO = true
	}
}

// NewClient creates a client for addr ("host:port"). Domain may be empty.
func NewClient(addr, domain, username, password string, opts ...Option) *Client {
	c := &Client{
		addr:    addr,
		creds:   nla.Credentials{Domain: domain, Username: username, Password: password},
		timeout: 15 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Connect runs the handshake up through CredSSP: TCP, the X.224 negotiation
// selecting CredSSP/NLA, the TLS handshake, then the CredSSP exchange that
// authenticates and delegates the password.
func (c *Client) Connect() error {
	tcp, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return fmt.Errorf("gordp: dial %s: %w", c.addr, err)
	}
	_ = tcp.SetDeadline(time.Now().Add(c.timeout))

	c.tpkt = tpkt.New(tcp)
	c.x224 = x224.New(c.tpkt)

	// Offer CredSSP (and plain TLS as a fallback the server may downgrade to).
	if err := c.x224.Connect(x224.ProtocolHybrid | x224.ProtocolSSL); err != nil {
		_ = tcp.Close()
		return err
	}

	tlsConn := tls.Client(tcp, &tls.Config{
		InsecureSkipVerify: true, // RDP hosts use self-signed certs; pinning is checked below.
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = tcp.Close()
		return fmt.Errorf("gordp: tls handshake: %w", err)
	}
	if err := c.verifyCert(tlsConn); err != nil {
		_ = tlsConn.Close()
		return err
	}
	c.conn = tlsConn
	c.tpkt.SetConn(tlsConn)

	if c.x224.SelectedProtocol&x224.ProtocolHybrid != 0 {
		if err := nla.Authenticate(tlsConn, c.creds); err != nil {
			_ = tlsConn.Close()
			return err
		}
	}

	// MCS: GCC conference create, erect domain, attach user, join channels.
	c.vc = &vcState{requested: requestedChannels()}
	c.mcs = mcs.New(c.x224)
	if err := c.mcs.Connect(mcs.ClientConfig{
		DesktopWidth:     c.width,
		DesktopHeight:    c.height,
		SelectedProtocol: c.x224.SelectedProtocol,
		Channels:         c.vc.requested,
	}); err != nil {
		_ = tlsConn.Close()
		return err
	}
	c.initChannels()

	// Client Info PDU (login) on the I/O channel, then the licensing exchange.
	info := pdu.BuildClientInfo(pdu.LoginInfo{
		Domain:   c.creds.Domain,
		Username: c.creds.Username,
		Password: c.creds.Password,
	})
	if err := c.mcs.Send(c.mcs.Server.IOChannelID, info); err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("gordp: send client info: %w", err)
	}
	if err := c.licensing(); err != nil {
		_ = tlsConn.Close()
		return err
	}

	// Capability exchange (demand/confirm active) and finalization.
	if err := c.activate(); err != nil {
		_ = tlsConn.Close()
		return err
	}

	// Clear the handshake deadline; the session read loop manages its own.
	_ = tlsConn.SetDeadline(time.Time{})
	return nil
}

// needSecHeader reports whether share PDUs carry a basic security header, which
// they do only when the server negotiated RDP-level encryption (rare over TLS).
func (c *Client) needSecHeader() bool {
	s := c.mcs.Server
	return s != nil && (s.EncryptionLevel != 0 || s.EncryptionMethod != 0)
}

func (c *Client) stripSecHeader(payload []byte) []byte {
	if c.needSecHeader() && len(payload) >= 4 {
		return payload[4:]
	}
	return payload
}

// sendIO sends a share PDU on the I/O channel, prepending a basic security
// header when the server requires one.
func (c *Client) sendIO(sharePDU []byte) error {
	if c.needSecHeader() {
		sharePDU = append([]byte{0, 0, 0, 0}, sharePDU...)
	}
	return c.mcs.Send(c.mcs.Server.IOChannelID, sharePDU)
}

// activate runs the capability exchange and connection finalization: it waits
// for the server Demand Active, sends Confirm Active and the synchronize /
// control / font-list sequence, and waits for the server Font Map that marks
// the session active.
func (c *Client) activate() error {
	shareID, err := c.waitDemandActive()
	if err != nil {
		return err
	}
	c.shareID = shareID

	width, height := c.width, c.height
	if width == 0 {
		width = 1024
	}
	if height == 0 {
		height = 768
	}
	user := c.mcs.UserID

	if err := c.sendIO(pdu.BuildConfirmActive(user, shareID, width, height)); err != nil {
		return fmt.Errorf("gordp: send confirm active: %w", err)
	}
	for _, p := range [][]byte{
		pdu.BuildSynchronize(user, shareID, c.mcs.Server.IOChannelID),
		pdu.BuildControlCooperate(user, shareID),
		pdu.BuildControlRequest(user, shareID),
		pdu.BuildFontList(user, shareID),
	} {
		if err := c.sendIO(p); err != nil {
			return fmt.Errorf("gordp: send finalization pdu: %w", err)
		}
	}

	return c.waitFontMap()
}

// reactivate re-runs the capability exchange after the server re-sends Demand
// Active, which it does to apply a desktop resize. It adopts the pending size,
// reallocates the framebuffer, and sends Confirm Active and the finalization
// PDUs; the server then repaints at the new size.
func (c *Client) reactivate(body []byte) error {
	da, err := pdu.ParseDemandActive(body)
	if err != nil {
		return err
	}
	c.shareID = da.ShareID
	if c.pendingWidth != 0 {
		c.width = c.pendingWidth
	}
	if c.pendingHeight != 0 {
		c.height = c.pendingHeight
	}
	c.pendingWidth, c.pendingHeight = 0, 0
	c.initFramebuffer()

	width, height := c.width, c.height
	if width == 0 {
		width = 1024
	}
	if height == 0 {
		height = 768
	}
	user := c.mcs.UserID
	if err := c.sendIO(pdu.BuildConfirmActive(user, c.shareID, width, height)); err != nil {
		return fmt.Errorf("gordp: reactivate confirm active: %w", err)
	}
	for _, p := range [][]byte{
		pdu.BuildSynchronize(user, c.shareID, c.mcs.Server.IOChannelID),
		pdu.BuildControlCooperate(user, c.shareID),
		pdu.BuildControlRequest(user, c.shareID),
		pdu.BuildFontList(user, c.shareID),
	} {
		if err := c.sendIO(p); err != nil {
			return fmt.Errorf("gordp: reactivate finalization pdu: %w", err)
		}
	}
	return nil
}

func (c *Client) waitDemandActive() (uint32, error) {
	for i := 0; i < 16; i++ {
		_, msg, err := c.mcs.Receive()
		if err != nil {
			return 0, fmt.Errorf("gordp: read demand active: %w", err)
		}
		if msg.FastPath {
			continue
		}
		sc, err := pdu.ReadShareControl(c.stripSecHeader(msg.Payload))
		if err != nil {
			return 0, err
		}
		switch sc.PduType {
		case pdu.PdutypeDemandActive:
			da, err := pdu.ParseDemandActive(sc.Body)
			if err != nil {
				return 0, err
			}
			return da.ShareID, nil
		case pdu.PdutypeDeactivateAll:
			continue
		}
	}
	return 0, fmt.Errorf("gordp: did not receive demand active")
}

func (c *Client) waitFontMap() error {
	for i := 0; i < 16; i++ {
		_, msg, err := c.mcs.Receive()
		if err != nil {
			return fmt.Errorf("gordp: read font map: %w", err)
		}
		if msg.FastPath {
			continue
		}
		sc, err := pdu.ReadShareControl(c.stripSecHeader(msg.Payload))
		if err != nil {
			return err
		}
		if sc.PduType != pdu.PdutypeData {
			continue
		}
		sd, err := pdu.ReadShareData(sc.Body)
		if err != nil {
			return err
		}
		if sd.PduType2 == pdu.Pdutype2FontMap {
			c.active = true
			return nil
		}
	}
	return fmt.Errorf("gordp: did not receive font map")
}

// licensing reads licensing PDUs until the server lets the session proceed.
func (c *Client) licensing() error {
	for i := 0; i < 8; i++ {
		_, msg, err := c.mcs.Receive()
		if err != nil {
			return fmt.Errorf("gordp: read licensing: %w", err)
		}
		if msg.FastPath {
			continue
		}
		done, err := pdu.ParseLicensing(msg.Payload)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return fmt.Errorf("gordp: licensing did not complete")
}

// Active reports whether the capability exchange and finalization completed, so
// the session is ready to receive graphics updates.
func (c *Client) Active() bool {
	return c.active
}

// UserChannel returns the MCS user channel assigned by the server, valid after
// Connect.
func (c *Client) UserChannel() uint16 {
	if c.mcs == nil {
		return 0
	}
	return c.mcs.UserID
}

// IOChannel returns the MCS I/O channel, valid after Connect.
func (c *Client) IOChannel() uint16 {
	if c.mcs == nil || c.mcs.Server == nil {
		return 0
	}
	return c.mcs.Server.IOChannelID
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// SelectedProtocol reports which security protocol the server chose.
func (c *Client) SelectedProtocol() uint32 {
	return c.x224.SelectedProtocol
}
