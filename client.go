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
	"net"
	"time"

	"github.com/casvisor/gordp/mcs"
	"github.com/casvisor/gordp/nla"
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

	width  uint16
	height uint16

	conn *tls.Conn
	tpkt *tpkt.Layer
	x224 *x224.Layer
	mcs  *mcs.Layer
}

// WithDesktopSize sets the desktop resolution requested from the server.
func WithDesktopSize(width, height uint16) Option {
	return func(c *Client) {
		c.width = width
		c.height = height
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
		tcp.Close()
		return err
	}

	tlsConn := tls.Client(tcp, &tls.Config{
		InsecureSkipVerify: true, // RDP hosts use self-signed certs; pinning is checked below.
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		tcp.Close()
		return fmt.Errorf("gordp: tls handshake: %w", err)
	}
	if err := c.verifyCert(tlsConn); err != nil {
		tlsConn.Close()
		return err
	}
	c.conn = tlsConn
	c.tpkt.SetConn(tlsConn)

	if c.x224.SelectedProtocol&x224.ProtocolHybrid != 0 {
		if err := nla.Authenticate(tlsConn, c.creds); err != nil {
			tlsConn.Close()
			return err
		}
	}

	// MCS: GCC conference create, erect domain, attach user, join channels.
	c.mcs = mcs.New(c.x224)
	if err := c.mcs.Connect(mcs.ClientConfig{
		DesktopWidth:     c.width,
		DesktopHeight:    c.height,
		SelectedProtocol: c.x224.SelectedProtocol,
	}); err != nil {
		tlsConn.Close()
		return err
	}

	// Clear the handshake deadline; the session read loop manages its own.
	_ = tlsConn.SetDeadline(time.Time{})
	return nil
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
