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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
)

// verifyCert checks the server certificate against the pinned fingerprint, if
// one was configured.
func (c *Client) verifyCert(conn *tls.Conn) error {
	if c.certFingerprint == "" {
		return nil
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("gordp: server presented no certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	got := hex.EncodeToString(sum[:])
	want := strings.ToLower(strings.ReplaceAll(c.certFingerprint, ":", ""))
	if got != want {
		return fmt.Errorf("gordp: server certificate fingerprint %s does not match pinned %s", got, want)
	}
	return nil
}

// ServerCertFingerprint returns the SHA-256 fingerprint of the connected
// server's certificate, for recording a pin on first connect.
func (c *Client) ServerCertFingerprint() string {
	if c.conn == nil {
		return ""
	}
	state := c.conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:])
}
