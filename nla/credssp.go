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

// Package nla implements CredSSP (MS-CSSP), the "Network Level Authentication"
// that modern Windows requires before it will even show a desktop. The gateway
// runs this over the TLS channel set up after the X.224 negotiation: it carries
// an NTLM exchange, proves it holds the server's public key, and only then
// hands over the user's password. Running it on the gateway is what keeps the
// password off the browser.
//
// The NTLM message building and sealing come from oiweiwei/go-msrpc (MIT) so we
// do not hand-roll — or risk copying — anyone else's NTLM. Everything in this
// file (the TSRequest wrapping and the public-key binding) is from the public
// MS-CSSP and MS-NLMP specifications.
package nla

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/ntlm"
)

// The CredSSP version we claim. Version 6 is what current Windows speaks; from
// version 5 on the public-key check is bound with a client nonce.
const credSSPVersion = 6

var (
	clientServerHashMagic = append([]byte("CredSSP Client-To-Server Binding Hash"), 0)
	serverClientHashMagic = append([]byte("CredSSP Server-To-Client Binding Hash"), 0)
)

// negoToken is one token inside NegoData.
type negoToken struct {
	Token []byte `asn1:"explicit,tag:0"`
}

// tsRequest is the top-level CredSSP message (MS-CSSP 2.2.1).
type tsRequest struct {
	Version     int         `asn1:"explicit,tag:0"`
	NegoTokens  []negoToken `asn1:"optional,explicit,tag:1"`
	AuthInfo    []byte      `asn1:"optional,explicit,tag:2"`
	PubKeyAuth  []byte      `asn1:"optional,explicit,tag:3"`
	ErrorCode   int         `asn1:"optional,explicit,tag:4"`
	ClientNonce []byte      `asn1:"optional,explicit,tag:5"`
}

// tsPasswordCreds is the delegated password (MS-CSSP 2.2.1.2.1).
type tsPasswordCreds struct {
	DomainName []byte `asn1:"explicit,tag:0"`
	UserName   []byte `asn1:"explicit,tag:1"`
	Password   []byte `asn1:"explicit,tag:2"`
}

// tsCredentials wraps the delegated credentials (MS-CSSP 2.2.1.2).
type tsCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

// Credentials is the identity the gateway authenticates with on the user's
// behalf. The password is used here and never leaves the gateway.
type Credentials struct {
	Domain   string
	Username string
	Password string
}

// transport is the minimal read/write the CredSSP exchange needs. In the full
// client this is the TLS connection.
type transport interface {
	Write(p []byte) (int, error)
	Read(p []byte) (int, error)
}

// Authenticate runs the full CredSSP exchange over conn, which must already be
// a completed TLS handshake with the RDP server.
func Authenticate(conn *tls.Conn, creds Credentials) error {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("nla: server presented no certificate")
	}
	pubKey, err := publicKeyBytes(state.PeerCertificates[0])
	if err != nil {
		return err
	}

	ctx := context.Background()

	cfg := ntlm.NewConfig()
	cfg.Integrity = true
	cfg.Confidentiality = true
	cfg.Credential = credential.NewFromPassword(logonName(creds), creds.Password)
	auth := &ntlm.Authentifier{Config: cfg}

	// Step 1: client -> server, NTLM NEGOTIATE.
	negotiate, err := auth.Negotiate(ctx)
	if err != nil {
		return fmt.Errorf("nla: ntlm negotiate: %w", err)
	}
	if err := writeTSRequest(conn, &tsRequest{
		Version:    credSSPVersion,
		NegoTokens: []negoToken{{Token: negotiate}},
	}); err != nil {
		return err
	}

	// Step 2: server -> client, NTLM CHALLENGE.
	resp, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if len(resp.NegoTokens) == 0 {
		return fmt.Errorf("nla: server did not return an NTLM challenge")
	}

	// Step 3: client -> server, NTLM AUTHENTICATE plus the sealed public key
	// bound to a fresh client nonce.
	authenticate, err := auth.Authenticate(ctx, resp.NegoTokens[0].Token)
	if err != nil {
		return fmt.Errorf("nla: ntlm authenticate: %w", err)
	}
	nonce, err := randomBytes(32)
	if err != nil {
		return err
	}
	bound := bindingHash(clientServerHashMagic, nonce, pubKey)
	sealed, err := wrap(ctx, auth, bound)
	if err != nil {
		return fmt.Errorf("nla: seal public key: %w", err)
	}
	if err := writeTSRequest(conn, &tsRequest{
		Version:     credSSPVersion,
		NegoTokens:  []negoToken{{Token: authenticate}},
		PubKeyAuth:  sealed,
		ClientNonce: nonce,
	}); err != nil {
		return err
	}

	// Step 4: server -> client, sealed server-bound public key.
	resp, err = readTSRequest(conn)
	if err != nil {
		return err
	}
	if resp.ErrorCode != 0 {
		return fmt.Errorf("nla: server reported error 0x%08x (%s)", uint32(resp.ErrorCode), ntStatus(uint32(resp.ErrorCode)))
	}
	if len(resp.PubKeyAuth) == 0 {
		return fmt.Errorf("nla: server did not return a sealed public key (authentication likely failed)")
	}
	got, err := unwrap(ctx, auth, resp.PubKeyAuth)
	if err != nil {
		return fmt.Errorf("nla: unseal server public key: %w", err)
	}
	want := bindingHash(serverClientHashMagic, nonce, pubKey)
	if !bytesEqual(got, want) {
		return fmt.Errorf("nla: server public key check failed (possible man-in-the-middle)")
	}

	// Step 5: client -> server, the delegated password.
	creds2, err := asn1.Marshal(tsCredentials{
		CredType: 1,
		Credentials: mustMarshal(tsPasswordCreds{
			DomainName: encodeUTF16(creds.Domain),
			UserName:   encodeUTF16(creds.Username),
			Password:   encodeUTF16(creds.Password),
		}),
	})
	if err != nil {
		return fmt.Errorf("nla: marshal credentials: %w", err)
	}
	sealedCreds, err := wrap(ctx, auth, creds2)
	if err != nil {
		return fmt.Errorf("nla: seal credentials: %w", err)
	}
	return writeTSRequest(conn, &tsRequest{
		Version:  credSSPVersion,
		AuthInfo: sealedCreds,
	})
}

// wrap seals plaintext with the NTLM confidentiality and prepends the 16-byte
// signature, the layout CredSSP's pubKeyAuth and authInfo fields use.
func wrap(ctx context.Context, auth *ntlm.Authentifier, plaintext []byte) ([]byte, error) {
	checksum, err := auth.MakeOutboundChecksum(ctx, [][]byte{plaintext})
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, len(plaintext))
	copy(sealed, plaintext)
	if err := auth.ApplyOutboundCipher(ctx, sealed); err != nil {
		return nil, err
	}
	signature, err := auth.MakeOutboundSignature(ctx, checksum)
	if err != nil {
		return nil, err
	}
	return append(signature, sealed...), nil
}

// unwrap reverses wrap and verifies the signature.
func unwrap(ctx context.Context, auth *ntlm.Authentifier, data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("sealed blob too short: %d bytes", len(data))
	}
	signature := data[:16]
	plaintext := make([]byte, len(data)-16)
	copy(plaintext, data[16:])
	if err := auth.ApplyInboundCipher(ctx, plaintext); err != nil {
		return nil, err
	}
	checksum, err := auth.MakeInboundChecksum(ctx, [][]byte{plaintext})
	if err != nil {
		return nil, err
	}
	expected, err := auth.MakeInboundSignature(ctx, checksum)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(signature, expected) {
		return nil, fmt.Errorf("signature mismatch")
	}
	return plaintext, nil
}

func bindingHash(magic, nonce, pubKey []byte) []byte {
	h := sha256.New()
	h.Write(magic)
	h.Write(nonce)
	h.Write(pubKey)
	return h.Sum(nil)
}

// publicKeyBytes returns the PKCS#1 DER of the server's RSA public key, which
// is what CredSSP binds against.
func publicKeyBytes(cert *x509.Certificate) ([]byte, error) {
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("nla: server key is %T, only RSA is supported for now", cert.PublicKey)
	}
	return x509.MarshalPKCS1PublicKey(rsaKey), nil
}

func logonName(c Credentials) string {
	if c.Domain != "" {
		return c.Domain + "\\" + c.Username
	}
	return c.Username
}
