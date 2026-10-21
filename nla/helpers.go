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

package nla

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("nla: read random: %w", err)
	}
	return b, nil
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// encodeUTF16 encodes s as little-endian UTF-16, the form Windows credential
// fields use.
func encodeUTF16(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("nla: marshal: %v", err))
	}
	return b
}

func writeTSRequest(conn io.Writer, req *tsRequest) error {
	b, err := asn1.Marshal(*req)
	if err != nil {
		return fmt.Errorf("nla: marshal TSRequest: %w", err)
	}
	if _, err := conn.Write(b); err != nil {
		return fmt.Errorf("nla: write TSRequest: %w", err)
	}
	return nil
}

func readTSRequest(conn io.Reader) (*tsRequest, error) {
	raw, err := readDERElement(conn)
	if err != nil {
		return nil, err
	}
	var req tsRequest
	if _, err := asn1.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("nla: unmarshal TSRequest: %w", err)
	}
	return &req, nil
}

// readDERElement reads exactly one DER TLV element from conn: the tag byte, the
// length (short or long form) and the content. TSRequest responses are not
// TPKT-framed, so we size the read from the DER length itself.
func readDERElement(conn io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("nla: read DER header: %w", err)
	}

	lengthByte := header[1]
	if lengthByte&0x80 == 0 {
		// Short form: the length is this byte.
		body := make([]byte, int(lengthByte))
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, fmt.Errorf("nla: read DER body: %w", err)
		}
		return append(header, body...), nil
	}

	// Long form: low 7 bits give the number of length bytes that follow.
	numLenBytes := int(lengthByte & 0x7f)
	if numLenBytes == 0 || numLenBytes > 4 {
		return nil, fmt.Errorf("nla: unsupported DER length form (%d bytes)", numLenBytes)
	}
	lenBytes := make([]byte, numLenBytes)
	if _, err := io.ReadFull(conn, lenBytes); err != nil {
		return nil, fmt.Errorf("nla: read DER length: %w", err)
	}
	length := 0
	for _, b := range lenBytes {
		length = length<<8 | int(b)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("nla: read DER body: %w", err)
	}

	out := append([]byte{}, header...)
	out = append(out, lenBytes...)
	out = append(out, body...)
	return out, nil
}

// ntStatus turns the common CredSSP error codes into readable text. The server
// returns these in the errorCode field when authentication fails.
func ntStatus(code uint32) string {
	switch code {
	case 0xC000006D:
		return "STATUS_LOGON_FAILURE: wrong user name or password"
	case 0xC000006A:
		return "STATUS_WRONG_PASSWORD"
	case 0xC0000064:
		return "STATUS_NO_SUCH_USER"
	case 0xC0000234:
		return "STATUS_ACCOUNT_LOCKED_OUT"
	case 0xC0000071:
		return "STATUS_PASSWORD_EXPIRED"
	case 0xC0000072:
		return "STATUS_ACCOUNT_DISABLED"
	case 0xC000006F:
		return "STATUS_INVALID_LOGON_HOURS"
	case 0xC0000070:
		return "STATUS_INVALID_WORKSTATION"
	case 0xC000018D:
		return "STATUS_TRUSTED_RELATIONSHIP_FAILURE"
	default:
		return "unknown NTSTATUS"
	}
}
