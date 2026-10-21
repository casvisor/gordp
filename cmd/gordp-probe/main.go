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

// Command gordp-probe connects to an RDP host and runs the handshake as far as
// the client currently supports, reporting what the server selected and whether
// CredSSP (NLA) succeeded. It is a development aid for testing against real
// Windows hosts, not part of the library.
package main

import (
	"flag"
	"fmt"
	"image/png"
	"os"
	"time"

	gordp "github.com/casvisor/gordp"
)

func main() {
	addr := flag.String("addr", "", "host:port, e.g. 10.0.0.5:3389")
	domain := flag.String("domain", "", "domain (optional)")
	user := flag.String("user", "", "username")
	pass := flag.String("pass", "", "password")
	shot := flag.String("screenshot", "", "pump updates and save the desktop to this PNG")
	flag.Parse()

	if *addr == "" || *user == "" {
		fmt.Fprintln(os.Stderr, "usage: gordp-probe -addr host:port -user NAME -pass PASS [-domain DOMAIN]")
		os.Exit(2)
	}

	c := gordp.NewClient(*addr, *domain, *user, *pass)
	if err := c.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	fmt.Printf("OK: session active (NLA + MCS + login + licensing + capabilities)\n")
	fmt.Printf("  selected protocol: 0x%08x\n", c.SelectedProtocol())
	fmt.Printf("  server cert sha256: %s\n", c.ServerCertFingerprint())
	fmt.Printf("  mcs user channel:  %d\n", c.UserChannel())
	fmt.Printf("  mcs i/o channel:   %d\n", c.IOChannel())
	fmt.Printf("  session active:    %v\n", c.Active())

	if *shot != "" {
		n, err := c.PumpUpdates(5 * time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pump: %v\n", err)
		}
		fmt.Printf("  rectangles:        %d\n", n)
		f, err := os.Create(*shot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create png: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := png.Encode(f, c.Framebuffer()); err != nil {
			fmt.Fprintf(os.Stderr, "encode png: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  saved screenshot:  %s\n", *shot)
	}
}
