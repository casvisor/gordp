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
	testInput := flag.Bool("input", false, "after the screenshot, press the Windows key and save <png>.after.png")
	pump := flag.Duration("pump", 5*time.Second, "how long to read updates before the screenshot")
	record := flag.String("record", "", "record fast-path updates during the pump to this file (replay with gordp-replay)")
	resize := flag.String("resize", "", "request a desktop resize to WxH (e.g. 1600x900) and verify")
	clip := flag.Bool("clip", false, "run a clipboard round-trip self-test (read remote clipboard, write to it)")
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
	defer func() { _ = c.Close() }()

	fmt.Printf("OK: session active (NLA + MCS + login + licensing + capabilities)\n")
	fmt.Printf("  selected protocol: 0x%08x\n", c.SelectedProtocol())
	fmt.Printf("  server cert sha256: %s\n", c.ServerCertFingerprint())
	fmt.Printf("  mcs user channel:  %d\n", c.UserChannel())
	fmt.Printf("  mcs i/o channel:   %d\n", c.IOChannel())
	fmt.Printf("  session active:    %v\n", c.Active())

	if *record != "" {
		w, h := c.DesktopSize()
		rec, err := gordp.NewRecorder(*record, w, h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "record: %v\n", err)
			os.Exit(1)
		}
		c.OnFastPath = rec.Record
		defer func() {
			if err := rec.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "close recording: %v\n", err)
				return
			}
			fmt.Printf("  saved recording:   %s\n", *record)
		}()
		// With no screenshot to drive a pump, read updates for -pump so the
		// recording captures something.
		if *shot == "" {
			n, err := c.PumpUpdates(*pump)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pump: %v\n", err)
			}
			fmt.Printf("  rectangles:        %d\n", n)
		}
	}

	if *shot != "" {
		n, err := c.PumpUpdates(*pump)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pump: %v\n", err)
		}
		fmt.Printf("  rectangles:        %d\n", n)
		fmt.Printf("  color depth:       %d bpp\n", c.LastBpp())
		f, err := os.Create(*shot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create png: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		if err := png.Encode(f, c.Framebuffer()); err != nil {
			fmt.Fprintf(os.Stderr, "encode png: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  saved screenshot:  %s\n", *shot)

		if *testInput {
			// Click the Start button at the bottom-left to open the Start menu,
			// then type into its search box to exercise the keyboard.
			if err := c.Click(200, 748); err != nil {
				fmt.Fprintf(os.Stderr, "click: %v\n", err)
				os.Exit(1)
			}
			_, _ = c.PumpUpdates(2 * time.Second)
			if err := c.TypeUnicode("notepad"); err != nil {
				fmt.Fprintf(os.Stderr, "type: %v\n", err)
				os.Exit(1)
			}
			if _, err := c.PumpUpdates(3 * time.Second); err != nil {
				fmt.Fprintf(os.Stderr, "pump after input: %v\n", err)
			}
			after := *shot + ".after.png"
			af, err := os.Create(after)
			if err != nil {
				fmt.Fprintf(os.Stderr, "create png: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = af.Close() }()
			if err := png.Encode(af, c.Framebuffer()); err != nil {
				fmt.Fprintf(os.Stderr, "encode png: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("  saved after-input: %s\n", after)
		}
	}

	if *resize != "" {
		runResizeTest(c, *resize)
	}

	if *clip {
		runClipboardTest(c)
	}
}

// runResizeTest requests a desktop resize over the DisplayControl dynamic
// channel and reports the resulting desktop size.
func runResizeTest(c *gordp.Client, spec string) {
	var w, h uint16
	if _, err := fmt.Sscanf(spec, "%dx%d", &w, &h); err != nil {
		fmt.Fprintf(os.Stderr, "bad -resize %q (want WxH)\n", spec)
		return
	}
	// Let drdynvc negotiate and the DisplayControl channel open.
	if _, err := c.PumpUpdates(4 * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "resize pump: %v\n", err)
	}
	bw, bh := c.DesktopSize()
	fmt.Printf("  resize: before %dx%d, requesting %dx%d\n", bw, bh, w, h)
	if err := c.Resize(w, h); err != nil {
		fmt.Printf("  resize: FAIL (%v)\n", err)
		return
	}
	// Pump to let the server deactivate-reactivate at the new size.
	if _, err := c.PumpUpdates(6 * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "resize pump: %v\n", err)
	}
	aw, ah := c.DesktopSize()
	fmt.Printf("  resize: now %dx%d\n", aw, ah)
	if f, err := os.Create("gordp-resize.png"); err == nil {
		if err := png.Encode(f, c.Framebuffer()); err == nil {
			fmt.Printf("  resize shot:       gordp-resize.png\n")
		}
		_ = f.Close()
	}
}

// runClipboardTest offers text to the remote clipboard and reports what the
// remote clipboard sends back.
func runClipboardTest(c *gordp.Client) {
	received := make(chan string, 4)
	c.OnClipboard = func(text string) { received <- text }
	// Finish the clipboard handshake.
	_, _ = c.PumpUpdates(3 * time.Second)
	fmt.Printf("  clipboard ready:   %v\n", c.ClipboardReady())

	text := fmt.Sprintf("gordp-clip-%d", time.Now().Unix())
	if err := c.SetClipboard(text); err != nil {
		fmt.Fprintf(os.Stderr, "set clipboard: %v\n", err)
	}
	_, _ = c.PumpUpdates(2 * time.Second)
	fmt.Printf("  write test:        offered %q to the remote clipboard\n", text)

	select {
	case got := <-received:
		fmt.Printf("  read test:         got %q from remote\n", got)
	default:
	}
}
