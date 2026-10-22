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

// Command gordp-replay reconstructs the screen from a recording made by
// gordp.Recorder and exports PNG frames. It is a development aid for verifying
// recordings, not part of the library.
//
//	# a single frame at 8 seconds into the recording:
//	gordp-replay -in session.gorec -at 8 -png frame.png
//
//	# one frame per second across the whole recording (frame-0000.png, ...):
//	gordp-replay -in session.gorec -out frame-
package main

import (
	"flag"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"time"

	gordp "github.com/casvisor/gordp"
	"github.com/casvisor/gordp/bitmap"
	"github.com/casvisor/gordp/pdu"
)

func main() {
	in := flag.String("in", "", "recording file to replay")
	at := flag.Float64("at", -1, "export a single PNG of the frame at this second (use -png for the path)")
	pngPath := flag.String("png", "frame.png", "output PNG path for -at")
	out := flag.String("out", "", "export a sequence of PNGs with this prefix, one every -interval seconds")
	interval := flag.Float64("interval", 1, "seconds between frames for -out")
	flag.Parse()

	if *in == "" || (*at < 0 && *out == "") {
		fmt.Fprintln(os.Stderr, "usage: gordp-replay -in FILE (-at SEC [-png OUT] | -out PREFIX [-interval SEC])")
		os.Exit(2)
	}

	rr, err := gordp.OpenRecording(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = rr.Close() }()

	w, h := rr.Header.Width, rr.Header.Height
	if w == 0 {
		w = 1024
	}
	if h == 0 {
		h = 768
	}
	fmt.Printf("recording: %dx%d, started %s\n", w, h, rr.Header.Start.Format(time.RFC3339))

	if *at >= 0 {
		if err := exportAt(rr, w, h, uint32(*at*1000), *pngPath); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := exportSequence(rr, w, h, *out, *interval); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

// exportAt replays every bitmap update up to targetMs, then writes one PNG.
func exportAt(rr *gordp.RecordReader, w, h int, targetMs uint32, path string) error {
	fb := image.NewRGBA(image.Rect(0, 0, w, h))
	applied, last := 0, uint32(0)
	for {
		ev, err := rr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if ev.OffsetMs > targetMs {
			break
		}
		last = ev.OffsetMs
		n, err := applyEvent(fb, ev)
		if err != nil {
			return err
		}
		applied += n
	}
	if err := savePNG(fb, path); err != nil {
		return err
	}
	fmt.Printf("frame at %.3fs (%d rects applied up to %.3fs): %s\n",
		float64(targetMs)/1000, applied, float64(last)/1000, path)
	return nil
}

// exportSequence replays the whole recording in one pass, snapshotting the
// framebuffer every intervalSec seconds of recorded time.
func exportSequence(rr *gordp.RecordReader, w, h int, prefix string, intervalSec float64) error {
	if intervalSec <= 0 {
		intervalSec = 1
	}
	step := uint32(intervalSec * 1000)
	fb := image.NewRGBA(image.Rect(0, 0, w, h))

	next, index := uint32(0), 0
	for {
		ev, err := rr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Snapshot the frame as it stood at each boundary the event passed.
		for ev.OffsetMs > next {
			if err := saveFrame(fb, prefix, index, next); err != nil {
				return err
			}
			index++
			next += step
		}
		if _, err := applyEvent(fb, ev); err != nil {
			return err
		}
	}
	// A final frame with everything applied.
	if err := saveFrame(fb, prefix, index, next); err != nil {
		return err
	}
	fmt.Printf("exported %d frames with prefix %q\n", index+1, prefix)
	return nil
}

func saveFrame(fb *image.RGBA, prefix string, index int, atMs uint32) error {
	path := fmt.Sprintf("%s%04d.png", prefix, index)
	if err := savePNG(fb, path); err != nil {
		return err
	}
	fmt.Printf("  %s (%.3fs)\n", path, float64(atMs)/1000)
	return nil
}

// applyEvent composites a bitmap update onto fb and returns the rect count.
// Non-bitmap events are ignored.
func applyEvent(fb *image.RGBA, ev *gordp.RecordEvent) (int, error) {
	if ev.Code != pdu.FastPathUpdateBitmap {
		return 0, nil
	}
	rects, err := bitmap.ParseBitmapUpdate(ev.Data)
	if err != nil {
		return 0, err
	}
	for _, rect := range rects {
		blit(fb, rect)
	}
	return len(rects), nil
}

// blit copies one decoded top-down RGBA rect into the framebuffer, clipped to
// bounds. It mirrors Client.blit in session.go, kept here so replay does not
// depend on the session read loop.
func blit(fb *image.RGBA, rect bitmap.Rect) {
	bounds := fb.Bounds()
	for y := 0; y < rect.Height; y++ {
		dy := rect.DestTop + y
		if dy < 0 || dy >= bounds.Dy() {
			continue
		}
		for x := 0; x < rect.Width; x++ {
			dx := rect.DestLeft + x
			if dx < 0 || dx >= bounds.Dx() {
				continue
			}
			src := (y*rect.Width + x) * 4
			dst := fb.PixOffset(dx, dy)
			copy(fb.Pix[dst:dst+4], rect.RGBA[src:src+4])
		}
	}
}

func savePNG(fb *image.RGBA, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return png.Encode(f, fb)
}
