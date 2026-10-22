# gordp

A pure-Go RDP (Remote Desktop Protocol) client library.

gordp is built for the [Casvisor](https://github.com/casvisor/casvisor) bastion
to connect to Windows hosts without the FreeRDP / guacd C stack. The gateway
authenticates to the Windows host on the user's behalf and relays the screen to
the browser, so the user's password never leaves the gateway.

Goals:

- Pure Go, no cgo, so one static binary runs on Linux, Windows and macOS.
- Apache-2.0, with no code taken from GPL-licensed RDP projects.
- Gateway-shaped: credentials are injected server-side, access is auditable.

## Status

Early. The connection chain up through Network Level Authentication works and is
tested against a default-configuration Windows Server 2022:

- [x] TPKT framing and fast-path PDU detection
- [x] X.224 connection negotiation (requests CredSSP / TLS)
- [x] TLS transport with optional certificate pinning
- [x] CredSSP / NLA: NTLMv2 via [go-msrpc](https://github.com/oiweiwei/go-msrpc),
      public-key binding with client nonce, password delegation
- [x] MCS connect (GCC conference create), erect domain, attach user, channel join
- [x] Client info (login) PDU and licensing (valid-client / admin mode)
- [x] Capability exchange (demand/confirm active) and connection finalization
      (synchronize, control, font list/map) — the session reaches the active state
- [x] Fast-path (and slow-path) bitmap update reception, framebuffer compositing
- [x] Bitmap decoding: interleaved RLE (15/16bpp) and the RDP 6.0 planar codec
      (24/32bpp true colour), plus uncompressed
- [x] Graphics pipeline (MS-RDPEGFX), the path current Windows clients use:
      RDP8 bulk decompression (ZGFX), surfaces, caches, frame acknowledgement,
      and the ClearCodec (with NSCodec and RLEX), planar and RemoteFX
      Progressive codecs. Output matches FreeRDP's decoders.
- [ ] H.264 (AVC420 / AVC444): Windows only encodes it when a group policy
      enables it
- [x] Mouse cursor shapes, including large cursors on scaled desktops
- [x] Input: fast-path mouse (move, buttons, wheel) and keyboard (scancode, unicode)
- [x] Virtual channels: static channels and dynamic channels (drdynvc)
- [x] Clipboard (text, both directions) and display resize
- [x] Drive redirection: a local directory appears as `\\tsclient\<name>`, with
      read-only / write-only modes and audit events for every file operation
- [ ] RemoteApp
- [x] Session recording and replay (fast-path update capture, PNG reconstruction)

A full 32bpp desktop frame decodes correctly against Windows Server 2022: run
`gordp-probe` with `-screenshot out.png`.

With `WithGFX`, gordp decodes every codec and hands the viewer the surface
commands (fills, copies, cache and glyph operations, decoded bitmaps), so a web
viewer keeps the surfaces and draws each server frame at once.

## Trying it

`cmd/gordp-probe` runs the handshake as far as the library supports and reports
whether NLA succeeded. It is a development aid, not part of the library:

```
go run ./cmd/gordp-probe -addr HOST:3389 -user Administrator -pass SECRET
```

## License

Apache-2.0. See [LICENSE](LICENSE).
