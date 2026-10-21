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
- [ ] Capability exchange (demand/confirm active) and connection finalization
- [ ] Bitmap decoding (interleaved RLE, planar, RemoteFX)
- [ ] Input (keyboard, mouse)
- [ ] Clipboard, display resize, drive redirection, RemoteApp
- [ ] Session recording

The graphics path is planned to hand fast-path updates to the browser for
decoding (via an IronRDP WASM module) rather than decoding in Go, so H.264 / GFX
stay reachable and the gateway stays light. See the design notes in the Casvisor
repo (`casvisor/rdp-client.md`).

## Trying it

`cmd/gordp-probe` runs the handshake as far as the library supports and reports
whether NLA succeeded. It is a development aid, not part of the library:

```
go run ./cmd/gordp-probe -addr HOST:3389 -user Administrator -pass SECRET
```

## License

Apache-2.0. See [LICENSE](LICENSE).
