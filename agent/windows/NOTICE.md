# Third-party notices

The Windows agent links the Go components below into `krynodes.exe` and
places the signed `wintun.dll` beside it. The release build
(`tooling/windows-bundle.sh`) embeds the DLL and every licence text below in
the executable; install and every service start write them to
`C:\Program Files\Krynodes` (`wintun.dll` and `licenses\`).

## Wintun

- Used for: the virtual network adapter that carries the tunnel.
- Source: https://www.wintun.net/builds/wintun-0.14.1.zip, SHA-256
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
  (pinned in `tooling/windows-bundle.sh`); the amd64 `wintun.dll` only.
- Licence: WireGuard LLC's Prebuilt Binaries License (`LICENSE.txt` in the
  zip, shipped as `licenses\wintun.txt`). Section 3d allows redistributing the
  DLL alongside software that uses it only through the `wintun.h` API, which
  wireguard-go's bindings do; 3a–3c forbid changing it or removing its
  notices. Krynodes writes the signed DLL out byte for byte.

## wireguard-go

- Used for: the WireGuard protocol implementation inside the service, and its
  `tun` package, which drives the Wintun adapter.
- Module: `golang.zx2c4.com/wireguard` `v0.0.0-20261024220952-b3bc704ef0ee`
  (the project tags no releases; this is its newest commit).
- Source: https://git.zx2c4.com/wireguard-go
- Licence: MIT (`LICENSE` in the module). Copyright (C) 2017-2025 WireGuard
  LLC. All Rights Reserved.

## Wintun Go bindings

- Used for: loading `wintun.dll` and talking to the adapter, through
  wireguard-go's `tun` package.
- Module: `golang.zx2c4.com/wintun` `v0.0.0-20230126152724-0fa3db229ce2`.
- Licence: MIT (`LICENSE` in the module). Copyright (C) 2017-2021 WireGuard
  LLC. All Rights Reserved.

## WireGuard for Windows: winipcfg

- Used for: the tunnel adapter's addresses, routes, DNS and interface
  settings (`tunnel/winipcfg` only; nothing else of the app is built in).
- Module: `golang.zx2c4.com/wireguard/windows` `v1.1.1`.
- Source: https://git.zx2c4.com/wireguard-windows
- Licence: MIT (`COPYING` in the module). Copyright (C) 2018-2026 WireGuard
  LLC. All Rights Reserved.

## Go extended libraries

- Used for: Windows system calls, and the cryptography and networking that
  wireguard-go builds on.
- Modules: `golang.org/x/sys` `v0.47.0`, `golang.org/x/crypto` `v0.50.0`,
  `golang.org/x/net` `v0.53.0`.
- Licence: BSD-3-Clause (`LICENSE` in each module). Copyright 2009 The Go
  Authors.

## fyne.io/systray

- Used for: the tray icon and its menu (`krynodes tray`).
- Module: `fyne.io/systray` `v1.12.2`.
- Source: https://github.com/fyne-io/systray
- Licence: Apache License 2.0 (`LICENSE` in the module; the module ships no
  `NOTICE` file). It is a fork of `github.com/getlantern/systray`, which is
  under the same licence. Its full text ships beside the executable.
- Its Linux and macOS parts need `github.com/godbus/dbus/v5` `v5.1.0`, which
  is listed in `go.mod` but not built into the Windows executable.
