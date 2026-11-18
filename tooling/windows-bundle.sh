#!/bin/sh
set -eu

wintun_url="https://www.wintun.net/builds/wintun-0.14.1.zip"
wintun_sha256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

cd "$(dirname "$0")/../agent/windows"
files="internal/bundle/files"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fsSL --retry 3 "$wintun_url" -o "$work/wintun.zip"
echo "$wintun_sha256  $work/wintun.zip" | sha256sum -c -
unzip -q "$work/wintun.zip" -d "$work"

rm -rf "$files/licenses"
mkdir -p "$files/licenses"
cp "$work/wintun/bin/amd64/wintun.dll" "$files/wintun.dll"
cp "$work/wintun/LICENSE.txt" "$files/licenses/wintun.txt"

export GOWORK=off
go mod download
while read -r module licence name; do
  dir="$(go list -m -f '{{.Dir}}' "$module")"
  cp "$dir/$licence" "$files/licenses/$name.txt"
done <<EOF
golang.zx2c4.com/wireguard LICENSE wireguard-go
golang.zx2c4.com/wintun LICENSE wintun-go
golang.zx2c4.com/wireguard/windows COPYING wireguard-windows
golang.org/x/sys LICENSE golang-x-sys
golang.org/x/crypto LICENSE golang-x-crypto
golang.org/x/net LICENSE golang-x-net
fyne.io/systray LICENSE systray
EOF

ls -l "$files" "$files/licenses"
