#!/bin/sh
set -eu

mode="enroll"
if [ "${1:-}" = "--update" ]; then
  mode="update"
fi
endpoint="${1:-}"
token="${2:-}"
trust_origin=""
if [ "$mode" = "enroll" ] && [ "${3:-}" = "--trust" ]; then
  trust_origin="${4:-}"
  if [ -z "$trust_origin" ] || [ -z "${5:-}" ]; then
    echo "--trust needs the dashboard origin and at least one device" >&2
    exit 1
  fi
  shift 4
else
  set --
fi
base="${KRY_DOWNLOAD_BASE:-https://github.com/Kleavox/Krynodes/releases/latest/download}"
bin="${KRY_BIN:-/usr/local/bin/kry}"
config="${KRY_CONFIG:-/etc/kry/config.json}"
release_key="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADLGUbsAkMk1uQY9fs9DNkQYPcMsJ3VyZTRLx2tRzzLg=
-----END PUBLIC KEY-----
"

if [ "$mode" = "enroll" ] && { [ -z "$endpoint" ] || [ -z "$token" ]; }; then
  echo "Usage: curl -fsSL <kry>/install.sh | sudo sh -s -- <endpoint> <enrollment-token>" >&2
  echo "   or: curl -fsSL <kry>/install.sh | sudo sh -s -- --update" >&2
  echo "Copy the full command from the Krynodes dashboard." >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run it as root: pipe the script into 'sudo sh -s --'." >&2
  exit 1
fi

if [ "$mode" = "update" ] && [ ! -f "$config" ]; then
  echo "No enrolled agent here ($config is missing). Use the Enroll node command instead." >&2
  exit 1
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) artifact="krynodes-linux-amd64" ;;
  Linux-aarch64 | Linux-arm64) artifact="krynodes-linux-arm64" ;;
  *)
    echo "Unsupported platform: $(uname -s) $(uname -m)" >&2
    exit 1
    ;;
esac

for tool in curl sha256sum openssl systemctl install; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required" >&2
    exit 1
  fi
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  curl --proto =https --tlsv1.3 -fsSL --retry 5 --retry-delay 3 --speed-limit 1024 --speed-time 60 "$1" -o "$2"
}

echo "Downloading $artifact"
if command -v gzip >/dev/null 2>&1 && fetch "$base/$artifact.gz" "$tmp/$artifact.gz" 2>/dev/null; then
  gzip -dc "$tmp/$artifact.gz" >"$tmp/$artifact"
else
  fetch "$base/$artifact" "$tmp/$artifact"
fi
fetch "$base/$artifact.sha256" "$tmp/$artifact.sha256"
(cd "$tmp" && sha256sum -c "$artifact.sha256" >/dev/null)
fetch "$base/$artifact.sig" "$tmp/$artifact.sig"
printf '%s' "$release_key" >"$tmp/release.pem"
if ! openssl pkeyutl -verify -pubin -inkey "$tmp/release.pem" -rawin -in "$tmp/$artifact" -sigfile "$tmp/$artifact.sig" >/dev/null 2>&1; then
  echo "The download is not signed by the Krynodes release key, so nothing was installed." >&2
  echo "This check needs OpenSSL 1.1.1 or newer." >&2
  exit 1
fi
install -m 0755 "$tmp/$artifact" "$bin"

if [ "$mode" = "enroll" ]; then
  "$bin" enroll --endpoint "$endpoint" --token "$token"
fi
"$bin" install-service
if [ -n "$trust_origin" ]; then
  "$bin" trust --initial --origin "$trust_origin" "$@"
fi
systemctl restart krynodes.service

if [ "$mode" = "update" ]; then
  echo "Krynodes agent updated to $("$bin" version)."
else
  echo "Krynodes agent $("$bin" version) is running."
fi
echo "Check it with: sudo systemctl status krynodes"
