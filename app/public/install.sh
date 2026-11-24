#!/bin/sh
set -eu

main() {
  trap '' HUP
  endpoint=""
  token=""
  origin=""
  trust=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --endpoint | --token | --origin | --trust)
        if [ $# -lt 2 ]; then
          echo "$1 needs a value" >&2
          exit 1
        fi
        case "$2" in
          "" | *[!A-Za-z0-9:/._,-]*)
            echo "$1 has characters it cannot carry" >&2
            exit 1
            ;;
        esac
        case "$1" in
          --endpoint) endpoint="$2" ;;
          --token) token="$2" ;;
          --origin) origin="$2" ;;
          *) trust="$2" ;;
        esac
        shift 2
        ;;
      *)
        echo "Unexpected argument: $1" >&2
        exit 1
        ;;
    esac
  done
  if [ -z "$endpoint" ] || [ -z "$token" ] || [ -z "$origin" ] || [ -z "$trust" ]; then
    echo "Usage: curl -fsSL <kry>/i/<code> | sudo sh" >&2
    echo "Copy the full command from the Krynodes dashboard." >&2
    exit 1
  fi
  case "$origin" in
    https://* | http://localhost* | http://127.0.0.1*) ;;
    *)
      echo "--origin takes the dashboard's address" >&2
      exit 1
      ;;
  esac
  base="${KRY_DOWNLOAD_BASE:-https://github.com/Kleavox/Krynodes/releases/latest/download}"
  bin="${KRY_BIN:-/usr/local/bin/kry}"
  config="${KRY_CONFIG:-/etc/kry/config.json}"
  release_key="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADLGUbsAkMk1uQY9fs9DNkQYPcMsJ3VyZTRLx2tRzzLg=
-----END PUBLIC KEY-----
"

  if [ -f "$config" ]; then
    echo "This server is already enrolled ($config exists). To enroll it again, remove Krynodes first: sudo $bin uninstall-service" >&2
    exit 1
  fi

  if [ "$(id -u)" != 0 ]; then
    echo "Run it as root: pipe the script into 'sudo sh'." >&2
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
  if ! checked=$(openssl pkeyutl -verify -pubin -inkey "$tmp/release.pem" -rawin -in "$tmp/$artifact" -sigfile "$tmp/$artifact.sig" 2>&1); then
    echo "The download could not be checked against the Krynodes release key, so nothing was installed." >&2
    echo "This check needs OpenSSL 3.0 or newer; this server has: $(openssl version 2>/dev/null || echo none)." >&2
    printf '%s\n' "$checked" | tail -n 3 >&2
    exit 1
  fi
  install -m 0755 "$tmp/$artifact" "$bin"

  "$bin" enroll --endpoint "$endpoint" --token "$token" --origin "$origin" --trust "$trust"
  "$bin" install-service

  echo "Krynodes agent $("$bin" version) is running."
  echo "Check it with: sudo systemctl status krynodes"
  if fp=$("$bin" network fingerprint); then
    echo "Network fingerprint: $fp"
  else
    echo "See it with: sudo kry network fingerprint"
  fi
}

main "$@"
