#!/bin/sh
cd "$(dirname "$0")" || exit 1
if [ "$(id -u)" -ne 0 ]; then
    echo "Yonetici olarak calistirin: sudo ./baslat.sh"
    exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
    echo "nftables yok. Kurun: apt install nftables  veya  dnf install nftables"
    exit 1
fi
arch="$(uname -m)"
bin="./discorddpi"
if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then
    bin="./discorddpi-arm64"
fi
if [ ! -x "$bin" ]; then
    chmod +x "$bin" 2>/dev/null
fi
if [ ! -f "$bin" ]; then
    echo "$bin bu klasorde yok."
    exit 1
fi
exec "$bin"
