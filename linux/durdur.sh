#!/bin/sh
if [ "$(id -u)" -ne 0 ]; then
    echo "Yonetici olarak calistirin: sudo ./durdur.sh"
    exit 1
fi
killall discorddpi discorddpi-arm64 2>/dev/null
nft delete table inet discorddpi 2>/dev/null
echo "Durduruldu."
