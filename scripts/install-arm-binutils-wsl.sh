#!/usr/bin/env bash
# Extract the existing Ubuntu GNU toolchain package locally; no apt install.
set -euo pipefail
M1_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$M1_ROOT"
mkdir -p temp/downloads vendor/arm-binutils
package=binutils-arm-none-eabi_2.45.50.20251209-1ubuntu1+23build1_amd64.deb
url="https://archive.ubuntu.com/ubuntu/pool/universe/b/binutils-arm-none-eabi/$package"
expected=abccb894e824f007bd2f969e2164d164d308badf507910f105c3c3641345b416
if [ ! -f "temp/downloads/$package" ]; then
    curl -fL --silent --show-error --retry 2 --max-time 180 "$url" -o "temp/downloads/$package"
fi
printf '%s  %s\n' "$expected" "temp/downloads/$package" | sha256sum -c -
dpkg-deb --extract "temp/downloads/$package" vendor/arm-binutils
vendor/arm-binutils/usr/bin/arm-none-eabi-as --version
vendor/arm-binutils/usr/bin/arm-none-eabi-ld --version
