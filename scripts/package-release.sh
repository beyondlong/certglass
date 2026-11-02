#!/bin/bash
set -euo pipefail

certglass_root="$(cd "$(dirname "$0")/.." && pwd)"
certglass_version="${1:-$(/usr/bin/plutil -extract CFBundleShortVersionString raw "$certglass_root/App/CertGlass/Info.plist")}"
certglass_output="${2:-$certglass_root/dist/CertGlass-$certglass_version}"
certglass_swift="${CERTGLASS_SWIFT:-swift}"

cd "$certglass_root"
rm -rf "$certglass_output"
mkdir -p "$certglass_output"

CERTGLASS_SWIFT="$certglass_swift" "$certglass_root/scripts/build-app.sh" release universal
certglass_universal_app="$certglass_root/build/release-universal/CertGlass.app"

for certglass_arch in arm64 x86_64; do
    certglass_app="$certglass_output/CertGlass-$certglass_version-$certglass_arch.app"
    certglass_stage="$certglass_output/staging-$certglass_arch"
    certglass_thin="$certglass_output/CertGlass-$certglass_arch-thin"

    ditto "$certglass_universal_app" "$certglass_app"
    lipo -thin "$certglass_arch" \
        "$certglass_universal_app/Contents/MacOS/CertGlass" -output "$certglass_thin"
    mv "$certglass_thin" "$certglass_app/Contents/MacOS/CertGlass"

    /usr/bin/codesign --force --sign - \
        --entitlements "$certglass_root/App/CertGlass/CertGlass.entitlements" "$certglass_app"
    /usr/bin/codesign --verify --strict "$certglass_app"
    /usr/bin/plutil -extract CFBundleIconFile raw "$certglass_app/Contents/Info.plist" \
        | grep -qx 'CertGlass.icns'
    test -f "$certglass_app/Contents/Resources/CertGlass.icns"
    lipo -info "$certglass_app/Contents/MacOS/CertGlass" | grep -q "architecture: $certglass_arch"

    mkdir -p "$certglass_stage"
    ditto "$certglass_app" "$certglass_stage/CertGlass.app"
    ln -s /Applications "$certglass_stage/Applications"

    ditto -c -k --sequesterRsrc --keepParent \
        "$certglass_app" "$certglass_output/CertGlass-$certglass_version-$certglass_arch.zip"
    hdiutil create \
        -volname "CertGlass $certglass_version ($certglass_arch)" \
        -srcfolder "$certglass_stage" -ov -format UDZO \
        "$certglass_output/CertGlass-$certglass_version-$certglass_arch.dmg" >/dev/null
done

shasum -a 256 \
    "$certglass_output/CertGlass-$certglass_version-arm64.dmg" \
    "$certglass_output/CertGlass-$certglass_version-arm64.zip" \
    "$certglass_output/CertGlass-$certglass_version-x86_64.dmg" \
    "$certglass_output/CertGlass-$certglass_version-x86_64.zip" \
    > "$certglass_output/SHA256SUMS.txt"

rm -rf "$certglass_output"/staging-arm64 "$certglass_output"/staging-x86_64
printf '已生成安装包：%s\n' "$certglass_output"
