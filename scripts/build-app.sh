#!/bin/bash
set -euo pipefail

certglass_root="$(cd "$(dirname "$0")/.." && pwd)"
certglass_configuration="${1:-debug}"
certglass_architecture="${2:-native}"
certglass_swift="${CERTGLASS_SWIFT:-swift}"

case "$certglass_configuration" in debug|release) ;; *) echo "用法：$0 [debug|release] [native|universal]" >&2; exit 2 ;; esac
case "$certglass_architecture" in native|universal) ;; *) echo "用法：$0 [debug|release] [native|universal]" >&2; exit 2 ;; esac
cd "$certglass_root"

certglass_bundle="$certglass_root/build/$certglass_configuration-$certglass_architecture/CertGlass.app"
mkdir -p "$certglass_bundle/Contents/MacOS" "$certglass_bundle/Contents/Resources"

if [[ "$certglass_architecture" == universal ]]; then
    certglass_binaries=()
    for certglass_arch in arm64 x86_64; do
        certglass_options=(--configuration "$certglass_configuration" --product CertGlass --arch "$certglass_arch" --scratch-path "$certglass_root/.build/$certglass_arch")
        "$certglass_swift" build "${certglass_options[@]}"
        certglass_bin_path="$("$certglass_swift" build "${certglass_options[@]}" --show-bin-path)"
        certglass_binaries+=("$certglass_bin_path/CertGlass")
    done
    /usr/bin/lipo -create "${certglass_binaries[@]}" -output "$certglass_bundle/Contents/MacOS/CertGlass"
else
    certglass_options=(--configuration "$certglass_configuration" --product CertGlass)
    "$certglass_swift" build "${certglass_options[@]}"
    certglass_bin_path="$("$certglass_swift" build "${certglass_options[@]}" --show-bin-path)"
    cp "$certglass_bin_path/CertGlass" "$certglass_bundle/Contents/MacOS/CertGlass"
fi

cp App/CertGlass/Info.plist "$certglass_bundle/Contents/Info.plist"

# Compile the app icon when the full Xcode toolchain is available. The local
# Command Line Tools image does not ship actool/iconutil reliably, so icon
# compilation is optional for this SwiftPM packaging path; Xcode builds still
# consume App/CertGlass/Assets.xcassets through the project file.
if certglass_actool="$(xcrun --find actool 2>/dev/null)"; then
    "$certglass_actool" \
        --compile "$certglass_bundle/Contents/Resources" \
        --platform macosx \
        --minimum-deployment-target 13.0 \
        --app-icon AppIcon \
        App/CertGlass/Assets.xcassets >/dev/null
elif command -v iconutil >/dev/null 2>&1; then
    certglass_iconset="$certglass_root/.build/certglass.iconset"
    mkdir -p "$certglass_iconset"
    cp App/CertGlass/Assets.xcassets/AppIcon.appiconset/*.png "$certglass_iconset/"
    if iconutil -c icns -o "$certglass_bundle/Contents/Resources/CertGlass.icns" "$certglass_iconset" >/dev/null 2>&1; then
        /usr/bin/plutil -insert CFBundleIconFile -string CertGlass.icns "$certglass_bundle/Contents/Info.plist"
    fi
fi

printf 'APPL????' > "$certglass_bundle/Contents/PkgInfo"
/usr/bin/plutil -lint "$certglass_bundle/Contents/Info.plist"
/usr/bin/codesign --force --sign - --entitlements App/CertGlass/CertGlass.entitlements "$certglass_bundle"
/usr/bin/codesign --verify --strict "$certglass_bundle"
echo "已生成本地开发应用：$certglass_bundle"
