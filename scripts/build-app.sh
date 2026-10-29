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
printf 'APPL????' > "$certglass_bundle/Contents/PkgInfo"
/usr/bin/plutil -lint "$certglass_bundle/Contents/Info.plist"
/usr/bin/codesign --force --sign - --entitlements App/CertGlass/CertGlass.entitlements "$certglass_bundle"
/usr/bin/codesign --verify --strict "$certglass_bundle"
echo "已生成本地开发应用：$certglass_bundle"
