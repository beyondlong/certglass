#!/bin/bash
# Opt-in compatibility runner for this machine's incomplete Swift 6.2 CLT layout.
# Normal Xcode installations should use `swift` directly.
set -euo pipefail

certglass_command="${1:-}"
case "$certglass_command" in build|test) shift ;; *) echo "用法：$0 build|test [SwiftPM 参数]" >&2; exit 2 ;; esac
certglass_root="$(cd "$(dirname "$0")/.." && pwd)"
certglass_developer="$(/usr/bin/xcode-select -p)"
certglass_sdk="${CERTGLASS_SDKROOT:-$(/usr/bin/xcrun --show-sdk-path)}"
certglass_frameworks="$certglass_developer/Library/Developer/Frameworks"
certglass_pm="$certglass_developer/usr/lib/swift/pm"

if [[ ! -x "$certglass_developer/usr/bin/swift-$certglass_command" || ! -d "$certglass_pm/SwiftBuild.framework" ]]; then
    echo "当前开发工具不适用此 CLT 兼容入口；请使用完整 Xcode 的 swift。" >&2
    exit 1
fi

export SDKROOT="$certglass_sdk"
export CLANG_MODULE_CACHE_PATH="$certglass_root/.build/module-cache"
export DYLD_FRAMEWORK_PATH="$certglass_pm:$certglass_pm/SwiftBuild.framework/Versions/A/PlugIns/SWBBuildService.bundle/Contents/Frameworks:$certglass_frameworks${DYLD_FRAMEWORK_PATH:+:$DYLD_FRAMEWORK_PATH}"
certglass_options=(
    --package-path "$certglass_root" --sdk "$certglass_sdk"
    --cache-path "$certglass_root/.build/cache"
    --config-path "$certglass_root/.build/config"
    --security-path "$certglass_root/.build/security"
    -Xswiftc -module-cache-path -Xswiftc "$CLANG_MODULE_CACHE_PATH"
    -Xswiftc -F -Xswiftc "$certglass_frameworks"
    -Xswiftc -plugin-path -Xswiftc "$certglass_developer/usr/lib/swift/host/plugins/testing"
    -Xswiftc -Xfrontend -Xswiftc -disable-cross-import-overlays
    -Xlinker -rpath -Xlinker "$certglass_frameworks"
)
# This bypasses only SwiftPM's nested manifest sandbox in restricted executors.
# It does not change macOS settings or the application's App Sandbox entitlements.
if [[ "${CERTGLASS_DISABLE_SWIFTPM_SANDBOX:-0}" == 1 ]]; then
    certglass_options+=(--disable-sandbox)
fi
exec "$certglass_developer/usr/bin/swift-$certglass_command" "${certglass_options[@]}" "$@"
