# CertGlass

A native macOS certificate and trust-chain inspector.

原生、离线的 macOS X.509 证书与信任链查看器。

CertGlass 由 Certificate（证书）与 Looking Glass（观察镜）组合而来，寓意看清数字证书的字段、用途与信任链。

## 当前阶段

这是**基础脚手架**，不是功能完整的证书查看器。已有原生只读文档入口、模块接口、三页界面、状态协调、行为测试和构建脚本。打开文件后会明确提示“容器解码尚未实现”；不会生成模拟证书、证书链或信任结论。

真实 DER / PEM / PKCS#7 解码、X.509 字段解析、macOS 信任评估、搜索复制及导出由后续任务实现。详见 [开发交接](doc/开发交接.md)。

## 开发和运行

推荐完整 Xcode 16+、Swift 6、macOS 开发环境。应用部署目标为 macOS 13，Swift Testing 测试运行器以实际工具链要求为准。

打开 `CertGlass.xcodeproj`，选择 `CertGlass` scheme。运行签名版本前，在 Signing & Capabilities 中选择自己的开发团队。项目当前没有第三方依赖，不需要安装生成器或包管理工具。

在项目根目录执行：

```bash
swift test
swift build --product CertGlass
scripts/build-app.sh release universal
```

最后一个命令生成 `build/release-universal/CertGlass.app`，包含 Apple Silicon 和 Intel 两个架构，并使用本地 ad-hoc 签名。它用于本机开发验证，不是 Developer ID 签名或公证发行包。可用 `scripts/build-app.sh debug native` 生成当前架构的 Debug 应用。

Xcode 应用目标构建：

```bash
xcodebuild -project CertGlass.xcodeproj -scheme CertGlass \
  -configuration Debug -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO build
```

包测试由 `swift test` 运行；当前应用 scheme 没有 UI 测试 target，不能把 `xcodebuild build` 当作测试通过。

当前机器只有 Command Line Tools，且存在构建框架路径和 Testing overlay 缺失问题。如普通 `swift` 在进入项目编译前失败，使用这个**显式的本机兼容入口**：

```bash
scripts/swift-clt.sh test
CERTGLASS_SWIFT="$PWD/scripts/swift-clt.sh" scripts/build-app.sh release universal
```

若在 Codex 受限执行环境遇到 `sandbox-exec: sandbox_apply: Operation not permitted`，仅对上述命令添加 `CERTGLASS_DISABLE_SWIFTPM_SANDBOX=1`。完整 Xcode 环境优先使用普通命令。兼容入口不修改系统工具链、信任设置或应用沙箱权限；详细原因和本次验证记录见交接文档。

## 目录与依赖方向

```text
App/CertGlass/                  应用入口、文件类型注册、沙箱权限
CertGlass.xcodeproj/            原生 macOS 应用工程与共享 scheme
Sources/CertGlassCore/          原始数据、模型、错误与服务协议
Sources/CertGlassInfrastructure/ 待替换的解析、信任和导出适配器
Sources/CertGlassFeatures/      文档适配、窗口状态和 SwiftUI 页面
Tests/                         领域契约和状态协调测试
scripts/                       本地打包及可选 CLT 兼容入口
doc/                           技术方案、实施计划与开发交接
```

`Core` 不依赖其他项目模块；`Infrastructure` 和 `Features` 分别依赖 `Core`；应用入口装配二者。新增常规 Swift 源码放入相应 SwiftPM 目录，不必逐个编辑 Xcode 工程；新增 `App/CertGlass/` 源文件则需同步 Xcode Sources。

## 接手入口

1. 阅读 [AGENTS.md](AGENTS.md) 和 [技术方案](doc/macOS-证书查看器技术方案.md)。
2. 阅读 [开发交接](doc/开发交接.md)，选择任务 A、B、C 或 D。
3. 按接口实现并补充相应测试，在 `ScaffoldServices.make()` 中替换对应适配器。
4. 更新交接状态、运行实际验证，再移除对应的占位提示。

首版保持只读、离线，不安装证书、不修改钥匙串、不处理私钥。
