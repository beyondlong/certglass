# CertGlass

<p align="center"><img src="Brand/generated/CertGlassWordmark.png" alt="CertGlass" width="520"></p>

A native macOS certificate and trust-chain inspector.

原生、离线的 macOS X.509 证书与信任链查看器。

CertGlass 由 Certificate（证书）与 Looking Glass（观察镜）组合而来，寓意看清数字证书的字段、用途与信任链。

品牌资产位于 [`Brand/`](Brand/)：应用图标不嵌入文字，GitHub 和 README 使用独立的 `CertGlass` 横向 wordmark；发布物另提供深色、浅色背景版本。

## 当前阶段

四个核心任务（容器解码、X.509 解析、离线信任评估、导出与页面交互）已实现并通过单元测试，`ScaffoldServices.make()` 已装配全部真实适配器：

- 单窗口证书集合：Finder 双击、Dock 拖放、应用内打开面板和窗口拖放打开的证书文件都**追加**到当前窗口左侧的"证书集合"，跨文件按 SHA-256 去重，不再一文件一窗口；打开失败时已有集合保留。
- 打开 DER / PEM / PKCS#7（DER 与 PEM）文件后解码证书集合，保留原始字节与遇到顺序；无 PEM 头的裸 Base64 证书文本（Windows 导出、部分 CA 门户格式）也受支持；PEM 私钥块、非法 Base64、截断数据等有独立错误提示。
- X.509 字段、OID、critical 标志、算法参数与未知扩展值全部按原始值保留；RSA、ECDSA、Ed25519、RSA-PSS 完整解析，SM2/SM3 等不支持算法降级为部分解析展示。
- 使用 Basic X.509 策略执行本机信任评估（不验证吊销列表），网络补链禁用并确认后才评估；执行状态、系统结论与诊断分别表达，路径完整性/锚点状态由实际链结构推导。
- 常用 RFC 5280 扩展（基本约束、密钥用法、扩展密钥用法、SAN/IAN、SKI/AKI、CRL 分发点、AIA、证书策略、名称约束、主体目录属性）提供中文结构化解释；未知扩展保留 OID、critical、原始值和只读 DER 摘要。
- 详细信息页为“字段列表 + 选中字段详情”布局：分组（基本字段 / 算法与公钥 / 扩展 / 签名与原始值）、搜索与扩展筛选、解释与原始值分区、多级复制；概览与路径页显示“声明用途”卡片（证书声明，非系统信任结论）。
- 支持字段搜索、复制（值 / 完整条目 / 原始十六进制）、路径节点详情，以及 DER / PEM 导出（保存面板写入，不写回原文件）。

应用级人工验收（Finder 打开、真实证书对照、导出面板、macOS 13 运行等）尚未完成，详见 [开发交接](doc/开发交接.md) 第 6 节的未验证范围。应用仍保持只读、离线，不安装证书、不修改钥匙串、不处理私钥。

## 开发和运行

推荐完整 Xcode 16+、Swift 6、macOS 开发环境。应用部署目标为 macOS 13，Swift Testing 测试运行器以实际工具链要求为准。

打开 `CertGlass.xcodeproj`，选择 `CertGlass` scheme。运行签名版本前，在 Signing & Capabilities 中选择自己的开发团队。项目解析依赖由 SwiftPM 管理（swift-certificates、SwiftASN1、swift-crypto，见 `Package.swift` 与 `Package.resolved`），首次构建时自动拉取。

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
Sources/CertGlassInfrastructure/ 解码、解析、信任评估和导出适配器
Sources/CertGlassFeatures/      文档适配、窗口状态和 SwiftUI 页面
Tests/                         容器、解析、信任、导出与状态协调测试
scripts/                       本地打包及可选 CLT 兼容入口
doc/                           技术方案、实施计划与开发交接
```

`Core` 不依赖其他项目模块；`Infrastructure` 和 `Features` 分别依赖 `Core`；应用入口装配二者。新增常规 Swift 源码放入相应 SwiftPM 目录，不必逐个编辑 Xcode 工程；新增 `App/CertGlass/` 源文件则需同步 Xcode Sources。

## 接手入口

1. 阅读 [AGENTS.md](AGENTS.md) 和 [技术方案](doc/macOS-证书查看器技术方案.md)。
2. 阅读 [开发交接](doc/开发交接.md) 了解实现状态与未验证范围。
3. 后续改进先补相应行为测试，再修改 `ScaffoldServices.make()` 中对应适配器。
4. 更新交接状态、运行实际验证，明确报告未验证范围。

首版保持只读、离线，不安装证书、不修改钥匙串、不处理私钥。
