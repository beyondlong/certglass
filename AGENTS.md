# CertGlass agent 工作约定

## 首先阅读

- `README.md`：运行方式和当前阶段。
- `doc/macOS-证书查看器技术方案.md`：产品及技术约束。
- `doc/开发交接.md`：实现状态、任务边界、接口语义和验收入口。

本次交付是脚手架；`Unimplemented*` 适配器不代表功能已完成。不要使用模拟证书或固定的信任结果替代真实实现。用户没有要求提交时，不执行 git commit、推送或发布。

## 工程约定

- Swift 6，macOS 13+；优先系统框架，不做无关重构、不新增未经当前任务需要的依赖。
- `CertGlassCore` 只放领域模型、协议和通用输入约束，不导入 SwiftUI、Security 或 X509。系统 CryptoKit 仅用于原始 DER 的 SHA-256 身份。
- `CertGlassInfrastructure` 实现容器解码、X.509 解析、信任评估和证书编码，不依赖 Features。
- `CertGlassFeatures` 只依赖 Core；SwiftUI 不直接调用 ASN.1、钥匙串或 SecTrust API。
- 每个文档有独立的 `InspectorStore`；UI 状态位于 MainActor，耗时解析和评估在后台实现，不跨并发边界传递未安全封装的系统对象。
- 服务通过 `InspectorServices` 注入；生产适配器在 `ScaffoldServices.make()` 统一装配。任务完成前同步修改装配入口和交接文档。
- 原始 DER 不可变，指纹和导出都基于原始字节；未知 OID、critical、参数和扩展值不得丢失。
- 解析能力、实际验签结果和系统信任结论分别表达；解析器不认识 critical 扩展，不代表系统拒绝该扩展。
- 信任执行状态、系统结论和多条诊断保持分离。离线配置未确认或评估失败时，不能输出确定的信任结论。
- 生产请求不增加联网或自定义根入口。不要调用钥匙串写入 API、安装证书、修改信任设置或输出私钥内容。
- 文件类型声明修改时同步 `CertificateFileTypes.swift` 和 `App/CertGlass/Info.plist`，保持 Viewer / Alternate。
- Xcode 应用与 SwiftPM 可执行目标共用 `App/CertGlass/CertGlassApp.swift`，不要维护两套应用入口。

## 验证和交付

- 核心逻辑改动先补相关行为或回归测试，避免只测试实现细节。
- 基础验证为 `swift test` 和 `swift build -c release --product CertGlass`；构建配置、模块和依赖变更再运行 `scripts/build-app.sh release universal`。
- 有完整 Xcode 时追加 README 中的应用构建命令；UI、Finder 打开和真实网络行为按技术方案人工验收。
- 当前 CLT 环境的异常和可选兼容脚本见 README；不改全局开发目录、不修补系统 SDK、不安装工具或绕过其他权限来掩盖验证失败。
- 明确报告实际执行的命令、结果、警告和未验证范围。构建、签名或测试替身通过不等于真实证书功能已验收。
- 测试根仅供隔离测试，不安装进钥匙串；固定验证时间。样本不得包含生产私钥或其他秘密。
- 如任务涉及 Maven，必须显式使用 `-Dmaven.repo.local=/Users/yangxinglong/software/apache-maven-3.6.3-bjca/bjca-rep`。

按任务实际复杂度使用 Superpowers；沿用用户的任务分级，不默认创建工作树、启动子代理、提交代码或追加审批流程。
