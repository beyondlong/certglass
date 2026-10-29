import Foundation

public struct InputLimits: Sendable, Equatable {
    public static let `default` = InputLimits(maximumFileBytes: 10 * 1_024 * 1_024, maximumCertificates: 100)
    public let maximumFileBytes: Int
    public let maximumCertificates: Int

    public init(maximumFileBytes: Int, maximumCertificates: Int) {
        precondition(maximumFileBytes > 0 && maximumCertificates > 0)
        self.maximumFileBytes = maximumFileBytes
        self.maximumCertificates = maximumCertificates
    }
}

public struct DocumentInput: Sendable, Equatable {
    public let data: Data
    public let displayName: String?

    public init(data: Data, displayName: String? = nil, limits: InputLimits = .default) throws {
        guard !data.isEmpty else { throw CertGlassError.emptyInput }
        guard data.count <= limits.maximumFileBytes else {
            throw CertGlassError.inputTooLarge(maximumBytes: limits.maximumFileBytes)
        }
        self.data = data
        self.displayName = displayName
    }
}

public enum CertGlassError: Error, Sendable, Equatable, LocalizedError {
    case emptyInput
    case inputTooLarge(maximumBytes: Int)
    case tooManyCertificates(maximumCount: Int)
    case noCertificates
    case unsupportedFile
    case readOnlyDocument
    case notImplemented(feature: String)

    public var errorDescription: String? {
        switch self {
        case .emptyInput: "文件为空。"
        case .inputTooLarge(let maximum): "文件超过大小限制（\(maximum) 字节）。"
        case .tooManyCertificates(let maximum): "容器中的证书超过数量限制（\(maximum) 张）。"
        case .noCertificates: "容器中没有证书。"
        case .unsupportedFile: "无法读取为普通证书文件。"
        case .readOnlyDocument: "CertGlass 以只读方式打开文件，请使用独立导出功能。"
        case .notImplemented(let feature): "\(feature)尚未实现；当前版本为基础脚手架。"
        }
    }
}
