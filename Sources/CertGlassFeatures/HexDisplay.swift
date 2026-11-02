import Foundation

extension Data {
    /// Uppercase-free hex used for serial numbers and raw extension bytes.
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
