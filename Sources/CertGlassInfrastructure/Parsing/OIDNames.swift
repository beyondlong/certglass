import CertGlassCore
import Foundation
import SwiftASN1

/// OID names used for display. Unknown OIDs keep their dotted form and raw
/// bytes; an entry here is display-only and does not imply any support claim.
enum OIDNames {
    static let distinguishedNameAttributes: [String: (chinese: String, english: String)] = [
        "2.5.4.3": ("通用名称", "Common Name"),
        "2.5.4.4": ("简称", "Serial Number"),
        "2.5.4.5": ("序列号", "Serial Number"),
        "2.5.4.6": ("国家", "Country"),
        "2.5.4.7": ("地区", "Locality"),
        "2.5.4.8": ("省/州", "State or Province"),
        "2.5.4.9": ("街道", "Street Address"),
        "2.5.4.10": ("组织", "Organization"),
        "2.5.4.11": ("部门", "Organizational Unit"),
        "2.5.4.12": ("职务", "Title"),
        "1.2.840.113549.1.9.1": ("电子邮件", "Email Address"),
        "0.9.2342.19200300.100.1.25": ("域组件", "Domain Component")
    ]

    static let attributeShortNames: [String: String] = [
        "2.5.4.3": "CN",
        "2.5.4.5": "serialNumber",
        "2.5.4.6": "C",
        "2.5.4.7": "L",
        "2.5.4.8": "ST",
        "2.5.4.9": "street",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
        "2.5.4.12": "title",
        "1.2.840.113549.1.9.1": "emailAddress",
        "0.9.2342.19200300.100.1.25": "DC"
    ]

    static let algorithms: [String: String] = [
        "1.2.840.113549.1.1.1": "RSA",
        "1.2.840.113549.1.1.4": "MD5 with RSA",
        "1.2.840.113549.1.1.5": "SHA-1 with RSA",
        "1.2.840.113549.1.1.10": "RSA-PSS",
        "1.2.840.113549.1.1.11": "SHA-256 with RSA",
        "1.2.840.113549.1.1.12": "SHA-384 with RSA",
        "1.2.840.113549.1.1.13": "SHA-512 with RSA",
        "1.2.840.10045.2.1": "ECDSA",
        "1.2.840.10045.4.1": "ECDSA with SHA-1",
        "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3": "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4": "ECDSA with SHA-512",
        "1.3.101.112": "Ed25519",
        "1.3.101.113": "Ed448",
        "1.2.156.10197.1.501": "SM2 with SM3",
        "1.2.156.10197.1.504": "SM2 with SM3 (key exchange)"
    ]

    static let curveParameters: [String: String] = [
        "1.2.840.10045.3.1.7": "P-256",
        "1.3.132.0.34": "P-384",
        "1.3.132.0.35": "P-521",
        "1.2.156.10197.1.301": "SM2"
    ]

    static let extensions: [String: (chinese: String, english: String)] = [
        "2.5.29.9": ("主体目录属性", "Subject Directory Attributes"),
        "2.5.29.14": ("主题密钥标识符", "Subject Key Identifier"),
        "2.5.29.15": ("密钥用法", "Key Usage"),
        "2.5.29.17": ("主题备用名称", "Subject Alternative Name"),
        "2.5.29.18": ("颁发者备用名称", "Issuer Alternative Name"),
        "2.5.29.19": ("基本约束", "Basic Constraints"),
        "2.5.29.30": ("名称约束", "Name Constraints"),
        "2.5.29.31": ("CRL 分发点", "CRL Distribution Points"),
        "2.5.29.32": ("证书策略", "Certificate Policies"),
        "2.5.29.35": ("颁发机构密钥标识符", "Authority Key Identifier"),
        "2.5.29.37": ("扩展密钥用法", "Extended Key Usage"),
        "1.3.6.1.5.5.7.1.1": ("颁发机构信息访问", "Authority Information Access")
    ]

    /// Whether the extension OID belongs to a publicly standardized arc:
    /// X.509 defined extensions (`2.5.29.*`, ISO/ITU) or PKIX private
    /// extensions (`1.3.6.1.5.5.7.1.*`, RFC 5280 AIA/SIA/QC statements).
    /// Vendor and enterprise arcs (Netscape `2.16.840.*`, Microsoft/IANA
    /// enterprise `1.3.6.1.4.1.*`, CA-proprietary `1.2.*`) are not standard.
    static func isPublicStandardExtension(_ oid: String) -> Bool {
        oid.hasPrefix("2.5.29.") || oid.hasPrefix("1.3.6.1.5.5.7.1.")
    }

    static let extendedKeyUsages: [String: (chinese: String, english: String)] = [
        "1.3.6.1.5.5.7.3.1": ("服务器身份验证", "serverAuth"),
        "1.3.6.1.5.5.7.3.2": ("客户端身份验证", "clientAuth"),
        "1.3.6.1.5.5.7.3.3": ("代码签名", "codeSigning"),
        "1.3.6.1.5.5.7.3.4": ("电子邮件保护", "emailProtection"),
        "1.3.6.1.5.5.7.3.5": ("IPsec 端系统", "ipsecEndSystem"),
        "1.3.6.1.5.5.7.3.6": ("IPsec 隧道终止", "ipsecTunnel"),
        "1.3.6.1.5.5.7.3.7": ("IPsec 用户", "ipsecUser"),
        "1.3.6.1.5.5.7.3.8": ("时间戳", "timeStamping"),
        "1.3.6.1.5.5.7.3.9": ("OCSP 响应签名", "OCSPSigning"),
        "2.5.29.37.0": ("任意扩展用途", "anyExtendedKeyUsage"),
        "1.3.6.1.4.1.311.10.3.1": ("Microsoft 内核代码签名", "Microsoft Kernel Code Signing")
    ]

    static let accessMethods: [String: (chinese: String, english: String)] = [
        "1.3.6.1.5.5.7.48.1": ("OCSP 服务", "OCSP"),
        "1.3.6.1.5.5.7.48.2": ("CA 证书签发者", "CA Issuers"),
        "1.3.6.1.5.5.7.48.5": ("CRL 分发", "CRL Distribution")
    ]

    static let policyQualifiers: [String: (chinese: String, english: String)] = [
        "1.3.6.1.5.5.7.2.1": ("CPS 指针", "CPS URI"),
        "1.3.6.1.5.5.7.2.2": ("用户通知", "User Notice")
    ]

    static func algorithmName(oid: String, parametersDER: Data?) -> String {
        if oid == "1.2.840.10045.2.1", let parameters = parametersDER,
           let curve = curveOID(ofDER: parameters) {
            let curveName = curveParameters[curve] ?? curve
            return "ECDSA（\(curveName)）"
        }
        return algorithms[oid] ?? "未知算法（\(oid)）"
    }

    private static func curveOID(ofDER der: Data) -> String? {
        guard let node = try? DER.parse([UInt8](der)),
              node.identifier.tagClass == .universal, node.identifier.tagNumber == 6,
              let oid = try? ASN1ObjectIdentifier(derEncoded: node) else { return nil }
        return oid.description
    }
}
