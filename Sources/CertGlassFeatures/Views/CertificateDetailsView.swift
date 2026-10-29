import CertGlassCore
import SwiftUI

struct CertificateDetailsView: View {
    let certificate: CertificateRecord?

    var body: some View {
        List {
            if let certificate, !certificate.fields.isEmpty {
                ForEach(certificate.fields) { field in
                    VStack(alignment: .leading, spacing: 6) {
                        Text("\(field.chineseName) · \(field.englishName)").font(.headline)
                        if let oid = field.oid { Text("OID: \(oid)").font(.caption) }
                        if let critical = field.critical {
                            Text("critical: \(critical ? "true" : "false")").font(.caption)
                        }
                        Text(field.displayValue).textSelection(.enabled)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                Text("解析完成后显示字段、OID、critical 标志和原始值。")
                    .foregroundStyle(.secondary)
            }
        }
        // HANDOFF D: field search, selected-field raw bytes and copy actions.
    }
}
