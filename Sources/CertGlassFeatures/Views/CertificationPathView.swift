import CertGlassCore
import SwiftUI

struct CertificationPathView: View {
    let report: ChainReport?

    var body: some View {
        List {
            if let report, !report.certificates.isEmpty {
                ForEach(report.certificates) { certificate in
                    Label(certificate.subject?.displayValue ?? certificate.id.sha256, systemImage: "doc.badge.gearshape")
                    ForEach(certificate.diagnostics) { diagnostic in
                        Text(diagnostic.message).font(.caption)
                    }
                }
            } else {
                Text("系统评估完成后显示实际返回的证书路径，不生成推测节点。")
                    .foregroundStyle(.secondary)
            }
        }
        // HANDOFF D: node details, path completeness and overall diagnostics.
    }
}
