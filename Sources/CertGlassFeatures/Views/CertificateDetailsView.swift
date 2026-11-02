import AppKit
import CertGlassCore
import SwiftUI

/// Windows certificate-viewer style details page: a display filter on top,
/// a compact two-column field list, and one read-only text region below that
/// shows the selected field's full multi-line value.
struct CertificateDetailsView: View {
    let certificate: CertificateRecord?
    @State private var searchText = ""
    @State private var filter: FieldFilter = .all
    @State private var selectedFieldID: String?

    enum FieldFilter: String, CaseIterable, Identifiable {
        case all = "<所有>"
        case standard = "标准扩展"
        case critical = "关键扩展"
        case unknown = "未知扩展"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if let certificate, !certificate.fields.isEmpty {
                VSplitView {
                    fieldList(certificate)
                        .frame(minHeight: 140, idealHeight: 240)
                    detailTextPanel(certificate)
                        .frame(minHeight: 130, maxHeight: .infinity)
                }
            } else {
                Text("解析完成后显示证书字段。")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onChange(of: certificate?.id) { _ in
            selectedFieldID = firstVisibleFieldID(certificate)
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            Text("显示(S):")
            Picker("", selection: $filter) {
                ForEach(FieldFilter.allCases) { option in
                    Text(option.rawValue).tag(option)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .frame(width: 130)

            Spacer()

            HStack(spacing: 5) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("搜索", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 190)
                if !searchText.isEmpty {
                    Button("清除") { searchText = "" }
                        .buttonStyle(.borderless)
                }
            }
        }
        .font(.callout)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private func fieldList(_ certificate: CertificateRecord) -> some View {
        List(selection: $selectedFieldID) {
            if filteredFields(certificate).isEmpty {
                Text(searchText.isEmpty ? "当前筛选没有字段。" : "没有匹配的字段。")
                    .foregroundStyle(.secondary)
            }
            ForEach(filteredFields(certificate)) { field in
                fieldRow(field)
                    .tag(field.id)
            }
        }
        .listStyle(.inset)
        .onAppear {
            if selectedFieldID == nil {
                selectedFieldID = firstVisibleFieldID(certificate)
            }
        }
    }

    private func fieldRow(_ field: CertificateField) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            HStack(spacing: 4) {
                if field.critical == true {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .help("关键扩展")
                }
                Text(field.chineseName)
                    .lineLimit(1)
            }
            .frame(width: 200, alignment: .leading)
            Text(displayValue(for: field))
                .lineLimit(1)
                .foregroundStyle(.secondary)
        }
        .font(.callout)
        .padding(.vertical, 1)
        .contentShape(Rectangle())
    }

    private func detailTextPanel(_ certificate: CertificateRecord) -> some View {
        VStack(spacing: 0) {
            Divider()
            if let field = certificate.fields.first(where: { $0.id == selectedFieldID }) {
                VStack(spacing: 0) {
                    if let hint = statusHint(field) {
                        Text(hint)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 10)
                            .padding(.top, 6)
                    }
                    ScrollView {
                        Text(valueText(field))
                            .font(usesMonospacedText(field)
                                ? .system(.callout, design: .monospaced)
                                : .callout)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }
                    HStack(spacing: 12) {
                        Spacer()
                        if let raw = field.rawValue, !raw.isEmpty {
                            copyButton("复制十六进制") { raw.hexString }
                        }
                        copyButton("复制") { valueText(field) }
                    }
                    .padding(.horizontal, 10)
                    .padding(.bottom, 8)
                }
            } else {
                Text("选择上方字段查看详细值。")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    private func statusHint(_ field: CertificateField) -> String? {
        guard let detail = extensionDetail(for: field) else { return nil }
        switch detail.interpretationStatus {
        case .interpreted: return nil
        case .rawOnly: return "应用未识别此扩展，仅显示原始值。"
        case .malformed: return "扩展编码异常，原始值仍然保留。"
        }
    }

    /// Full multi-line value in the Windows viewer's text style: structured
    /// indented lines for decoded extensions, hex blocks for byte fields.
    private func valueText(_ field: CertificateField) -> String {
        if let detail = extensionDetail(for: field) {
            if !detail.items.isEmpty {
                var lines: [String] = []
                let numbered = detail.items.count > 1
                for (index, item) in detail.items.enumerated() {
                    itemLines(item, level: 0, prefix: numbered ? "[\(index + 1)]" : "", into: &lines)
                }
                return lines.joined(separator: "\n")
            }
            return Self.hexBlock(detail.rawValue, asciiColumn: true)
        }
        if usesHexBlock(field), let raw = field.rawValue, !raw.isEmpty {
            return Self.hexBlock(raw)
        }
        let displayValue = displayValue(for: field)
        return displayValue.isEmpty ? "（无值）" : displayValue
    }

    /// Keep the details tab stable even for records created by a legacy or
    /// partial parser that retained the Date values but did not refresh the
    /// corresponding field text.
    private func displayValue(for field: CertificateField) -> String {
        switch field.id {
        case "notValidBefore":
            return certificate?.notValidBefore.map(CertificateDateFormatting.string(from:))
                ?? field.displayValue
        case "notValidAfter":
            return certificate?.notValidAfter.map(CertificateDateFormatting.string(from:))
                ?? field.displayValue
        default:
            return field.displayValue
        }
    }

    private func itemLines(
        _ item: CertificateExtensionItem, level: Int, prefix: String, into lines: inout [String]
    ) {
        let indent = String(repeating: "    ", count: level)
        let head = indent + prefix + item.chineseName
        lines.append(item.displayValue.isEmpty ? head + "：" : head + "：" + item.displayValue)
        for child in item.children {
            itemLines(child, level: level + 1, prefix: "", into: &lines)
        }
    }

    private func usesHexBlock(_ field: CertificateField) -> Bool {
        field.id == "serialNumber" || field.id == "publicKey" || field.id == "signature"
    }

    private func usesMonospacedText(_ field: CertificateField) -> Bool {
        if usesHexBlock(field) { return true }
        if let detail = extensionDetail(for: field) { return detail.items.isEmpty }
        return false
    }

    /// 16 bytes per line, split into two groups of 8 like the Windows viewer,
    /// with an optional printable-ASCII column.
    static func hexBlock(_ data: Data, asciiColumn: Bool = false) -> String {
        let bytes = [UInt8](data)
        var lines: [String] = []
        var index = 0
        while index < bytes.count {
            let chunk = bytes[index..<min(index + 16, bytes.count)]
            let first = chunk.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " ")
            let second = chunk.dropFirst(8).map { String(format: "%02X", $0) }.joined(separator: " ")
            var line = second.isEmpty ? first : first + "  " + second
            if asciiColumn {
                line += "  " + chunk.map { byte in
                    (0x20...0x7E).contains(byte) ? String(UnicodeScalar(byte)) : "."
                }.joined()
            }
            lines.append(line)
            index += 16
        }
        return lines.joined(separator: "\n")
    }

    private func filteredFields(_ certificate: CertificateRecord) -> [CertificateField] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return certificate.fields.filter { field in
            let isExtension = field.id.hasPrefix("extension.")
            // "Standard" vs "unknown" is about the OID's origin: publicly
            // standardized arcs (X.509 2.5.29.*, PKIX 1.3.6.1.5.5.7.1.*) versus
            // vendor/CA-proprietary arcs — independent of whether this app
            // implements an interpretation for the extension.
            switch filter {
            case .all: break
            case .standard:
                guard isExtension, extensionDetail(for: field)?.isPublicStandard == true else { return false }
            case .critical:
                guard isExtension, field.critical == true else { return false }
            case .unknown:
                guard isExtension, extensionDetail(for: field)?.isPublicStandard == false else { return false }
            }
            guard !query.isEmpty else { return true }
            return field.chineseName.lowercased().contains(query)
                || field.englishName.lowercased().contains(query)
                || (field.oid?.lowercased().contains(query) ?? false)
                || field.displayValue.lowercased().contains(query)
        }
    }

    private func firstVisibleFieldID(_ certificate: CertificateRecord?) -> String? {
        guard let certificate else { return nil }
        return filteredFields(certificate).first?.id ?? certificate.fields.first?.id
    }

    private func extensionDetail(for field: CertificateField) -> CertificateExtensionDetail? {
        guard field.id.hasPrefix("extension.") else { return nil }
        let id = String(field.id.dropFirst("extension.".count))
        return certificate?.extensionDetails.first(where: { $0.id == id })
    }

    private func copyButton(_ title: String, value: @escaping () -> String) -> some View {
        Button(title) {
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            pasteboard.setString(value(), forType: .string)
        }
        .buttonStyle(.borderless)
        .font(.caption)
    }
}
