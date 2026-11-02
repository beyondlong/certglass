import Foundation

/// Stable certificate timestamp formatting used by the parser and all views.
/// Certificate validity values are encoded in UTC; keeping the display in UTC
/// avoids changing the value when the app is opened in another time zone.
public enum CertificateDateFormatting {
    public static func string(from date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }
}
