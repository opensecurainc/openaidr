// Locate a real visible window for screencapture. No accessibility database edits.
import CoreGraphics
import Foundation
import Vision

if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--text" {
    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.recognitionLanguages = ["en-US"]
    do {
        try VNImageRequestHandler(url: URL(fileURLWithPath: CommandLine.arguments[2])).perform([request])
        print((request.results ?? []).compactMap { $0.topCandidates(1).first?.string }.joined(separator: "\n"))
        exit(0)
    } catch {
        fputs("Could not read window text: \(error)\n", stderr)
        exit(1)
    }
}

let owner = CommandLine.arguments[1]
let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
for window in windows {
    let name = window[kCGWindowOwnerName as String] as? String ?? ""
    let title = window[kCGWindowName as String] as? String ?? ""
    let layer = window[kCGWindowLayer as String] as? Int ?? -1
    if layer == 0 && (name == owner || title == owner),
       let id = window[kCGWindowNumber as String] as? UInt32,
       let bounds = window[kCGWindowBounds as String] as? [String: Any],
       let width = bounds["Width"] as? Double, width > 100 {
        print(id)
        exit(0)
    }
}
fputs("No visible window for \(owner). A logged-in desktop and screen capture access are required.\n", stderr)
exit(1)
