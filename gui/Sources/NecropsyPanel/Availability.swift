import Foundation

/// Whether this build actually contains the SwiftUI panels.
///
/// Every view in this target is wrapped in `#if canImport(SwiftUI)` so the
/// package builds on Linux, where CI can compile and test `NecropsyKit`. That
/// leaves the target empty off Apple platforms, which Swift will not emit a
/// module for -- hence this declaration, which is also the honest answer to
/// "did the panels get compiled into this binary?".
public enum NecropsyPanelAvailability: Sendable {
    /// True on Apple platforms, where the SwiftUI views are compiled in.
    public static var isAvailable: Bool {
        #if canImport(SwiftUI)
        return true
        #else
        return false
        #endif
    }

    public static var explanation: String {
        isAvailable
            ? "SwiftUI panels are compiled into this build."
            : "SwiftUI is unavailable on this platform; NecropsyKit still works headlessly."
    }
}
