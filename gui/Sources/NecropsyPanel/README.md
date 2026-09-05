SwiftUI panels for the macOS shell.

Every file here is wrapped in `#if canImport(SwiftUI)` so the package still
builds on Linux, where these compile to nothing. That means CI verifies they
*parse*, but only Xcode type-checks them. See docs/PHASE6.md.
