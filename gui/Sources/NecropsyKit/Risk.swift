import Foundation

/// The risk vocabulary shared with the pentest module.
///
/// Deliberately mirrors `necropsy/contracts/risk.py`. The whole reason both
/// modules speak it is so one component in the shell renders proposals from
/// either, with the same colour meaning the same thing.
public enum RiskBand: String, Codable, CaseIterable, Sendable {
    case minimal, low, moderate, high, severe

    public init(score: Double) {
        switch score {
        case ..<2: self = .minimal
        case ..<4: self = .low
        case ..<6.5: self = .moderate
        case ..<8.5: self = .high
        default: self = .severe
        }
    }

    /// Ordering for sorts and comparisons; not a colour.
    public var rank: Int { Self.allCases.firstIndex(of: self) ?? 0 }
}

public enum Severity: String, Codable, CaseIterable, Comparable, Sendable {
    case info, low, medium, high, critical

    public var rank: Int { Self.allCases.firstIndex(of: self) ?? 0 }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

/// One reason an action is more (or less) dangerous than the baseline.
public struct RiskFactor: Codable, Hashable, Sendable {
    public let code: String
    public let label: String
    public let weight: Double
    /// +1 aggravating, -1 mitigating. Kept separate from the weight so a
    /// mitigating factor renders in the same list without sign confusion.
    public let direction: Int

    public var isMitigating: Bool { direction < 0 }
    public var signedWeight: Double { weight * Double(direction) }
}

/// How much a behavioural observation is worth, given what it ran on.
public enum EvidenceGrade: String, Codable, Sendable {
    case observed
    case observedEmulated = "observed_emulated"
    case inferred

    /// Whether the panel should show a caveat badge next to the cell.
    public var needsCaveat: Bool { self != .observed }
}
