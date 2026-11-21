import Foundation
import Darwin

enum LANAddressResolver {
    /// One usable IPv4 address on this Mac.
    struct Candidate: Equatable, Hashable {
        let interface: String
        let ip: String

        /// Tailscale, WireGuard, ZeroTier and most other VPNs (virtual private
        /// networks) appear on macOS as utun/ipsec/ppp/wg/zt interfaces, or use
        /// the 100.64.0.0/10 carrier-grade NAT (network address translation)
        /// range that Tailscale assigns.
        var isVPN: Bool {
            let vpnPrefixes = ["utun", "ipsec", "ppp", "wg", "zt", "tun", "tap"]
            return vpnPrefixes.contains { interface.hasPrefix($0) } || LANAddressResolver.isCGNAT(ip)
        }

        var label: String {
            isVPN ? "\(ip) — VPN (\(interface))" : "\(ip) — \(interface)"
        }
    }

    /// UserDefaults key for the address the user picked for the QR code.
    /// Absent means automatic (primaryIPv4).
    static let pairingHostDefaultsKey = "wireless.pairingHost"

    /// Every non-loopback, non-link-local IPv4 address that is up, LAN first.
    static func allIPv4() -> [Candidate] {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return [] }
        defer { freeifaddrs(ifaddrPtr) }

        var candidates: [Candidate] = []
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = ptr {
            let flags = Int32(cur.pointee.ifa_flags)
            if let addr = cur.pointee.ifa_addr {
                let family = addr.pointee.sa_family
                if (flags & IFF_UP) != 0,
                   (flags & IFF_LOOPBACK) == 0,
                   family == sa_family_t(AF_INET) {
                    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    let rc = getnameinfo(
                        addr,
                        socklen_t(addr.pointee.sa_len),
                        &host, socklen_t(host.count),
                        nil, 0,
                        NI_NUMERICHOST
                    )
                    if rc == 0, let ip = String(validatingUTF8: host),
                       !isLoopback(ip), !isLinkLocal(ip) {
                        let name = String(cString: cur.pointee.ifa_name)
                        let candidate = Candidate(interface: name, ip: ip)
                        if !candidates.contains(candidate) { candidates.append(candidate) }
                    }
                }
            }
            ptr = cur.pointee.ifa_next
        }
        // LAN before VPN; keep discovery order otherwise.
        return candidates.filter { !$0.isVPN } + candidates.filter { $0.isVPN }
    }

    /// Returns the first non-loopback, non-link-local IPv4 address from `getifaddrs`,
    /// preferring `en0` (typical Wi-Fi / Ethernet) when present.
    static func primaryIPv4() -> String? {
        let candidates = allIPv4()
        if let en0 = candidates.first(where: { $0.interface == "en0" }) { return en0.ip }
        if let enN = candidates.first(where: { $0.interface.hasPrefix("en") }) { return enN.ip }
        return candidates.first?.ip
    }

    /// The address to put in the pairing QR code: the user's pick when it is
    /// still present on this Mac (for example the Tailscale address), else
    /// the primary LAN address.
    static func pairingIPv4(defaults: UserDefaults = .standard) -> String? {
        if let chosen = defaults.string(forKey: pairingHostDefaultsKey),
           allIPv4().contains(where: { $0.ip == chosen }) {
            return chosen
        }
        return primaryIPv4()
    }

    /// 100.64.0.0/10 — Tailscale's address range.
    static func isCGNAT(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        return parts[0] == 100 && (64...127).contains(parts[1])
    }

    static func isLoopback(_ ip: String) -> Bool {
        ip == "127.0.0.1" || ip == "::1" || ip.hasPrefix("127.")
    }

    static func isLinkLocal(_ ip: String) -> Bool {
        ip.hasPrefix("169.254.")
    }
}
