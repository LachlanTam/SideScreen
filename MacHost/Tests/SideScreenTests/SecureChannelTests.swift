import CryptoKit
import XCTest
@testable import SideScreen

/// Golden vectors shared with the Android SecureChannelTest. They were made
/// with an independent Python reference implementation (HKDF per RFC 5869,
/// AES-GCM from `cryptography`), so both apps are checked against the same
/// numbers rather than against each other.
final class SecureChannelTests: XCTestCase {
    private let token = Data((0..<32).map { UInt8($0) })
    private let clientNonce = Data((0x40..<0x60).map { UInt8($0) })
    private let hostNonce = Data((0x80..<0xA0).map { UInt8($0) })

    private var clientHello: Data {
        var out = Data(HandshakeCodec.secureRequestMagic)
        out.append(clientNonce)
        let name = Data("Tab S10 FE".utf8)
        out.append(UInt8(name.count))
        out.append(name)
        return out
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private func keys() -> SecureChannel.SessionKeys {
        SecureChannel.deriveSessionKeys(token: token, clientHello: clientHello, clientNonce: clientNonce, hostNonce: hostNonce)
    }

    func testSessionTranscriptAndProofsMatchVectors() {
        let k = keys()
        XCTAssertEqual(hex(k.transcriptHash), "2e4ee87ead329c7d8f621421e13e5d1a76a4d6a6f559ccc16e3b3bdeeaec3583")
        XCTAssertEqual(hex(k.hostProof), "721dfbda888b3412effc8af1c206f2144de687091be24cf8e4db02820556a494")
        XCTAssertEqual(hex(k.clientProof), "a85b0e14effa12afe00b086094019458bb9bfa5dadc0bd280055c93cd3a07d45")
    }

    func testRecordsMatchVectors() throws {
        let k = keys()
        let c2s = try RecordSealer.sealRecord(Data("hello".utf8), key: k.clientToHost, counter: 0)
        XCTAssertEqual(hex(c2s), "00000015" + "367b29dcdd6584c9c8b4e66aef18f6f5dbf4ff79f5")
        let s2c = try RecordSealer.sealRecord(Data([1, 2, 3]), key: k.hostToClient, counter: 1)
        XCTAssertEqual(hex(s2c), "00000013" + "6b92d3e4d64216d2100502ab4d0e554df56769")
    }

    func testOpenerReassemblesSplitRecordsAndRejectsReplay() throws {
        let k = keys()
        let sealer = RecordSealer(key: k.clientToHost)
        var wire = Data()
        try sealer.seal(Data("one".utf8)) { wire.append($0) }
        try sealer.seal(Data("two".utf8)) { wire.append($0) }

        let opener = RecordOpener(key: k.clientToHost)
        var plain = Data()
        for byte in wire { plain.append(try opener.feed(Data([byte]))) }
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "onetwo")

        // Feeding the first record again is a replay: wrong counter, must fail.
        let first = wire.prefix(4 + 3 + 16)
        XCTAssertThrowsError(try opener.feed(Data(first)))
    }

    func testTamperedRecordFails() throws {
        let k = keys()
        var wire = try RecordSealer.sealRecord(Data("hello".utf8), key: k.hostToClient, counter: 0)
        wire[wire.count - 1] ^= 0x01
        XCTAssertThrowsError(try RecordOpener(key: k.hostToClient).feed(wire))
    }

    func testWrongTokenGivesDifferentProof() {
        let wrong = SecureChannel.deriveSessionKeys(
            token: Data(repeating: 0xFF, count: 32), clientHello: clientHello,
            clientNonce: clientNonce, hostNonce: hostNonce
        )
        XCTAssertNotEqual(wrong.clientProof, keys().clientProof)
    }

    func testPairingKeysMatchVectors() throws {
        let th = Data(SHA256.hash(data: Data("pairing transcript".utf8)))
        XCTAssertEqual(hex(th), "12593b928df26a62f40a7c8781b2883556fd1a98c150937530215d81763e77b6")
        let k = SecureChannel.derivePairingKeys(sharedSecret: Data(repeating: 0x11, count: 32), code: "12345678", transcriptHash: th)
        XCTAssertEqual(hex(k.clientProof), "655aff08b3cd95161f53bd75c2fe3b21d8cf9ab596349b8cb1968fce790b1c0c")
        let payload = HandshakeCodec.encodePairingPayload(token: token, macName: "Mac")
        let sealed = try SecureChannel.sealPairingPayload(payload, keys: k)
        XCTAssertEqual(
            hex(sealed),
            "d05c9485cd9ac8477f3c82edbca808615a591b4fd3a84c2ee95049e4fe5365cd0a1a8cf46d761f12cea28a8558db422d29a933d8"
        )
    }

    func testParseSecureHello() throws {
        let parsed = try HandshakeCodec.parseSecureHello(clientHello)
        XCTAssertEqual(parsed.clientNonce, clientNonce)
        XCTAssertEqual(parsed.deviceName, "Tab S10 FE")
        XCTAssertEqual(parsed.raw, clientHello)
    }

    func testParseSecurePairingRequest() throws {
        let pub = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        var bytes = Data(HandshakeCodec.securePairingRequestMagic)
        bytes.append(pub)
        bytes.append(3)
        bytes.append(contentsOf: Array("Tab".utf8))
        let parsed = try HandshakeCodec.parseSecurePairingRequest(bytes)
        XCTAssertEqual(parsed.clientPublicKey, pub)
        XCTAssertEqual(parsed.deviceName, "Tab")
        XCTAssertEqual(HandshakeCodec.securePairingExtraPrefixLen, 33)
    }

    func testCGNATDetection() {
        XCTAssertTrue(LANAddressResolver.isCGNAT("100.101.102.103"))
        XCTAssertTrue(LANAddressResolver.isCGNAT("100.64.0.1"))
        XCTAssertFalse(LANAddressResolver.isCGNAT("100.128.0.1"))
        XCTAssertFalse(LANAddressResolver.isCGNAT("192.168.1.10"))
        XCTAssertTrue(LANAddressResolver.Candidate(interface: "utun4", ip: "10.0.0.2").isVPN)
        XCTAssertFalse(LANAddressResolver.Candidate(interface: "en0", ip: "192.168.1.10").isVPN)
    }

    func testPairingHostPrefersCustomEntry() throws {
        let suite = "SecureChannelTests.pairingHost"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        defaults.set(LANAddressResolver.customPairingHostTag, forKey: LANAddressResolver.pairingHostDefaultsKey)
        defaults.set(" my-mac.tailnet.ts.net ", forKey: LANAddressResolver.customPairingHostDefaultsKey)
        XCTAssertEqual(LANAddressResolver.pairingIPv4(defaults: defaults), "my-mac.tailnet.ts.net")

        // An empty custom entry falls back to automatic.
        defaults.set("", forKey: LANAddressResolver.customPairingHostDefaultsKey)
        XCTAssertEqual(LANAddressResolver.pairingIPv4(defaults: defaults), LANAddressResolver.primaryIPv4())

        // A picked address that has vanished also falls back to automatic.
        defaults.set("203.0.113.9", forKey: LANAddressResolver.pairingHostDefaultsKey)
        XCTAssertEqual(LANAddressResolver.pairingIPv4(defaults: defaults), LANAddressResolver.primaryIPv4())
    }
}
