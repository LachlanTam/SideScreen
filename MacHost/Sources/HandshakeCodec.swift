import Foundation

enum HandshakeError: Error, Equatable {
    case invalidMagic
    case invalidName
    case truncated
}

enum HandshakeStatus: UInt8 {
    case ok = 0x00
    case invalidToken = 0x01
    case invalidMagic = 0x02
    case invalidName = 0x03
}

struct ParsedHandshake {
    let token: Data
    let deviceName: String
}

/// Status byte of the code-pairing response (issue #35).
enum PairingStatus: UInt8 {
    case ok = 0x00
    case invalidCode = 0x01
}

struct ParsedPairingRequest {
    let code: String
    let deviceName: String
}

/// Encrypted session hello "SSWE" (see SecureChannel).
struct ParsedSecureHello {
    let clientNonce: Data
    let deviceName: String
    /// The full request bytes, which go into the transcript hash.
    let raw: Data
}

/// Encrypted code-pairing request "SSPE" (see SecureChannel).
struct ParsedSecurePairingRequest {
    let clientPublicKey: Data
    let deviceName: String
    let raw: Data
}

enum HandshakeCodec {
    static let requestMagic: [UInt8] = [0x53, 0x53, 0x57, 0x41]   // "SSWA"
    static let responseMagic: [UInt8] = [0x53, 0x53, 0x57, 0x52]  // "SSWR"
    static let fixedPrefixLen = 4 + 32 + 1                         // magic + token + name_len

    /// Code-pairing request "SSPC": [magic 4][code 8 ASCII digits + zero-pad 24][name_len 1][name N].
    /// The 32-byte middle field deliberately mirrors the SSWA token field so the
    /// total prefix is the same 37 bytes: an OLD host reads its full fixed
    /// prefix, sees an unknown magic, and answers invalidMagic instead of
    /// stalling on a short read — the client can then say "update the Mac app".
    static let pairingRequestMagic: [UInt8] = [0x53, 0x53, 0x50, 0x43]   // "SSPC"
    /// Code-pairing response "SSPR": [magic 4][status 1] then, when status ==
    /// ok: [token 32][mac_name_len 1][mac_name M].
    static let pairingResponseMagic: [UInt8] = [0x53, 0x53, 0x50, 0x52]  // "SSPR"
    static let pairingCodeFieldLen = 32

    /// Encrypted session request "SSWE": [magic 4][client nonce 32][name_len 1][name N].
    /// Same 37-byte fixed prefix as SSWA, so the host can read the prefix
    /// before it knows which handshake it is. The token itself is never sent.
    static let secureRequestMagic: [UInt8] = [0x53, 0x53, 0x57, 0x45]   // "SSWE"
    /// Encrypted session server hello "SSWS": [magic 4][status 1] then, when
    /// status == ok: [host nonce 32][host proof 32]. The client answers with
    /// [client proof 32], and the host replies with a normal SSWR response.
    static let secureServerHelloMagic: [UInt8] = [0x53, 0x53, 0x57, 0x53]  // "SSWS"
    /// Encrypted code pairing "SSPE": [magic 4][P-256 public key 65][name_len 1][name N].
    static let securePairingRequestMagic: [UInt8] = [0x53, 0x53, 0x50, 0x45]  // "SSPE"
    /// Pairing server hello "SSPS": [magic 4][status 1] then, when ok: [host public key 65].
    /// The client answers [proof 32]; the host replies SSPR [status 1] and,
    /// when ok, [sealed_len 2][AES-GCM sealed token 32 + name_len 1 + name M + tag 16].
    static let securePairingServerHelloMagic: [UInt8] = [0x53, 0x53, 0x50, 0x53]  // "SSPS"
    /// Bytes of an SSPE request after the shared 37-byte prefix, up to and including name_len.
    static let securePairingExtraPrefixLen = 4 + 65 + 1 - fixedPrefixLen

    /// Parses the `[name_len 1][name N]` tail shared by SSWA and SSPC requests.
    private static func parseNameSuffix(_ bytes: [UInt8], totalCount: Int) throws -> String {
        let nameLen = Int(bytes[36])
        guard nameLen >= 1 && nameLen <= 64 else { throw HandshakeError.invalidName }
        guard totalCount >= fixedPrefixLen + nameLen else { throw HandshakeError.truncated }
        let nameBytes = Array(bytes[37..<(37 + nameLen)])
        guard let name = String(bytes: nameBytes, encoding: .utf8), !name.isEmpty else {
            throw HandshakeError.invalidName
        }
        return name
    }

    /// Parses the variable-length request `[magic 4][token 32][name_len 1][name N]`.
    static func parseRequest(_ data: Data) throws -> ParsedHandshake {
        guard data.count >= fixedPrefixLen else { throw HandshakeError.truncated }
        let bytes = Array(data)
        guard Array(bytes[0..<4]) == requestMagic else { throw HandshakeError.invalidMagic }
        let token = Data(bytes[4..<36])
        let name = try parseNameSuffix(bytes, totalCount: data.count)
        return ParsedHandshake(token: token, deviceName: name)
    }

    static func encodeResponse(status: HandshakeStatus) -> Data {
        Data(responseMagic + [status.rawValue])
    }

    /// Parses a full pairing request `[magic 4][code 32][name_len 1][name N]`.
    /// The code is the leading run of pairing-alphabet characters in the
    /// 32-byte field (the rest is zero padding).
    static func parsePairingRequest(_ data: Data) throws -> ParsedPairingRequest {
        guard data.count >= fixedPrefixLen else { throw HandshakeError.truncated }
        let bytes = Array(data)
        guard Array(bytes[0..<4]) == pairingRequestMagic else { throw HandshakeError.invalidMagic }
        let codeField = bytes[4..<(4 + pairingCodeFieldLen)].prefix { $0 != 0 }
        guard let code = String(bytes: codeField, encoding: .utf8), !code.isEmpty else {
            throw HandshakeError.invalidMagic
        }
        let name = try parseNameSuffix(bytes, totalCount: data.count)
        return ParsedPairingRequest(code: code, deviceName: name)
    }

    static func encodePairingResponse(status: PairingStatus, token: Data? = nil, macName: String? = nil) -> Data {
        var out = Data(pairingResponseMagic + [status.rawValue])
        guard status == .ok, let token = token else { return out }
        precondition(token.count == 32, "pairing token must be 32 bytes")
        out.append(token)
        var nameBytes = Array((macName ?? "Mac").utf8.prefix(64))
        if nameBytes.isEmpty { nameBytes = Array("Mac".utf8) }
        out.append(UInt8(nameBytes.count))
        out.append(contentsOf: nameBytes)
        return out
    }

    /// Parses a full SSWE request.
    static func parseSecureHello(_ data: Data) throws -> ParsedSecureHello {
        guard data.count >= fixedPrefixLen else { throw HandshakeError.truncated }
        let bytes = Array(data)
        guard Array(bytes[0..<4]) == secureRequestMagic else { throw HandshakeError.invalidMagic }
        let nonce = Data(bytes[4..<36])
        let name = try parseNameSuffix(bytes, totalCount: data.count)
        return ParsedSecureHello(clientNonce: nonce, deviceName: name, raw: Data(bytes[0..<(fixedPrefixLen + Int(bytes[36]))]))
    }

    static func encodeSecureServerHello(status: HandshakeStatus, hostNonce: Data? = nil, hostProof: Data? = nil) -> Data {
        var out = Data(secureServerHelloMagic + [status.rawValue])
        guard status == .ok, let hostNonce = hostNonce, let hostProof = hostProof else { return out }
        precondition(hostNonce.count == 32 && hostProof.count == 32, "nonce and proof must be 32 bytes")
        out.append(hostNonce)
        out.append(hostProof)
        return out
    }

    /// Parses a full SSPE request `[magic 4][pub 65][name_len 1][name N]`.
    static func parseSecurePairingRequest(_ data: Data) throws -> ParsedSecurePairingRequest {
        let fixed = 4 + 65 + 1
        guard data.count >= fixed else { throw HandshakeError.truncated }
        let bytes = Array(data)
        guard Array(bytes[0..<4]) == securePairingRequestMagic else { throw HandshakeError.invalidMagic }
        let pub = Data(bytes[4..<69])
        let nameLen = Int(bytes[69])
        guard nameLen >= 1 && nameLen <= 64 else { throw HandshakeError.invalidName }
        guard data.count >= fixed + nameLen else { throw HandshakeError.truncated }
        guard let name = String(bytes: bytes[fixed..<(fixed + nameLen)], encoding: .utf8), !name.isEmpty else {
            throw HandshakeError.invalidName
        }
        return ParsedSecurePairingRequest(clientPublicKey: pub, deviceName: name, raw: Data(bytes[0..<(fixed + nameLen)]))
    }

    static func encodeSecurePairingServerHello(status: PairingStatus, hostPublicKey: Data? = nil) -> Data {
        var out = Data(securePairingServerHelloMagic + [status.rawValue])
        guard status == .ok, let pub = hostPublicKey else { return out }
        out.append(pub)
        return out
    }

    /// Plaintext of the sealed pairing payload: [token 32][mac_name_len 1][mac_name M].
    static func encodePairingPayload(token: Data, macName: String) -> Data {
        precondition(token.count == 32, "pairing token must be 32 bytes")
        var nameBytes = Array(macName.utf8.prefix(64))
        if nameBytes.isEmpty { nameBytes = Array("Mac".utf8) }
        var out = token
        out.append(UInt8(nameBytes.count))
        out.append(contentsOf: nameBytes)
        return out
    }

    /// Final secure pairing response: SSPR [status] and, when ok, [sealed_len 2][sealed].
    static func encodeSecurePairingResponse(status: PairingStatus, sealed: Data? = nil) -> Data {
        var out = Data(pairingResponseMagic + [status.rawValue])
        guard status == .ok, let sealed = sealed else { return out }
        withUnsafeBytes(of: UInt16(sealed.count).bigEndian) { out.append(contentsOf: $0) }
        out.append(sealed)
        return out
    }
}
