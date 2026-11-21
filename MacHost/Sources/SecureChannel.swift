import CryptoKit
import Foundation
import os

/// Encrypted, mutually authenticated wireless transport.
///
/// Before this, wireless mode sent the 32-byte pairing token in the clear on
/// every connect, and every video frame and touch event after it as plain TCP.
/// Anyone on the same network (or on a VPN relay) could copy the token and
/// connect later, or watch the screen. Now:
///
/// * Session handshake ("SSWE"): the token is never sent. Both sides prove they
///   know it with HMAC (hash-based message authentication code) proofs over
///   fresh random nonces, and derive per-connection keys with HKDF (HMAC-based
///   key derivation function).
/// * Records: everything after the handshake travels as
///   `[length 4, big-endian][AES-256-GCM ciphertext][tag 16]`, one key per
///   direction, nonce = 4 zero bytes + 8-byte big-endian record counter.
///   AES-GCM (Advanced Encryption Standard, Galois/Counter Mode) gives both
///   confidentiality and tamper detection; a replayed, dropped or reordered
///   record fails to decrypt and the connection is closed.
/// * Code pairing ("SSPE"): an ephemeral P-256 ECDH (elliptic-curve
///   Diffie-Hellman) exchange, bound to the one-time code, wraps the token, so
///   a passive eavesdropper never sees it.
///
/// The Android side mirrors this in `SecureChannel.kt`. Both carry the same
/// test vectors.
enum SecureChannel {
    static let sessionInfo = Array("SideScreen wireless v1".utf8)
    static let pairingInfo = Array("SideScreen pairing v1".utf8)
    static let hostLabel = Array("host".utf8)
    static let clientLabel = Array("client".utf8)

    static let nonceLength = 32
    static let proofLength = 32
    static let tagLength = 16
    static let recordHeaderLength = 4
    /// Large enough for a 4K/8K keyframe plus header; anything bigger is garbage.
    static let maxRecordLength = 64 * 1024 * 1024
    static let p256PublicKeyLength = 65

    struct SessionKeys {
        let transcriptHash: Data
        let confirmKey: SymmetricKey
        let clientToHost: SymmetricKey
        let hostToClient: SymmetricKey

        var hostProof: Data { SecureChannel.hmac(confirmKey, hostLabel, transcriptHash) }
        var clientProof: Data { SecureChannel.hmac(confirmKey, clientLabel, transcriptHash) }
    }

    struct PairingKeys {
        let transcriptHash: Data
        let confirmKey: SymmetricKey
        let wrapKey: SymmetricKey

        var clientProof: Data { SecureChannel.hmac(confirmKey, clientLabel, transcriptHash) }
    }

    static func randomNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: nonceLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, nonceLength, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return Data(bytes)
    }

    /// `clientHello` is the full SSWE request exactly as received.
    static func deriveSessionKeys(token: Data, clientHello: Data, clientNonce: Data, hostNonce: Data) -> SessionKeys {
        let th = Data(SHA256.hash(data: clientHello + hostNonce))
        let okm = hkdf(
            ikm: token,
            salt: clientNonce + hostNonce,
            info: Data(sessionInfo) + th,
            length: 96
        )
        return SessionKeys(
            transcriptHash: th,
            confirmKey: SymmetricKey(data: okm[0..<32]),
            clientToHost: SymmetricKey(data: okm[32..<64]),
            hostToClient: SymmetricKey(data: okm[64..<96])
        )
    }

    /// `transcriptHash` = SHA-256(full SSPE request || host public key).
    /// `code` is the 8 normalised ASCII digits.
    static func derivePairingKeys(sharedSecret: Data, code: String, transcriptHash: Data) -> PairingKeys {
        let okm = hkdf(
            ikm: sharedSecret + Data(code.utf8),
            salt: transcriptHash,
            info: Data(pairingInfo),
            length: 64
        )
        return PairingKeys(
            transcriptHash: transcriptHash,
            confirmKey: SymmetricKey(data: okm[0..<32]),
            wrapKey: SymmetricKey(data: okm[32..<64])
        )
    }

    static func pairingTranscriptHash(clientMessage: Data, hostPublicKey: Data) -> Data {
        Data(SHA256.hash(data: clientMessage + hostPublicKey))
    }

    static func hmac(_ key: SymmetricKey, _ label: [UInt8], _ th: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(label) + th, using: key))
    }

    /// Constant-time equality for proofs.
    static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    static func hkdf(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: length
        )
        return key.withUnsafeBytes { Data($0) }
    }

    static func recordNonce(_ counter: UInt64) -> Data {
        var nonce = Data(repeating: 0, count: 4)
        withUnsafeBytes(of: counter.bigEndian) { nonce.append(contentsOf: $0) }
        return nonce
    }

    /// Seals the one-shot pairing payload `[token 32][name_len 1][name M]`.
    /// The wrap key is used exactly once, so an all-zero nonce is safe.
    static func sealPairingPayload(_ payload: Data, keys: PairingKeys) throws -> Data {
        let box = try AES.GCM.seal(payload, using: keys.wrapKey, nonce: AES.GCM.Nonce(data: Data(count: 12)))
        return box.ciphertext + box.tag
    }
}

enum SecureChannelError: Error {
    case recordTooLarge
    case decryptFailed
}

/// Outgoing half of an encrypted session. Thread-safe: sealing and handing the
/// bytes to the connection happen under one lock, so record counters always
/// match the order the bytes reach the wire even though frames, pongs and
/// config messages are sent from different queues.
final class RecordSealer {
    private let key: SymmetricKey
    private let lock = OSAllocatedUnfairLock(initialState: UInt64(0))

    init(key: SymmetricKey) {
        self.key = key
    }

    /// Seals `plaintext` and passes the wire bytes to `emit` while still
    /// holding the lock.
    func seal(_ plaintext: Data, emit: (Data) -> Void) throws {
        try lock.withLockUnchecked { counter in
            let wire = try Self.sealRecord(plaintext, key: key, counter: counter)
            counter += 1
            emit(wire)
        }
    }

    static func sealRecord(_ plaintext: Data, key: SymmetricKey, counter: UInt64) throws -> Data {
        let box = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: AES.GCM.Nonce(data: SecureChannel.recordNonce(counter))
        )
        let bodyLength = box.ciphertext.count + SecureChannel.tagLength
        guard bodyLength <= SecureChannel.maxRecordLength else { throw SecureChannelError.recordTooLarge }
        var wire = Data(capacity: SecureChannel.recordHeaderLength + bodyLength)
        withUnsafeBytes(of: UInt32(bodyLength).bigEndian) { wire.append(contentsOf: $0) }
        wire.append(box.ciphertext)
        wire.append(box.tag)
        return wire
    }
}

/// Incoming half of an encrypted session. Feed it raw bytes as they arrive;
/// it returns the plaintext of every complete record. Not thread-safe: use it
/// from the single receive loop only.
final class RecordOpener {
    private let key: SymmetricKey
    private var counter: UInt64 = 0
    private var buffer = Data()

    init(key: SymmetricKey) {
        self.key = key
    }

    func feed(_ bytes: Data) throws -> Data {
        buffer.append(bytes)
        var plaintext = Data()
        while buffer.count >= SecureChannel.recordHeaderLength {
            let start = buffer.startIndex
            let length = buffer[start..<(start + 4)].reduce(0) { ($0 << 8) | Int($1) }
            guard length >= SecureChannel.tagLength, length <= SecureChannel.maxRecordLength else {
                throw SecureChannelError.recordTooLarge
            }
            guard buffer.count >= SecureChannel.recordHeaderLength + length else { break }
            let bodyStart = start + SecureChannel.recordHeaderLength
            let body = buffer[bodyStart..<(bodyStart + length)]
            plaintext.append(try Self.openRecord(Data(body), key: key, counter: counter))
            counter += 1
            buffer.removeSubrange(start..<(bodyStart + length))
        }
        return plaintext
    }

    static func openRecord(_ body: Data, key: SymmetricKey, counter: UInt64) throws -> Data {
        guard body.count >= SecureChannel.tagLength else { throw SecureChannelError.decryptFailed }
        let ciphertext = body.prefix(body.count - SecureChannel.tagLength)
        let tag = body.suffix(SecureChannel.tagLength)
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: SecureChannel.recordNonce(counter)),
                ciphertext: ciphertext,
                tag: tag
            )
            return try AES.GCM.open(box, using: key)
        } catch {
            throw SecureChannelError.decryptFailed
        }
    }
}
