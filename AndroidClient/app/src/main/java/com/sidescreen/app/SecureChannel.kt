package com.sidescreen.app

import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypted, mutually authenticated wireless transport. Mirrors
 * `MacHost/Sources/SecureChannel.swift`; see that file for the design. In
 * short: the pairing token is never sent, both sides prove they know it with
 * HMAC (hash-based message authentication code) proofs over fresh nonces,
 * HKDF (HMAC-based key derivation function) gives one key per direction, and
 * every byte after the handshake travels in AES-256-GCM records.
 *
 * Pure JVM (no android.* imports) so it runs in plain unit tests.
 */
object SecureChannel {
    private val SESSION_INFO = "SideScreen wireless v1".toByteArray(Charsets.US_ASCII)
    private val PAIRING_INFO = "SideScreen pairing v1".toByteArray(Charsets.US_ASCII)
    private val HOST_LABEL = "host".toByteArray(Charsets.US_ASCII)
    private val CLIENT_LABEL = "client".toByteArray(Charsets.US_ASCII)

    const val NONCE_LEN = 32
    const val PROOF_LEN = 32
    const val TAG_LEN = 16
    const val MAX_RECORD_LEN = 64 * 1024 * 1024
    const val P256_PUBLIC_KEY_LEN = 65

    private val random = SecureRandom()

    class SessionKeys(
        val transcriptHash: ByteArray,
        val confirmKey: ByteArray,
        val clientToHost: ByteArray,
        val hostToClient: ByteArray,
    ) {
        val hostProof: ByteArray get() = hmac(confirmKey, HOST_LABEL + transcriptHash)
        val clientProof: ByteArray get() = hmac(confirmKey, CLIENT_LABEL + transcriptHash)
    }

    class PairingKeys(
        val transcriptHash: ByteArray,
        val confirmKey: ByteArray,
        val wrapKey: ByteArray,
    ) {
        val clientProof: ByteArray get() = hmac(confirmKey, CLIENT_LABEL + transcriptHash)
    }

    fun randomNonce(): ByteArray = ByteArray(NONCE_LEN).also { random.nextBytes(it) }

    /** [clientHello] is the full SSWE request exactly as sent. */
    fun deriveSessionKeys(
        token: ByteArray,
        clientHello: ByteArray,
        clientNonce: ByteArray,
        hostNonce: ByteArray,
    ): SessionKeys {
        val th = sha256(clientHello + hostNonce)
        val okm = hkdf(token, clientNonce + hostNonce, SESSION_INFO + th, 96)
        return SessionKeys(th, okm.copyOfRange(0, 32), okm.copyOfRange(32, 64), okm.copyOfRange(64, 96))
    }

    /** [code] is the 8 typed digits with separators removed. */
    fun derivePairingKeys(
        sharedSecret: ByteArray,
        code: String,
        transcriptHash: ByteArray,
    ): PairingKeys {
        val okm = hkdf(sharedSecret + code.toByteArray(Charsets.US_ASCII), transcriptHash, PAIRING_INFO, 64)
        return PairingKeys(transcriptHash, okm.copyOfRange(0, 32), okm.copyOfRange(32, 64))
    }

    fun pairingTranscriptHash(
        clientMessage: ByteArray,
        hostPublicKey: ByteArray,
    ): ByteArray = sha256(clientMessage + hostPublicKey)

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun hmac(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** HKDF-SHA256 (RFC 5869). */
    fun hkdf(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        val prk = hmac(salt, ikm)
        val out = java.io.ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            t = hmac(prk, t + info + byteArrayOf(i.toByte()))
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    fun constantTimeEquals(
        a: ByteArray,
        b: ByteArray,
    ): Boolean = MessageDigest.isEqual(a, b)

    fun recordNonce(counter: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) n[4 + i] = (counter ushr (56 - 8 * i)).toByte()
        return n
    }

    fun gcm(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        offset: Int = 0,
        length: Int = input.size,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
        return cipher.doFinal(input, offset, length)
    }

    /** Wire bytes for one record: [len 4 BE][ciphertext][tag 16]. */
    fun sealRecord(
        plaintext: ByteArray,
        offset: Int,
        length: Int,
        key: ByteArray,
        counter: Long,
    ): ByteArray {
        val body = gcm(Cipher.ENCRYPT_MODE, key, recordNonce(counter), plaintext, offset, length)
        if (body.size > MAX_RECORD_LEN) throw IOException("record too large")
        val wire = ByteArray(4 + body.size)
        wire[0] = (body.size ushr 24).toByte()
        wire[1] = (body.size ushr 16).toByte()
        wire[2] = (body.size ushr 8).toByte()
        wire[3] = body.size.toByte()
        System.arraycopy(body, 0, wire, 4, body.size)
        return wire
    }

    /** Opens the one-shot pairing payload sealed with the wrap key (all-zero nonce). */
    fun openPairingPayload(
        sealed: ByteArray,
        keys: PairingKeys,
    ): ByteArray = gcm(Cipher.DECRYPT_MODE, keys.wrapKey, ByteArray(12), sealed)

    // --- P-256 ECDH (elliptic-curve Diffie-Hellman) for code pairing ---

    fun generateP256KeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    /** Uncompressed X9.63 encoding: 0x04 || X(32) || Y(32), as CryptoKit uses. */
    fun encodeP256PublicKey(key: ECPublicKey): ByteArray {
        fun fixed32(v: BigInteger): ByteArray {
            val raw = v.toByteArray()
            val out = ByteArray(32)
            val start = maxOf(0, raw.size - 32)
            val len = raw.size - start
            System.arraycopy(raw, start, out, 32 - len, len)
            return out
        }
        return byteArrayOf(0x04) + fixed32(key.w.affineX) + fixed32(key.w.affineY)
    }

    /** ECDH with the Mac's X9.63 public key; returns the 32-byte shared X coordinate. */
    fun p256SharedSecret(
        own: KeyPair,
        peerX963: ByteArray,
    ): ByteArray {
        require(peerX963.size == P256_PUBLIC_KEY_LEN && peerX963[0] == 0x04.toByte()) { "bad P-256 public key" }
        val x = BigInteger(1, peerX963.copyOfRange(1, 33))
        val y = BigInteger(1, peerX963.copyOfRange(33, 65))
        val params = (own.public as ECPublicKey).params
        val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(own.private)
        ka.doPhase(peer, true)
        return ka.generateSecret()
    }
}

/**
 * Decrypting view of the socket input. Each read pulls whole records, checks
 * their tag and counter, and hands out plaintext. Any tampering, replay or
 * reordering throws [IOException], which ends the session.
 */
class SecureInputStream(raw: InputStream, private val key: ByteArray) : InputStream() {
    private val input = DataInputStream(java.io.BufferedInputStream(raw, 65536))
    private var counter = 0L
    private var plain = ByteArray(0)
    private var pos = 0

    private fun fill(): Boolean {
        val len =
            try {
                input.readInt()
            } catch (e: EOFException) {
                return false
            }
        if (len < SecureChannel.TAG_LEN || len > SecureChannel.MAX_RECORD_LEN) {
            throw IOException("bad record length $len")
        }
        val body = ByteArray(len)
        input.readFully(body)
        plain =
            try {
                SecureChannel.gcm(Cipher.DECRYPT_MODE, key, SecureChannel.recordNonce(counter), body)
            } catch (e: java.security.GeneralSecurityException) {
                throw IOException("record failed authentication", e)
            }
        counter++
        pos = 0
        return true
    }

    override fun read(): Int {
        while (pos >= plain.size) if (!fill()) return -1
        return plain[pos++].toInt() and 0xFF
    }

    override fun read(
        b: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        if (len == 0) return 0
        while (pos >= plain.size) if (!fill()) return -1
        val n = minOf(len, plain.size - pos)
        System.arraycopy(plain, pos, b, off, n)
        pos += n
        return n
    }

    override fun available(): Int = plain.size - pos

    override fun close() = input.close()
}

/**
 * Encrypting view of the socket output. Bytes are buffered until [flush],
 * which seals them as one record — every existing write site already ends a
 * message with flush(). Synchronised so a touch write and a keyframe request
 * can never interleave inside a record or reuse a counter.
 */
class SecureOutputStream(private val raw: OutputStream, private val key: ByteArray) : OutputStream() {
    private val pending = java.io.ByteArrayOutputStream(256)
    private var counter = 0L

    @Synchronized override fun write(b: Int) = pending.write(b)

    @Synchronized override fun write(
        b: ByteArray,
        off: Int,
        len: Int,
    ) = pending.write(b, off, len)

    @Synchronized override fun flush() {
        if (pending.size() == 0) {
            raw.flush()
            return
        }
        val bytes = pending.toByteArray()
        pending.reset()
        raw.write(SecureChannel.sealRecord(bytes, 0, bytes.size, key, counter))
        counter++
        raw.flush()
    }

    override fun close() {
        try {
            flush()
        } catch (_: IOException) {
        }
        raw.close()
    }
}
