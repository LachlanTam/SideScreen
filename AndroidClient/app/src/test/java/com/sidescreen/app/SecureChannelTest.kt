package com.sidescreen.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.security.interfaces.ECPublicKey

/**
 * Golden vectors shared with the Mac's SecureChannelTests. They come from an
 * independent Python reference implementation, so both apps are checked
 * against the same numbers rather than only against each other.
 */
class SecureChannelTest {
    private val token = ByteArray(32) { it.toByte() }
    private val clientNonce = ByteArray(32) { (0x40 + it).toByte() }
    private val hostNonce = ByteArray(32) { (0x80 + it).toByte() }
    private val hello = AuthHandshake.encodeSecureRequest(clientNonce, "Tab S10 FE")

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun keys() = SecureChannel.deriveSessionKeys(token, hello, clientNonce, hostNonce)

    @Test
    fun sessionTranscriptAndProofsMatchVectors() {
        val k = keys()
        assertEquals("2e4ee87ead329c7d8f621421e13e5d1a76a4d6a6f559ccc16e3b3bdeeaec3583", hex(k.transcriptHash))
        assertEquals("721dfbda888b3412effc8af1c206f2144de687091be24cf8e4db02820556a494", hex(k.hostProof))
        assertEquals("a85b0e14effa12afe00b086094019458bb9bfa5dadc0bd280055c93cd3a07d45", hex(k.clientProof))
    }

    @Test
    fun recordsMatchVectors() {
        val k = keys()
        val hello = "hello".toByteArray()
        assertEquals(
            "00000015" + "367b29dcdd6584c9c8b4e66aef18f6f5dbf4ff79f5",
            hex(SecureChannel.sealRecord(hello, 0, hello.size, k.clientToHost, 0)),
        )
        assertEquals(
            "00000013" + "6b92d3e4d64216d2100502ab4d0e554df56769",
            hex(SecureChannel.sealRecord(byteArrayOf(1, 2, 3), 0, 3, k.hostToClient, 1)),
        )
    }

    @Test
    fun streamsRoundTripOneRecordPerFlush() {
        val k = keys()
        val wire = ByteArrayOutputStream()
        val out = DataOutputStream(SecureOutputStream(wire, k.clientToHost))
        out.writeByte(8)
        out.flush()
        out.writeInt(1234)
        out.write(ByteArray(100_000) { it.toByte() })
        out.flush()

        val input = DataInputStream(SecureInputStream(ByteArrayInputStream(wire.toByteArray()), k.clientToHost))
        assertEquals(8, input.readByte().toInt())
        assertEquals(1234, input.readInt())
        val big = ByteArray(100_000)
        input.readFully(big)
        assertArrayEquals(ByteArray(100_000) { it.toByte() }, big)
        assertEquals(-1, input.read())
    }

    @Test
    fun tamperedOrWrongKeyRecordIsRejected() {
        val k = keys()
        val data = "hello".toByteArray()
        val wire = SecureChannel.sealRecord(data, 0, data.size, k.hostToClient, 0)
        wire[wire.size - 1] = (wire[wire.size - 1].toInt() xor 1).toByte()
        try {
            SecureInputStream(ByteArrayInputStream(wire), k.hostToClient).read()
            fail("expected IOException")
        } catch (e: IOException) {
            // OK
        }
    }

    @Test
    fun replayedRecordIsRejected() {
        val k = keys()
        val data = "hi".toByteArray()
        val rec = SecureChannel.sealRecord(data, 0, data.size, k.hostToClient, 0)
        val input = SecureInputStream(ByteArrayInputStream(rec + rec), k.hostToClient)
        assertEquals('h'.code, input.read())
        assertEquals('i'.code, input.read())
        try {
            input.read()
            fail("replayed record must fail (counter mismatch)")
        } catch (e: IOException) {
            // OK
        }
    }

    @Test
    fun pairingKeysMatchVectors() {
        val th = SecureChannel.sha256("pairing transcript".toByteArray())
        assertEquals("12593b928df26a62f40a7c8781b2883556fd1a98c150937530215d81763e77b6", hex(th))
        val k = SecureChannel.derivePairingKeys(ByteArray(32) { 0x11 }, "12345678", th)
        assertEquals("655aff08b3cd95161f53bd75c2fe3b21d8cf9ab596349b8cb1968fce790b1c0c", hex(k.clientProof))
        val sealed =
            hexToBytes(
                "d05c9485cd9ac8477f3c82edbca808615a591b4fd3a84c2ee95049e4fe5365cd" +
                    "0a1a8cf46d761f12cea28a8558db422d29a933d8",
            )
        val payload = SecureChannel.openPairingPayload(sealed, k)
        assertArrayEquals(token + byteArrayOf(3) + "Mac".toByteArray(), payload)
    }

    @Test
    fun ecdhAgreesBothWays() {
        val a = SecureChannel.generateP256KeyPair()
        val b = SecureChannel.generateP256KeyPair()
        val aPub = SecureChannel.encodeP256PublicKey(a.public as ECPublicKey)
        val bPub = SecureChannel.encodeP256PublicKey(b.public as ECPublicKey)
        assertEquals(65, aPub.size)
        assertArrayEquals(SecureChannel.p256SharedSecret(a, bPub), SecureChannel.p256SharedSecret(b, aPub))
    }

    @Test
    fun wrongTokenGivesDifferentProof() {
        val wrong = SecureChannel.deriveSessionKeys(ByteArray(32) { -1 }, hello, clientNonce, hostNonce)
        assertFalse(SecureChannel.constantTimeEquals(wrong.clientProof, keys().clientProof))
    }

    private fun hexToBytes(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
