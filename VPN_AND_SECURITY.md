# Wireless mode over a VPN, and how the connection is secured

This fork changes wireless mode so that it works over a VPN (virtual private network) such as Tailscale, and so that everything sent between the Mac and the tablet is encrypted.

Both apps must run this version. The new Mac app refuses the old unencrypted handshake, and the old Mac app cannot talk to the new Android app.

## Using it over Tailscale (or another VPN)

1. Install Tailscale on the Mac and the tablet and sign both in to the same account.
2. On the Mac, open Side Screen, go to the Wireless section and start the server.
3. Under **Address in QR**, pick the address marked **VPN** (for Tailscale it starts with `100.`).
4. On the tablet, scan the QR code. Code pairing also works: type the Mac's VPN address, the port and the 8-digit code.

The tablet reconnects to whichever address it paired with. To switch between home Wi-Fi and the VPN, pair again with the other address. The Tailscale address works at home too, so picking it once covers both.

### What was wrong

- **Android bound every wireless socket to the Wi-Fi network** (a workaround for LG / Android 12 routing). A socket bound to Wi-Fi ignores the VPN's routes, so a Mac at a `100.x.x.x` Tailscale address could never be reached (upstream issue #121). The app now binds to Wi-Fi only when the Mac's address is on the Wi-Fi network's own subnet. Otherwise it uses normal routing, which goes through the VPN.
- **The Mac always put its `en0` address in the QR code**, so QR pairing could not target a VPN address. There is now a picker listing every address on the Mac, with VPN interfaces (utun, WireGuard, ZeroTier, and the 100.64.0.0/10 range Tailscale uses) labelled.

## What is secured now

| Before | After |
|---|---|
| The 32-byte pairing token was sent in plain text on every connect, so anyone who saw one connect could reuse it later. | The token is never sent. Each side proves it holds the token with an HMAC (hash-based message authentication code) over fresh random nonces from both sides, so a captured handshake cannot be replayed. |
| Video, touch input and control messages were plain TCP (Transmission Control Protocol). | After the handshake, every byte travels in AES-256-GCM (Advanced Encryption Standard, Galois/Counter Mode) records, with a separate key for each direction derived by HKDF (HMAC-based key derivation function). Tampered, replayed, dropped or reordered records fail authentication and close the connection. |
| Code pairing returned the token in plain text. | Code pairing runs an ephemeral P-256 ECDH (elliptic-curve Diffie-Hellman) key exchange bound to the one-time code. The token comes back sealed, so someone just listening on the network never sees it. The 5-attempt limit is unchanged. |
| Any TCP connection to the port, even a port scan, dropped the tablet that was streaming (upstream issue #69). | A new connection takes over only after it is admitted: a USB client once it sends its first bytes, a wireless client once it passes the handshake. Connections that are not admitted within 10 seconds are closed. |
| The tablet's pairing token could end up in Android cloud backups and device transfers. | `paired_host.xml` is excluded from both. |

### Known limits

- **QR pairing is the strongest option.** The token travels only through the camera. Code pairing protects against anyone listening, but an attacker who can actively intercept traffic at the moment you pair could still guess the 8-digit code offline. Doing better would need a PAKE (password-authenticated key exchange). If you code-pair, do it on a network you trust, or over Tailscale, which already encrypts traffic with WireGuard.
- **USB mode still trusts loopback.** Any program on the Mac can connect to the local port, as before (upstream issue #89).
- **The Mac stores the token in UserDefaults**, not the Keychain, as before.
- **This fork's builds are not signed with the upstream release keys.** Get them from GitHub Actions (below) or build from source (see the README).

## Getting builds from GitHub

1. On the fork, open the **Actions** tab and enable workflows (forks start with them turned off).
2. Pick **Build macOS** or **Build Android** and click **Run workflow**. They also run on every push and pull request to `main`.
3. When a run finishes, download the file under **Artifacts** at the bottom of its page:
   - `SideScreen-mac`: a DMG (disk image). The app is ad-hoc signed, so after dragging it to Applications run `xattr -cr /Applications/SideScreen.app` once, or macOS will refuse to open it.
   - `SideScreen-android-debug`: an APK (Android package). Copy it to the tablet and install it (allow installs from unknown sources when asked). It installs as a separate "debug" app beside the Play Store version, so the store app can stay installed.

Each run also runs the unit tests for both apps, including the encryption test vectors.

## Protocol reference

All integers are big-endian.

**Session (`SSWE`)**

1. Tablet → Mac: `"SSWE"` · client nonce (32) · name length (1) · name.
2. Mac → tablet: `"SSWS"` · status (1) · host nonce (32) · host proof (32).
3. Tablet → Mac: client proof (32).
4. Mac → tablet: `"SSWR"` · status (1). From here on, every message is a record.

Keys: `th = SHA-256(request ‖ host nonce)`, `okm = HKDF-SHA256(ikm = token, salt = client nonce ‖ host nonce, info = "SideScreen wireless v1" ‖ th, 96)`, split into confirm, tablet-to-Mac and Mac-to-tablet keys of 32 bytes each. Host proof = `HMAC(confirm, "host" ‖ th)`, client proof = `HMAC(confirm, "client" ‖ th)`.

Record: length (4) · AES-256-GCM ciphertext · tag (16). Nonce = 4 zero bytes · 8-byte record counter, starting at 0 in each direction.

**Code pairing (`SSPE`)**

1. Tablet → Mac: `"SSPE"` · P-256 public key, uncompressed (65) · name length (1) · name.
2. Mac → tablet: `"SSPS"` · status (1) · Mac public key (65).
3. Tablet → Mac: proof (32).
4. Mac → tablet: `"SSPR"` · status (1) · sealed length (2) · AES-GCM sealed (token (32) · name length (1) · Mac name).

Keys: `th = SHA-256(request ‖ Mac public key)`, `okm = HKDF-SHA256(ikm = ECDH secret ‖ 8 code digits, salt = th, info = "SideScreen pairing v1", 64)`, split into confirm and wrap keys. Proof = `HMAC(confirm, "client" ‖ th)`. The wrap key is used once, with an all-zero nonce.

Both apps check the same test vectors (`SecureChannelTests.swift` and `SecureChannelTest.kt`). They were generated with an independent Python implementation.
