# Cryptographic Attacks - CTF Exploitation Reference

> **Document Purpose:** Actionable cryptographic attack techniques for CTF challenges.
> Designed for autonomous agent retrieval with methodologies for padding oracle,
> ECB exploitation, XOR analysis, and other common crypto CTF patterns.

---

## 1. QUICK REFERENCE: Identification

> **When to use this section:** You encounter encrypted or encoded data and need
> to identify the scheme before attacking it.

### 1.1 Encoding vs Encryption Detection

**Tags:** `crypto, identification, encoding, detection`

| Pattern | Likely Type |
|---------|-------------|
| Only A-Z, a-z, 0-9, +, /, = | Base64 |
| Only 0-9, a-f (or A-F) | Hex |
| Only A-Z, 2-7, = | Base32 |
| %XX patterns | URL encoding |
| Fixed-length hex (32 chars) | MD5 hash |
| Fixed-length hex (40 chars) | SHA1 hash |
| Fixed-length hex (64 chars) | SHA256 hash |
| `$2a$`, `$2b$` prefix | bcrypt hash |
| Block-aligned length | Block cipher (AES, DES) |

### 1.2 Block Cipher Mode Detection

**Tags:** `crypto, block-cipher, ecb, cbc, mode-detection`

**ECB mode indicators:**
- Repeated plaintext blocks → repeated ciphertext blocks
- Ciphertext length is always multiple of block size (16 bytes for AES)
- Same input always produces same output (no IV)

**CBC mode indicators:**
- IV prepended to ciphertext (first block changes even with same plaintext)
- Padding errors when modifying ciphertext bytes
- Each block depends on previous block

**Agent Takeaway:**
- Use `crypto_analyzer` with `identify_encoding` to detect encoding type
- Use `crypto_analyzer` with `detect_cipher_mode` to identify ECB vs CBC
- ECB → consider cut-and-paste attacks
- CBC → consider padding oracle or bit-flipping attacks

---

## 2. PADDING ORACLE ATTACK

> **When to use this section:** You have CBC-encrypted ciphertext and the server
> reveals whether padding is valid or invalid (via different errors/status codes).

### 2.1 Detection

**Tags:** `crypto, padding-oracle, detection, cbc`

**How to detect a padding oracle:**
1. Send valid ciphertext → get normal response
2. Modify last byte of ciphertext → get different error (e.g., 500 vs 200, or different error message)
3. If responses split into exactly 2 groups → padding oracle exists

**Error indicators:**
- HTTP 500 for invalid padding vs 200 for valid
- "Padding is invalid" error message
- "Bad Data" or "MAC validation failed"
- Different response lengths for valid vs invalid padding

### 2.2 Exploitation Methodology

**Tags:** `crypto, padding-oracle, exploitation, byte-by-byte`

**Block structure (AES-CBC, 16-byte blocks):**
```
Ciphertext: [IV (16 bytes)][Block 1 (16 bytes)][Block 2 (16 bytes)]...
```

**Decryption of last byte of last block:**
1. Target: find `intermediate[last]` value
2. Set `modified_ciphertext[last-16] = guess XOR 0x01`
3. For guess 0-255: if padding valid → `intermediate[last] = guess XOR 0x01`
4. `plaintext[last] = intermediate[last] XOR original_ciphertext[last-16]`

**Decryption of byte N from end:**
1. Set known bytes to create valid padding: `modified[i] = intermediate[i] XOR pad_value`
2. Brute force target byte same way
3. `pad_value` = number of bytes from end (0x02 for second-to-last, etc.)

### 2.3 Tools

**Tags:** `crypto, padding-oracle, tools`

Use `crypto_probe` with `crypto_type: "padding_oracle"` for automated detection.
Use `crypto_payload_generator` with `operation: "padding_oracle"` for methodology.

**Agent Takeaway:**
- Padding oracle requires ~256 requests per byte to decrypt
- Works block-by-block, byte-by-byte from the end
- The oracle is: valid padding (one response) vs invalid padding (different response)
- Most common in CTFs with cookie-based encryption

---

## 3. ECB MODE ATTACKS

> **When to use this section:** The application uses ECB mode encryption and you
> need to exploit the lack of diffusion.

### 3.1 ECB Cut-and-Paste

**Tags:** `crypto, ecb, cut-and-paste, block-manipulation`

**Concept:** In ECB, each block is encrypted independently. You can rearrange blocks.

**Example attack (role manipulation):**
```
Block 1: email=aaaaaaaaaa  (pad to align)
Block 2: admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b  (admin + PKCS7 padding)
Block 3: aa&role=user\x04\x04\x04\x04  (original role)
```

1. Register with crafted email to get "admin" + padding as a complete block
2. Replace the last block (containing "user") with the "admin" block
3. Submit modified ciphertext → server decrypts to admin role

### 3.2 ECB Byte-at-a-Time

**Tags:** `crypto, ecb, byte-at-a-time, oracle`

**When the server appends a secret to your input before encrypting:**

1. Send input of length (block_size - 1) → observe last encrypted block
2. For each possible byte, send input + byte → compare encrypted blocks
3. When blocks match → you've found the next secret byte
4. Repeat, reducing input length by 1 each time

**Agent Takeaway:**
- ECB is the weakest block cipher mode — always look for repeated blocks
- Cut-and-paste: rearrange encrypted blocks to change plaintext meaning
- Byte-at-a-time: extract appended secrets one byte at a time
- Use `crypto_probe` with `crypto_type: "ecb_detect"` for detection

---

## 4. XOR ANALYSIS

> **When to use this section:** Ciphertext appears to be XOR-encrypted.

### 4.1 Single-Byte XOR

**Tags:** `crypto, xor, single-byte, frequency-analysis`

**Detection:** Ciphertext is same length as plaintext, hex encoded.

**Attack:** Try all 256 possible key bytes, score by English letter frequency:
1. For key 0x00 to 0xFF: XOR each byte of ciphertext with key
2. Score the result by how closely letter frequencies match English
3. Highest-scoring key is the answer

### 4.2 Multi-Byte XOR (Repeating Key)

**Tags:** `crypto, xor, repeating-key, vigenere`

1. Determine key length using Hamming distance or Kasiski examination
2. Split ciphertext into groups by position (mod key_length)
3. Solve each group as single-byte XOR
4. Combine single-byte keys to get full key

### 4.3 Known-Plaintext XOR

**Tags:** `crypto, xor, known-plaintext`

If you know part of the plaintext:
```
key = ciphertext XOR known_plaintext
```
Then apply key to rest of ciphertext.

**Agent Takeaway:**
- Use `crypto_analyzer` with `xor_analysis` for automated single-byte XOR cracking
- XOR with a key is symmetric: encrypt = decrypt
- If you know ANY plaintext, you can recover the key for that portion
- Multi-byte XOR is like multiple single-byte XOR problems

---

## 5. CBC BIT-FLIPPING

> **When to use this section:** You need to modify encrypted CBC data to change
> specific plaintext bytes.

### 5.1 The Attack

**Tags:** `crypto, cbc, bit-flip, plaintext-manipulation`

**Key property:** Flipping bit N in ciphertext block K changes bit N in plaintext block K+1.

**Formula:**
```
To change plaintext[block K+1][byte N] from value A to value B:
ciphertext[block K][byte N] ^= A ^ B
```

**Example:** Change `role=user` to `role=admin` in encrypted cookie:
1. Find the block containing the target bytes
2. XOR the corresponding byte in the PREVIOUS ciphertext block
3. `ciphertext[prev_block][target_byte] ^= ord('u') ^ ord('a')`

**Side effect:** Block K's plaintext will be corrupted (but often acceptable).

**Agent Takeaway:**
- Bit-flipping only works in CBC mode
- You modify the PREVIOUS block to change the CURRENT block's plaintext
- The previous block will be corrupted — this is the trade-off
- Use `crypto_payload_generator` with `operation: "bit_flip"` for detailed methodology

---

## 6. HASH ATTACKS

> **When to use this section:** The challenge involves hash functions.

### 6.1 Hash Length Extension

**Tags:** `crypto, hash, length-extension, md5, sha1`

**Applicable to:** MD5, SHA1, SHA256 (NOT SHA3, HMAC, bcrypt)

**When to use:** Server computes `hash(secret + user_input)` and you know the hash but not the secret.

**Attack:** Extend the hash to include additional data without knowing the secret.

**Tool:** HashPump, hash_extender

### 6.2 Hash Collision / Type Juggling

**Tags:** `crypto, hash, collision, type-juggling, php`

**PHP type juggling (== comparison):**
```php
md5("240610708") == md5("QNKCDZO")  // Both start with "0e"
// "0e..." == "0e..." is TRUE in PHP (scientific notation = 0)
```

**Magic hashes starting with "0e":**
- MD5: `240610708`, `QNKCDZO`, `aabg7XSs`, `aabC9RqS`
- SHA1: `aaroZmOk`, `aaK1STfY`

**Agent Takeaway:**
- Hash length extension only works with specific hash functions (MD5, SHA1, SHA256)
- PHP `==` comparison is vulnerable to type juggling with `0e` hashes
- Use `crypto_analyzer` with `frequency_analysis` for basic cryptanalysis
- Always check if the challenge uses `==` vs `===` in PHP
