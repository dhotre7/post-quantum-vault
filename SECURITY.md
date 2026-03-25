# Security Model & Threat Assessment

## Algorithm Rationale
The Post-Quantum Vault utilizes a hybrid cryptographic pipeline to provide maximum security against both classical and future quantum threats:

1. **ML-KEM-768**: A post-quantum Key Encapsulation Mechanism standardized by NIST. We use it to securely negotiate a temporary 256-bit symmetric key over an untrusted channel. Classical asymmetric algorithms like RSA-2048 are vulnerable to Shor's Algorithm running on future quantum computers. ML-KEM is currently believed to be quantum-resistant.
2. **AES-256-GCM**: The industry standard for authenticated symmetric encryption. AES-256 remains quantum-safe (Grover's algorithm only halves the effective key length to 128 bits, which is still virtually unbreakable). GCM (Galois/Counter Mode) provides both confidentiality and data authenticity via a tamper-proof 16-byte Auth Tag.

## Security Hardening
The codebase has been hardened against common implementation flaws:
- **Nonce Reuse Prevention**: A fresh 12-byte nonce is sourced from `/dev/urandom` (via OpenSSL's `RAND_bytes`) for every single encryption operation. Combined with a fresh Key Encapsulation `shared_secret`, key/nonce pair reuse is cryptographically negligible.
- **Strict Return Checking**: All `EVP_*` and `OQS_*` API return values are strictly verified before execution proceeds. 
- **Header Validation**: `vault_open()` validates the `VAUL` magic bytes, exact version numbers, and exact payload chunk sizes before attempting decryption to prevent crashing on malformed bytes.
- **RAM Security**: Because encryption engines demand that sensitive material is loaded into volatile memory, `explicit_bzero` (or `OPENSSL_cleanse`) is explicitly called on all private keys and shared secrets immediately after use. This prevents memory leaks and defends against scrapers recovering passwords from memory dumps.

## Known Limitations (Threat Model)
This vault provides "Harvest-Now-Decrypt-Later" protection for file *data*. It does **NOT** protect against the following attacks:
- **File Metadata Verification**: The file's name, creation timestamp, and total size are *not* hidden in the `.vault` file. Attackers analyzing network traffic can accurately infer the total size of your encrypted payload.
- **Physical Access**: This tool assumes the Secret Key (`.sk` file) is stored on a physically secure device. It does not encrypt the Secret Key at rest. If an attacker gains physical access to the device storing the `.sk` file unsupervised, they can decrypt all associated `.vault` files locally.
- **Timing Attacks**: Operations are currently reliant on the underlying OpenSSL and liboqs implementations. While both broadly defend against timing, the implementation logic does not run explicitly out-of-bounds in constant time.
- **Key Logging/Screen Scraping**: The vault provides data at-rest protection. It does not secure an endpoint against active local malware capable of keylogging or reading files out of the decrypter's destination folder.
