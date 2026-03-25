# Building a Hybrid Post-Quantum Vault in C

The world's cybersecurity infrastructure is facing an expiration date. When cryptographically-relevant quantum computers arrive, they will run Shor's Algorithm and shatter the RSA-2048 encryption we use every single day to protect our data.

Even worse, hackers are already practicing a "Harvest Now, Decrypt Later" attack. They steal vast quantities of encrypted files today, quietly storing them on hard drives, waiting for the quantum computing breakthrough that will let them retroactively unlock the secrets.

To see how we can fight back, I built a `Post-Quantum Vault` entirely in C.

### The Hybrid Pipeline
Currently, post-quantum cryptography is excellent at sharing temporary passwords, but it's not designed to encrypt a 5GB video file efficiently. So, I built a hybrid engine:

1. **ML-KEM-768 for Password Sharing**: The program uses `liboqs` (Open Quantum Safe) to implement the NIST-standardized `ML-KEM-768` lattice-based algorithm. It automatically spins up a mathematically massive "public/private" puzzle. If you use the private key to solve the puzzle, you extract a random 256-bit password.
2. **AES-256-GCM for File Sealing**: The industry standard for heavy-duty encryption is AES-256. It's incredibly fast, and crucially, *it is completely immune to Shor's algorithm*. The vault takes the extracted 256-bit password from step 1, passes it to the OpenSSL `EVP` interface, and encrypts the file at blazing speeds.
3. **Tamper-Proof Galois Mathematics**: The GCM layer of AES simultaneously generates a 16-byte Authenticated Tag using a mathematical rolling checksum. If a hacker intercepts the vault file and alters a single byte, the tag spectacularly fails validation, and the C program automatically deletes the corrupted output to protect the user.

### Classical vs Quantum Speed: The Benchmark
The most shocking part of this project wasn't the complex mathematics; it was the speed. When pitting traditional `RSA-2048` key generation against the new `ML-KEM-768` algorithm running 100 iterations, the post-quantum keys were generated *significantly faster*. 

We not only built an engine that protects against the computers of the future—we made it faster than the tools of the past.
