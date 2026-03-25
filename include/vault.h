#ifndef VAULT_H
#define VAULT_H

#include <stdint.h>
#include <stdio.h>

/* 
 * VAULT FILE FORMAT v1
 * 
 * A .vault file contains precisely these bytes in order:
 * [4 bytes]  Magic Header: 0x56 0x41 0x55 0x4C ('VAUL')
 * [1 byte]   Version: 0x01
 * [1088 bytes] ML-KEM-768 Ciphertext (used to recover the shared secret)
 * [12 bytes] AES-256-GCM Nonce (random number used once per encryption)
 * [16 bytes] AES-256-GCM Auth Tag (verifies the file wasn't tampered with)
 * [4 bytes]  Plaintext Length (how big the original file was)
 * [N bytes]  AES Ciphertext (the actual encrypted file data)
 */

#define VAULT_MAGIC 0x4C554156 // 'VAUL' in little-endian
#define VAULT_VERSION 1

// Function to generate the Post-Quantum Keypair
// Writes public key to pk_path and secret key to sk_path
int vault_keygen(const char *pk_path, const char *sk_path);

// Encrypts (seals) a file using the public key
int vault_seal(const char *pk_path, const char *in_path, const char *out_path);

// Decrypts (opens) a file using the secret key
int vault_open(const char *sk_path, const char *in_path, const char *out_path);

#endif // VAULT_H
