#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace AES {

constexpr int BLOCK_SIZE = 16;   // 128-bit block
constexpr int KEY_SIZE_256 = 32; // 256-bit key
constexpr int NK_256 = 8;        // number of 32-bit words in key
constexpr int NR_256 = 14;       // number of rounds
constexpr int NB = 4;            // number of columns (32-bit words) in state

// S-box lookup table
extern const uint8_t SBOX[256];
extern const uint8_t INV_SBOX[256];

// Rcon for key expansion
extern const uint8_t RCON[11];

// Key expansion: generate round keys from cipher key (AES-256)
void KeyExpansion(const uint8_t key[KEY_SIZE_256], uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE]);

// Single block AES-256 encrypt
void EncryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                  const uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE]);

// Single block AES-256 decrypt
void DecryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                  const uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE]);

// Apply PKCS7 padding, returns padded data
std::vector<uint8_t> PKCS7Pad(const std::vector<uint8_t>& data, size_t blockSize = BLOCK_SIZE);

// Remove PKCS7 padding, returns unpadded data
std::vector<uint8_t> PKCS7Unpad(const std::vector<uint8_t>& data, size_t blockSize = BLOCK_SIZE);

// AES-256-CBC encrypt
std::vector<uint8_t> EncryptCBC(const std::vector<uint8_t>& plaintext,
                                const uint8_t key[KEY_SIZE_256],
                                const uint8_t iv[BLOCK_SIZE]);

// AES-256-CBC decrypt
std::vector<uint8_t> DecryptCBC(const std::vector<uint8_t>& ciphertext,
                                const uint8_t key[KEY_SIZE_256],
                                const uint8_t iv[BLOCK_SIZE]);

// Generate random bytes (uses Windows CryptoAPI)
void GenerateRandomBytes(uint8_t* buf, size_t len);

// Derive a 32-byte AES-256 key from arbitrary input data using SHA-256
void DeriveKey256(const uint8_t* input, size_t inputLen, uint8_t outKey[KEY_SIZE_256]);

} // namespace AES
