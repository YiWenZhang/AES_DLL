#include "AES.h"

#include <cstring>
#include <stdexcept>

// Windows CryptoAPI for random number generation
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

namespace AES {

// ============================================================
// S-box and inverse S-box
// ============================================================
const uint8_t SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// ============================================================
// Rcon
// ============================================================
const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// ============================================================
// GF(2^8) multiplication helpers
// ============================================================
static uint8_t gfMul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        bool hiBit = (a & 0x80) != 0;
        a <<= 1;
        if (hiBit) a ^= 0x1B; // irreducible polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return result;
}

// Precomputed multiplication tables
static uint8_t MUL2_TABLE[256];
static uint8_t MUL3_TABLE[256];
static uint8_t MUL9_TABLE[256];
static uint8_t MUL11_TABLE[256];
static uint8_t MUL13_TABLE[256];
static uint8_t MUL14_TABLE[256];
static bool tablesInitialized = false;

static void initTables() {
    if (tablesInitialized) return;
    for (int i = 0; i < 256; i++) {
        MUL2_TABLE[i]  = gfMul((uint8_t)i, 2);
        MUL3_TABLE[i]  = gfMul((uint8_t)i, 3);
        MUL9_TABLE[i]  = gfMul((uint8_t)i, 9);
        MUL11_TABLE[i] = gfMul((uint8_t)i, 11);
        MUL13_TABLE[i] = gfMul((uint8_t)i, 13);
        MUL14_TABLE[i] = gfMul((uint8_t)i, 14);
    }
    tablesInitialized = true;
}

const uint8_t* MUL2  = MUL2_TABLE;
const uint8_t* MUL3  = MUL3_TABLE;
const uint8_t* MUL9  = MUL9_TABLE;
const uint8_t* MUL11 = MUL11_TABLE;
const uint8_t* MUL13 = MUL13_TABLE;
const uint8_t* MUL14 = MUL14_TABLE;

// ============================================================
// Key expansion (AES-256)
// Produces (NR_256+1) = 15 round keys of 16 bytes each
// ============================================================
void KeyExpansion(const uint8_t key[KEY_SIZE_256], uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE]) {
    initTables();

    uint8_t w[240]; // 60 words for AES-256
    // Copy the original key into first 8 words (32 bytes)
    for (int i = 0; i < NK_256; i++) {
        w[4 * i + 0] = key[4 * i + 0];
        w[4 * i + 1] = key[4 * i + 1];
        w[4 * i + 2] = key[4 * i + 2];
        w[4 * i + 3] = key[4 * i + 3];
    }

    for (int i = NK_256; i < NB * (NR_256 + 1); i++) {
        uint8_t temp[4];
        temp[0] = w[4 * (i - 1) + 0];
        temp[1] = w[4 * (i - 1) + 1];
        temp[2] = w[4 * (i - 1) + 2];
        temp[3] = w[4 * (i - 1) + 3];

        if (i % NK_256 == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            // SubWord
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];
            // XOR Rcon
            temp[0] ^= RCON[i / NK_256];
        } else if (i % NK_256 == 4) {
            // SubWord only for AES-256
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];
        }

        w[4 * i + 0] = w[4 * (i - NK_256) + 0] ^ temp[0];
        w[4 * i + 1] = w[4 * (i - NK_256) + 1] ^ temp[1];
        w[4 * i + 2] = w[4 * (i - NK_256) + 2] ^ temp[2];
        w[4 * i + 3] = w[4 * (i - NK_256) + 3] ^ temp[3];
    }

    // Copy to round keys format
    for (int r = 0; r <= NR_256; r++) {
        for (int j = 0; j < 4; j++) {
            roundKeys[r][4 * j + 0] = w[4 * (r * 4 + j) + 0];
            roundKeys[r][4 * j + 1] = w[4 * (r * 4 + j) + 1];
            roundKeys[r][4 * j + 2] = w[4 * (r * 4 + j) + 2];
            roundKeys[r][4 * j + 3] = w[4 * (r * 4 + j) + 3];
        }
    }
}

// ============================================================
// AddRoundKey
// ============================================================
static void AddRoundKey(uint8_t state[4][4], const uint8_t roundKey[BLOCK_SIZE]) {
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= roundKey[4 * c + r];
        }
    }
}

// ============================================================
// SubBytes / InvSubBytes
// ============================================================
static void SubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = SBOX[state[r][c]];
}

static void InvSubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = INV_SBOX[state[r][c]];
}

// ============================================================
// ShiftRows / InvShiftRows
// ============================================================
static void ShiftRows(uint8_t state[4][4]) {
    // Row 1: shift left by 1
    uint8_t t = state[1][0];
    state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;
    // Row 2: shift left by 2
    uint8_t u = state[2][0], v = state[2][1];
    state[2][0] = state[2][2]; state[2][1] = state[2][3]; state[2][2] = u; state[2][3] = v;
    // Row 3: shift left by 3 (right by 1)
    t = state[3][3];
    state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;
}

static void InvShiftRows(uint8_t state[4][4]) {
    // Row 1: shift right by 1
    uint8_t t = state[1][3];
    state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t;
    // Row 2: shift right by 2
    uint8_t u = state[2][0], v = state[2][1];
    state[2][0] = state[2][2]; state[2][1] = state[2][3]; state[2][2] = u; state[2][3] = v;
    // Row 3: shift right by 3 (left by 1)
    t = state[3][0];
    state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t;
}

// ============================================================
// MixColumns / InvMixColumns
// ============================================================
static void MixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
        state[0][c] = MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3;
        state[1][c] = s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3;
        state[2][c] = s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3];
        state[3][c] = MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3];
    }
}

static void InvMixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
        state[0][c] = MUL14[s0] ^ MUL11[s1] ^ MUL13[s2] ^ MUL9[s3];
        state[1][c] = MUL9[s0]  ^ MUL14[s1] ^ MUL11[s2] ^ MUL13[s3];
        state[2][c] = MUL13[s0] ^ MUL9[s1]  ^ MUL14[s2] ^ MUL11[s3];
        state[3][c] = MUL11[s0] ^ MUL13[s1] ^ MUL9[s2]  ^ MUL14[s3];
    }
}

// ============================================================
// Block encrypt/decrypt
// ============================================================
void EncryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                  const uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE]) {
    uint8_t state[4][4];
    // Load input (column-major)
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = in[4 * c + r];

    AddRoundKey(state, roundKeys[0]);

    for (int round = 1; round < NR_256; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys[round]);
    }

    // Final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys[NR_256]);

    // Store output (column-major)
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[4 * c + r] = state[r][c];
}

void DecryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                  const uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE]) {
    uint8_t state[4][4];
    // Load input (column-major)
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = in[4 * c + r];

    AddRoundKey(state, roundKeys[NR_256]);

    for (int round = NR_256 - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys[round]);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys[0]);

    // Store output (column-major)
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[4 * c + r] = state[r][c];
}

// ============================================================
// PKCS7 padding
// ============================================================
std::vector<uint8_t> PKCS7Pad(const std::vector<uint8_t>& data, size_t blockSize) {
    size_t padLen = blockSize - (data.size() % blockSize);
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), padLen, static_cast<uint8_t>(padLen));
    return padded;
}

std::vector<uint8_t> PKCS7Unpad(const std::vector<uint8_t>& data, size_t blockSize) {
    if (data.empty()) return {};
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > blockSize) return data;
    // Verify all padding bytes are correct
    for (uint8_t i = 0; i < padLen; i++) {
        if (data[data.size() - 1 - i] != padLen) return data;
    }
    return std::vector<uint8_t>(data.begin(), data.end() - padLen);
}

// ============================================================
// CBC mode encrypt/decrypt
// ============================================================
std::vector<uint8_t> EncryptCBC(const std::vector<uint8_t>& plaintext,
                                const uint8_t key[KEY_SIZE_256],
                                const uint8_t iv[BLOCK_SIZE]) {
    initTables();

    uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE];
    KeyExpansion(key, roundKeys);

    auto padded = PKCS7Pad(plaintext);
    std::vector<uint8_t> ciphertext(padded.size());

    uint8_t prevCipher[BLOCK_SIZE];
    memcpy(prevCipher, iv, BLOCK_SIZE);

    for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] = padded[i + j] ^ prevCipher[j];
        }
        EncryptBlock(block, &ciphertext[i], roundKeys);
        memcpy(prevCipher, &ciphertext[i], BLOCK_SIZE);
    }

    return ciphertext;
}

std::vector<uint8_t> DecryptCBC(const std::vector<uint8_t>& ciphertext,
                                const uint8_t key[KEY_SIZE_256],
                                const uint8_t iv[BLOCK_SIZE]) {
    initTables();

    if (ciphertext.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Ciphertext length must be a multiple of block size");
    }

    uint8_t roundKeys[NR_256 + 1][BLOCK_SIZE];
    KeyExpansion(key, roundKeys);

    std::vector<uint8_t> plaintext(ciphertext.size());
    uint8_t prevCipher[BLOCK_SIZE];
    memcpy(prevCipher, iv, BLOCK_SIZE);

    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        DecryptBlock(&ciphertext[i], block, roundKeys);
        for (int j = 0; j < BLOCK_SIZE; j++) {
            plaintext[i + j] = block[j] ^ prevCipher[j];
        }
        memcpy(prevCipher, &ciphertext[i], BLOCK_SIZE);
    }

    return PKCS7Unpad(plaintext);
}

// ============================================================
// Random number generation using Windows CryptoAPI
// ============================================================
void GenerateRandomBytes(uint8_t* buf, size_t len) {
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, static_cast<DWORD>(len), buf);
        CryptReleaseContext(hProv, 0);
        return;
    }
    // Fallback PRNG using system time + stack address as seed
    SYSTEMTIME st;
    GetSystemTime(&st);
    uint64_t seed = ((uint64_t)st.wMilliseconds << 48) ^ ((uint64_t)st.wSecond << 32) ^
                    ((uint64_t)st.wMinute << 16) ^ ((uint64_t)&buf);
    for (size_t i = 0; i < len; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = static_cast<uint8_t>((seed >> 32) ^ (seed >> 16) ^ seed);
    }
}

// ============================================================
// Key derivation: derive a 32-byte key from arbitrary input using SHA-256 via Windows CryptoAPI
// ============================================================
void DeriveKey256(const uint8_t* input, size_t inputLen, uint8_t outKey[KEY_SIZE_256]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // Fallback to a simple method if CryptoAPI fails
        // Derive key by iterating and mixing input data
        memset(outKey, 0, KEY_SIZE_256);
        for (size_t i = 0; i < KEY_SIZE_256; i++) {
            outKey[i] = input[i % inputLen] ^ static_cast<uint8_t>(i * 0x5B);
        }
        // Multiple mixing passes
        for (int pass = 0; pass < 3; pass++) {
            uint8_t carry = outKey[0];
            for (size_t i = 1; i < KEY_SIZE_256; i++) {
                uint8_t next = outKey[i];
                outKey[i] = outKey[i] ^ carry ^ static_cast<uint8_t>(i * 0x9D);
                carry = next;
            }
            outKey[0] = outKey[0] ^ carry ^ static_cast<uint8_t>(pass * 0x37);
        }
        return;
    }

    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptHashData(hHash, input, static_cast<DWORD>(inputLen), 0);
        DWORD hashLen = KEY_SIZE_256;
        CryptGetHashParam(hHash, HP_HASHVAL, outKey, &hashLen, 0);
        CryptDestroyHash(hHash);
    }

    CryptReleaseContext(hProv, 0);
}

} // namespace AES
