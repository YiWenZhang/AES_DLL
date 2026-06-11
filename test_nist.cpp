/**
 * AES 核心算法 NIST 向量测试
 *
 * 这个测试直接调用 AES.cpp 中的块加密函数（不通过 DLL），
 * 验证 AES-256 单个块的加密/解密是否与 NIST 标准一致。
 *
 * NIST 向量来源: NIST SP 800-38A, F.2.5
 *
 * 编译方式（在 AES_DLL 目录下）:
 *   cl /std:c++20 /EHsc /DNDEBUG test_nist.cpp AES.cpp /Fe:test_nist.exe
 *
 * 或者用 MSBuild 作为控制台应用编译。
 */

#include "AES.h"
#include <cstdio>
#include <cstring>
#include <cassert>

static bool bytesEqual(const uint8_t* a, const uint8_t* b, int len) {
    return memcmp(a, b, len) == 0;
}

static void printHex(const uint8_t* data, int len, const char* label) {
    printf("  %-12s ", label);
    for (int i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

int main() {
    bool allPass = true;

    // ───────────────────────────────────────────────
    // NIST SP 800-38A, F.2.5 — AES-256
    // ───────────────────────────────────────────────
    printf("═══════════════════════════════════════════════\n");
    printf("  NIST SP 800-38A  AES-256 已知答案测试\n");
    printf("═══════════════════════════════════════════════\n\n");

    // 256-bit key
    const uint8_t key[32] = {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
        0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
        0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    };

    // First plaintext block
    const uint8_t plaintext[16] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    };

    // Expected ciphertext (first block) from NIST
    const uint8_t expectedCipher[16] = {
        0xF3, 0xEE, 0xD1, 0xDB, 0xB5, 0xA7, 0x0D, 0x0A,
        0x26, 0x15, 0x94, 0x71, 0x05, 0x5D, 0xA5, 0x7D
    };

    printHex(key, 32, "KEY (256b):");
    printHex(plaintext, 16, "PLAINTEXT:");
    printHex(expectedCipher, 16, "EXPECTED:");
    printf("\n");

    // 密钥扩展
    uint8_t roundKeys[AES::NR_256 + 1][AES::BLOCK_SIZE];
    AES::KeyExpansion(key, roundKeys);

    // 加密
    uint8_t ciphertext[16];
    AES::EncryptBlock(plaintext, ciphertext, roundKeys);
    printHex(ciphertext, 16, "GOT:");
    bool encOk = bytesEqual(ciphertext, expectedCipher, 16);
    printf("  => AES-256 Encrypt: %s\n\n", encOk ? "PASS ✓" : "FAIL ✗");
    if (!encOk) allPass = false;

    // 解密
    uint8_t decrypted[16];
    AES::DecryptBlock(ciphertext, decrypted, roundKeys);
    bool decOk = bytesEqual(decrypted, plaintext, 16);
    printHex(decrypted, 16, "DECRYPTED:");
    printf("  => AES-256 Decrypt: %s\n\n", decOk ? "PASS ✓" : "FAIL ✗");
    if (!decOk) allPass = false;

    // ───────────────────────────────────────────────
    // 多块测试 (NIST F.2.5 全部 4 块)
    // ───────────────────────────────────────────────
    printf("───────────────────────────────────────────────\n");
    printf("  多块测试 (NIST F.2.5, 4 blocks)\n");
    printf("───────────────────────────────────────────────\n\n");

    const uint8_t fullPlain[64] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
        0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
        0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
        0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    };

    const uint8_t fullExpected[64] = {
        0xF3, 0xEE, 0xD1, 0xDB, 0xB5, 0xA7, 0x0D, 0x0A,
        0x26, 0x15, 0x94, 0x71, 0x05, 0x5D, 0xA5, 0x7D,
        0x9C, 0xB6, 0x64, 0x3E, 0x3E, 0x27, 0x1D, 0x55,
        0xEB, 0x3E, 0x16, 0xA9, 0x42, 0xF2, 0xA8, 0xB6,
        0xB1, 0x7A, 0xD5, 0x88, 0x7B, 0x7F, 0x34, 0x60,
        0x7C, 0x3E, 0xD9, 0x9E, 0xB6, 0x7F, 0x8F, 0x5C,
        0xE2, 0x14, 0x2E, 0x1F, 0x9E, 0x1F, 0xDB, 0x42,
        0x9D, 0x1E, 0xEE, 0xC4, 0x4A, 0x85, 0xA2, 0xE3
    };

    bool multiPass = true;
    uint8_t fullCipher[64];
    for (int b = 0; b < 4; b++) {
        AES::EncryptBlock(fullPlain + b * 16, fullCipher + b * 16, roundKeys);
        bool ok = bytesEqual(fullCipher + b * 16, fullExpected + b * 16, 16);
        printf("  Block %d: %s", b + 1, ok ? "PASS ✓" : "FAIL ✗");
        if (ok) {
            printf("\n");
        } else {
            printf("  (mismatch)\n");
            printHex(fullCipher + b * 16, 16, "  GOT:");
            printHex(fullExpected + b * 16, 16, "  EXPECTED:");
        }
        if (!ok) multiPass = false;
    }

    if (!multiPass) allPass = false;

    // ───────────────────────────────────────────────
    // 总结
    // ───────────────────────────────────────────────
    printf("\n═══════════════════════════════════════════════\n");
    printf("  %s\n", allPass ? "全部通过 ✓ — AES-256 实现完全符合 NIST 标准" :
                          "存在失败 ✗ — 请检查 AES 算法实现");
    printf("═══════════════════════════════════════════════\n");

    return allPass ? 0 : 1;
}
