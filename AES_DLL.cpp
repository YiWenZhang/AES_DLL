#define AES_DLL_EXPORTS
#include "AES_DLL.h"
#include "AES.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================
// Helper: convert bytes to hex string (lowercase)
// ============================================================
static char* BytesToHex(const uint8_t* data, size_t len) {
    char* hex = static_cast<char*>(malloc(len * 2 + 1));
    if (!hex) return nullptr;
    for (size_t i = 0; i < len; i++) {
        snprintf(hex + i * 2, 3, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

// ============================================================
// Helper: convert hex string to bytes
// ============================================================
static std::vector<uint8_t> HexToBytes(const char* hex) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return {};
    std::vector<uint8_t> bytes(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        unsigned int b;
        if (sscanf_s(hex + i, "%2x", &b) != 1) return {};
        bytes[i / 2] = static_cast<uint8_t>(b);
    }
    return bytes;
}

// ============================================================
// GetMacAddress: returns primary MAC as hex string (uppercase, no separators)
// ============================================================
AES_DLL_API char* __stdcall GetMacAddress() {
    ULONG bufLen = 0;
    GetAdaptersInfo(nullptr, &bufLen);

    if (bufLen == 0) return nullptr;

    std::vector<uint8_t> buffer(bufLen);
    auto* pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    if (GetAdaptersInfo(pAdapterInfo, &bufLen) != ERROR_SUCCESS) return nullptr;

    char macHex[32] = {0};
    // Use the first adapter with a non-zero MAC
    for (auto* p = pAdapterInfo; p != nullptr; p = p->Next) {
        if (p->AddressLength > 0) {
            snprintf(macHex, sizeof(macHex),
                     "%02X%02X%02X%02X%02X%02X",
                     p->Address[0], p->Address[1], p->Address[2],
                     p->Address[3], p->Address[4], p->Address[5]);
            break;
        }
    }

    size_t len = strlen(macHex);
    char* result = static_cast<char*>(malloc(len + 1));
    if (result) {
        memcpy(result, macHex, len + 1);
    }
    return result;
}

// ============================================================
// GenerateKeyFromMachine: derive 32-byte AES-256 key from MAC address
// ============================================================
AES_DLL_API int __stdcall GenerateKeyFromMachine(uint8_t keyOut[32]) {
    char* macStr = GetMacAddress();
    if (!macStr) return -1;

    AES::DeriveKey256(reinterpret_cast<const uint8_t*>(macStr), strlen(macStr), keyOut);
    free(macStr);
    return 0;
}

// ============================================================
// AES_EncryptFile: read plaintext file, write encrypted file
// File format: [16-byte IV][ciphertext...]
// ============================================================
AES_DLL_API int __stdcall AES_EncryptFile(const wchar_t* inputPath,
                                           const wchar_t* outputPath,
                                           const uint8_t key[32]) {
    // Read input file
    HANDLE hIn = CreateFileW(inputPath, GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hIn, &fileSize) || fileSize.QuadPart > 100 * 1024 * 1024) { // 100MB limit
        CloseHandle(hIn);
        return -1;
    }

    std::vector<uint8_t> plaintext(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(hIn, plaintext.data(), static_cast<DWORD>(plaintext.size()), &bytesRead, nullptr)) {
        CloseHandle(hIn);
        return -1;
    }
    CloseHandle(hIn);
    plaintext.resize(bytesRead);

    // Generate random IV
    uint8_t iv[AES::BLOCK_SIZE];
    AES::GenerateRandomBytes(iv, AES::BLOCK_SIZE);

    // Encrypt
    std::vector<uint8_t> ciphertext;
    try {
        ciphertext = AES::EncryptCBC(plaintext, key, iv);
    } catch (...) {
        return -1;
    }

    // Write output: IV + ciphertext
    HANDLE hOut = CreateFileW(outputPath, GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) return -1;

    DWORD bytesWritten = 0;
    WriteFile(hOut, iv, AES::BLOCK_SIZE, &bytesWritten, nullptr);
    WriteFile(hOut, ciphertext.data(), static_cast<DWORD>(ciphertext.size()), &bytesWritten, nullptr);
    CloseHandle(hOut);

    return 0;
}

// ============================================================
// AES_DecryptFile: read encrypted file (IV + ciphertext), write plaintext
// ============================================================
AES_DLL_API int __stdcall AES_DecryptFile(const wchar_t* inputPath,
                                           const wchar_t* outputPath,
                                           const uint8_t key[32]) {
    // Read input file
    HANDLE hIn = CreateFileW(inputPath, GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) return -1;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hIn, &fileSize) || fileSize.QuadPart < AES::BLOCK_SIZE) {
        CloseHandle(hIn);
        return -1;
    }

    std::vector<uint8_t> fileData(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(hIn, fileData.data(), static_cast<DWORD>(fileData.size()), &bytesRead, nullptr)) {
        CloseHandle(hIn);
        return -1;
    }
    CloseHandle(hIn);
    fileData.resize(bytesRead);

    // Extract IV (first 16 bytes)
    uint8_t iv[AES::BLOCK_SIZE];
    memcpy(iv, fileData.data(), AES::BLOCK_SIZE);

    // Remaining is ciphertext
    std::vector<uint8_t> ciphertext(fileData.begin() + AES::BLOCK_SIZE, fileData.end());

    // Decrypt
    std::vector<uint8_t> plaintext;
    try {
        plaintext = AES::DecryptCBC(ciphertext, key, iv);
    } catch (...) {
        return -1;
    }

    // Write output
    HANDLE hOut = CreateFileW(outputPath, GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) return -1;

    DWORD bytesWritten = 0;
    WriteFile(hOut, plaintext.data(), static_cast<DWORD>(plaintext.size()), &bytesWritten, nullptr);
    CloseHandle(hOut);

    return 0;
}

// ============================================================
// EncryptString: encrypt a UTF-8 string, return hex-encoded result
// Format in hex: IV(32 hex chars) + ciphertext (hex)
// ============================================================
AES_DLL_API char* __stdcall EncryptString(const char* plaintext,
                                           const uint8_t key[32]) {
    if (!plaintext) return nullptr;

    size_t len = strlen(plaintext);
    std::vector<uint8_t> plainBytes(plaintext, plaintext + len);

    uint8_t iv[AES::BLOCK_SIZE];
    AES::GenerateRandomBytes(iv, AES::BLOCK_SIZE);

    std::vector<uint8_t> ciphertext;
    try {
        ciphertext = AES::EncryptCBC(plainBytes, key, iv);
    } catch (...) {
        return nullptr;
    }

    // Build result: IV hex + ciphertext hex
    char* ivHex = BytesToHex(iv, AES::BLOCK_SIZE);
    char* ctHex = BytesToHex(ciphertext.data(), ciphertext.size());
    if (!ivHex || !ctHex) {
        free(ivHex);
        free(ctHex);
        return nullptr;
    }

    // Concatenate
    size_t resultLen = strlen(ivHex) + strlen(ctHex) + 1;
    char* result = static_cast<char*>(malloc(resultLen));
    if (result) {
        snprintf(result, resultLen, "%s%s", ivHex, ctHex);
    }

    free(ivHex);
    free(ctHex);
    return result;
}

// ============================================================
// DecryptString: decrypt a hex-encoded string back to plaintext
// ============================================================
AES_DLL_API char* __stdcall DecryptString(const char* hexCiphertext,
                                           const uint8_t key[32]) {
    if (!hexCiphertext) return nullptr;

    size_t hexLen = strlen(hexCiphertext);
    // Need at least 32 hex chars for IV (16 bytes)
    if (hexLen < AES::BLOCK_SIZE * 2) return nullptr;

    // Extract IV (first 32 hex chars = 16 bytes)
    char ivHex[33] = {0};
    memcpy(ivHex, hexCiphertext, 32);
    auto ivBytes = HexToBytes(ivHex);
    if (ivBytes.size() != AES::BLOCK_SIZE) return nullptr;

    // Remaining hex is ciphertext
    auto ciphertext = HexToBytes(hexCiphertext + 32);
    if (ciphertext.empty()) return nullptr;

    std::vector<uint8_t> plaintext;
    try {
        plaintext = AES::DecryptCBC(ciphertext, key, ivBytes.data());
    } catch (...) {
        return nullptr;
    }

    // Convert to null-terminated string
    char* result = static_cast<char*>(malloc(plaintext.size() + 1));
    if (result) {
        memcpy(result, plaintext.data(), plaintext.size());
        result[plaintext.size()] = '\0';
    }
    return result;
}

// ============================================================
// GenerateKeyFromHardware: derive 32-byte AES-256 key from
// volume serial + computer name + MAC address via SHA-256
// ============================================================
AES_DLL_API int __stdcall GenerateKeyFromHardware(uint8_t keyOut[32]) {
    // Collect hardware entropy sources
    uint8_t buffer[512];
    size_t offset = 0;

    // 1) Volume serial number of the system drive
    wchar_t volumeName[256] = {0};
    DWORD volSerial = 0;
    if (GetVolumeInformationW(L"C:\\", volumeName, 256, &volSerial, nullptr, nullptr, nullptr, 0)) {
        memcpy(buffer + offset, &volSerial, sizeof(volSerial));
        offset += sizeof(volSerial);
    }

    // 2) Computer name
    wchar_t compName[256] = {0};
    DWORD compNameLen = 256;
    if (GetComputerNameW(compName, &compNameLen)) {
        int bytes = WideCharToMultiByte(CP_UTF8, 0, compName, -1,
                                        reinterpret_cast<char*>(buffer + offset),
                                        static_cast<int>(sizeof(buffer) - offset),
                                        nullptr, nullptr);
        if (bytes > 0) {
            offset += (bytes - 1); // skip null terminator
        }
    }

    // 3) MAC address via existing helper
    char* macStr = GetMacAddress();
    if (macStr) {
        size_t macLen = strlen(macStr);
        if (offset + macLen <= sizeof(buffer)) {
            memcpy(buffer + offset, macStr, macLen);
            offset += macLen;
        }
        free(macStr);
    }

    if (offset == 0) return -1;

    AES::DeriveKey256(buffer, offset, keyOut);
    return 0;
}

// ============================================================
// EncryptKeyWithPassword: encrypt a 32-byte AES key with a password.
// Output: [16-byte IV][48-byte ciphertext (PKCS7-padded 32→48)] = 64 bytes
// ============================================================
AES_DLL_API int __stdcall EncryptKeyWithPassword(const char* password,
                                                  const uint8_t aesKey[32],
                                                  uint8_t outEncryptedKey[64]) {
    if (!password || !aesKey || !outEncryptedKey) return -1;

    // Derive a 256-bit key from the password
    uint8_t passwordKey[32];
    AES::DeriveKey256(reinterpret_cast<const uint8_t*>(password), strlen(password), passwordKey);

    // Generate random IV
    uint8_t iv[AES::BLOCK_SIZE];
    AES::GenerateRandomBytes(iv, AES::BLOCK_SIZE);

    // Encrypt the 32-byte AES key (CBC mode: PKCS7 pads to 48 bytes)
    std::vector<uint8_t> keyBytes(aesKey, aesKey + 32);
    std::vector<uint8_t> ciphertext;
    try {
        ciphertext = AES::EncryptCBC(keyBytes, passwordKey, iv);
    } catch (...) {
        return -1;
    }

    // Output: IV (16) + ciphertext (48) = 64 bytes
    memcpy(outEncryptedKey, iv, AES::BLOCK_SIZE);
    memcpy(outEncryptedKey + AES::BLOCK_SIZE, ciphertext.data(), ciphertext.size());

    return 0;
}

// ============================================================
// DecryptKeyWithPassword: decrypt a password-encrypted AES key.
// Input: [16-byte IV][48-byte ciphertext] = 64 bytes
// ============================================================
AES_DLL_API int __stdcall DecryptKeyWithPassword(const char* password,
                                                  const uint8_t encryptedKey[64],
                                                  uint8_t outAesKey[32]) {
    if (!password || !encryptedKey || !outAesKey) return -1;

    // Derive the same 256-bit key from the password
    uint8_t passwordKey[32];
    AES::DeriveKey256(reinterpret_cast<const uint8_t*>(password), strlen(password), passwordKey);

    // Extract IV (first 16 bytes)
    uint8_t iv[AES::BLOCK_SIZE];
    memcpy(iv, encryptedKey, AES::BLOCK_SIZE);

    // Remaining 48 bytes is ciphertext
    std::vector<uint8_t> ciphertext(encryptedKey + AES::BLOCK_SIZE,
                                    encryptedKey + AES::BLOCK_SIZE + 48);

    // Decrypt
    std::vector<uint8_t> plaintext;
    try {
        plaintext = AES::DecryptCBC(ciphertext, passwordKey, iv);
    } catch (...) {
        return -1;
    }

    if (plaintext.size() != 32) return -1;

    memcpy(outAesKey, plaintext.data(), 32);
    return 0;
}

// ============================================================
// FreeString: free memory allocated by the DLL
// ============================================================
AES_DLL_API void __stdcall FreeString(char* str) {
    free(str);
}
