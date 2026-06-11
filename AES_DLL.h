#pragma once

#ifdef AES_DLL_EXPORTS
#define AES_DLL_API __declspec(dllexport)
#else
#define AES_DLL_API __declspec(dllimport)
#endif

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Generate an AES-256 key derived from the machine's MAC address.
// keyOut must be at least 32 bytes.
// Returns 0 on success, -1 on failure.
AES_DLL_API int __stdcall GenerateKeyFromMachine(uint8_t keyOut[32]);

// Encrypt a file on disk.
// inputPath  - path to the plaintext file
// outputPath - path where encrypted data will be written
// key        - 32-byte AES-256 key
// Returns 0 on success, -1 on failure.
AES_DLL_API int __stdcall AES_EncryptFile(const wchar_t* inputPath,
                                           const wchar_t* outputPath,
                                           const uint8_t key[32]);

// Decrypt a file on disk.
// inputPath  - path to the encrypted file
// outputPath - path where decrypted data will be written
// key        - 32-byte AES-256 key
// Returns 0 on success, -1 on failure.
AES_DLL_API int __stdcall AES_DecryptFile(const wchar_t* inputPath,
                                           const wchar_t* outputPath,
                                           const uint8_t key[32]);

// Encrypt a string (UTF-8). Output is a hex-encoded string.
// Caller must free the returned string with FreeString().
AES_DLL_API char* __stdcall EncryptString(const char* plaintext,
                                           const uint8_t key[32]);

// Decrypt a hex-encoded encrypted string back to the original plaintext.
// Caller must free the returned string with FreeString().
AES_DLL_API char* __stdcall DecryptString(const char* hexCiphertext,
                                           const uint8_t key[32]);

// Free a string allocated by EncryptString / DecryptString.
AES_DLL_API void __stdcall FreeString(char* str);

// Get the primary MAC address as a human-readable hex string (no colons).
// Caller must free the returned string with FreeString().
AES_DLL_API char* __stdcall GetMacAddress();

#ifdef __cplusplus
}
#endif
