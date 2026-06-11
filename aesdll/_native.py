"""
AES encryption DLL — native binding layer via ctypes.
"""

import ctypes
import os
from typing import Optional


def _find_dll() -> str:
    dll_name = "AES_DLL.dll"
    search_dirs = [
        os.path.dirname(os.path.abspath(__file__)),
    ]
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    search_dirs.append(os.path.join(repo_root, "x64", "Release"))
    search_dirs.append(os.path.join(repo_root, "build", "Release"))
    search_dirs.append(os.getcwd())

    for d in search_dirs:
        path = os.path.join(d, dll_name)
        if os.path.isfile(path):
            return path

    return dll_name


_dll_path = _find_dll()
_dll = ctypes.WinDLL(_dll_path)

# ---- GenerateKeyFromMachine ----
_dll.GenerateKeyFromMachine.argtypes = [ctypes.POINTER(ctypes.c_uint8 * 32)]
_dll.GenerateKeyFromMachine.restype = ctypes.c_int

# ---- AES_EncryptFile ----
_dll.AES_EncryptFile.argtypes = [
    ctypes.c_wchar_p, ctypes.c_wchar_p,
    ctypes.POINTER(ctypes.c_uint8 * 32),
]
_dll.AES_EncryptFile.restype = ctypes.c_int

# ---- AES_DecryptFile ----
_dll.AES_DecryptFile.argtypes = [
    ctypes.c_wchar_p, ctypes.c_wchar_p,
    ctypes.POINTER(ctypes.c_uint8 * 32),
]
_dll.AES_DecryptFile.restype = ctypes.c_int

# ---- EncryptString ----
_dll.EncryptString.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8 * 32)]
_dll.EncryptString.restype = ctypes.c_void_p

# ---- DecryptString ----
_dll.DecryptString.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8 * 32)]
_dll.DecryptString.restype = ctypes.c_void_p

# ---- FreeString ----
_dll.FreeString.argtypes = [ctypes.c_void_p]
_dll.FreeString.restype = None

# ---- GetMacAddress ----
_dll.GetMacAddress.argtypes = []
_dll.GetMacAddress.restype = ctypes.c_void_p


def generate_key_from_machine() -> bytes:
    """Derive a 32-byte AES-256 key from the machine's MAC address."""
    key = (ctypes.c_uint8 * 32)()
    ret = _dll.GenerateKeyFromMachine(key)
    if ret != 0:
        raise OSError("GenerateKeyFromMachine failed — no network adapter found?")
    return bytes(key)


def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """Encrypt a file using AES-256-CBC."""
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")
    key_array = (ctypes.c_uint8 * 32)(*key)
    ret = _dll.AES_EncryptFile(input_path, output_path, key_array)
    if ret != 0:
        raise OSError(f"EncryptFile failed for '{input_path}'")


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """Decrypt a file that was encrypted with encrypt_file()."""
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")
    key_array = (ctypes.c_uint8 * 32)(*key)
    ret = _dll.AES_DecryptFile(input_path, output_path, key_array)
    if ret != 0:
        raise OSError(f"DecryptFile failed for '{input_path}'")


def encrypt_string(plaintext: str, key: bytes) -> str:
    """Encrypt a string. Returns hex-encoded ciphertext."""
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")
    key_array = (ctypes.c_uint8 * 32)(*key)
    ptr = _dll.EncryptString(plaintext.encode("utf-8"), key_array)
    if not ptr:
        raise RuntimeError("EncryptString failed")
    result = ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")
    _dll.FreeString(ptr)
    return result


def decrypt_string(hex_ciphertext: str, key: bytes) -> str:
    """Decrypt a hex-encoded ciphertext back to the original string."""
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")
    key_array = (ctypes.c_uint8 * 32)(*key)
    ptr = _dll.DecryptString(hex_ciphertext.encode("utf-8"), key_array)
    if not ptr:
        raise RuntimeError("DecryptString failed — wrong key or corrupted data")
    result = ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")
    _dll.FreeString(ptr)
    return result


def get_mac_address() -> str:
    """Get the primary MAC address as an uppercase hex string (no separators)."""
    ptr = _dll.GetMacAddress()
    if not ptr:
        raise RuntimeError("GetMacAddress failed — no network adapter found")
    result = ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")
    _dll.FreeString(ptr)
    return result
