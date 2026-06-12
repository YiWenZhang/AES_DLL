"""
AES_DLL — AES-256-CBC encryption library for Python.

Usage::

    import aesdll

    # Generate a key from the machine's MAC address
    key = aesdll.generate_key_from_machine()

    # Encrypt and decrypt files
    aesdll.encrypt_file("secret.txt", "secret.enc", key)
    aesdll.decrypt_file("secret.enc", "decrypted.txt", key)

    # Encrypt and decrypt strings
    token = aesdll.encrypt_string("hello world", key)
    original = aesdll.decrypt_string(token, key)
"""

from aesdll._native import (
    decrypt_file,
    decrypt_key_with_password,
    decrypt_string,
    encrypt_file,
    encrypt_key_with_password,
    encrypt_string,
    generate_key_from_hardware,
    generate_key_from_machine,
    get_mac_address,
)

__all__ = [
    "decrypt_file",
    "decrypt_key_with_password",
    "decrypt_string",
    "encrypt_file",
    "encrypt_key_with_password",
    "encrypt_string",
    "generate_key_from_hardware",
    "generate_key_from_machine",
    "get_mac_address",
]
__version__ = "1.1.0"
