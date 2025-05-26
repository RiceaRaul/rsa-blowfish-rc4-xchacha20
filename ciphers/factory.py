from typing import Dict, Type

from ciphers.cipher import Cipher
from ciphers.asymetric import AsymmetricCipher
from instances.rsa import RSACipher
from instances.blowfish import BlowfishCipher
from instances.rc4 import RC4Cipher
from instances.ecc import ECCCipher
from instances.dh import DHCipher


class CipherFactory:
    """
Factory class for creating cipher instances.
"""

    _symmetric_ciphers: Dict[str, Type[Cipher]] = {
        'blowfish': BlowfishCipher,
        'rc4': RC4Cipher
    }

    _asymmetric_ciphers: Dict[str, Type[AsymmetricCipher]] = {
        'rsa': RSACipher,
        'ecc': ECCCipher,
        'dh': DHCipher
    }

    @classmethod
    def get_cipher(cls, name: str) -> Cipher:
        """
Get a cipher instance by name.

Args:
name: Name of the cipher

Returns:
Instance of the requested cipher

Raises:
ValueError: If the cipher name is not recognized
        """
        if name in cls._symmetric_ciphers:
            return cls._symmetric_ciphers[name]()
        elif name in cls._asymmetric_ciphers:
            return cls._asymmetric_ciphers[name]()
        else:
            raise ValueError(f"Unknown cipher: {name}")

    @classmethod
    def is_symmetric(cls, name: str) -> bool:
        """
Check if a cipher is symmetric.

Args:
name: Name of the cipher

Returns:
True if the cipher is symmetric, False otherwise
        """
        return name in cls._symmetric_ciphers

    @classmethod
    def is_asymmetric(cls, name: str) -> bool:
        """
Check if a cipher is asymmetric.

Args:
name: Name of the cipher

Returns:
True if the cipher is asymmetric, False otherwise
        """
        return name in cls._asymmetric_ciphers

    @classmethod
    def register_symmetric_cipher(cls, name: str, cipher_class: Type[Cipher]) -> None:
        """
Register a new symmetric cipher.

Args:
name: Name to register the cipher under
cipher_class: Class of the cipher
        """
        cls._symmetric_ciphers[name] = cipher_class

    @classmethod
    def register_asymmetric_cipher(cls, name: str, cipher_class: Type[AsymmetricCipher]) -> None:
        """
Register a new asymmetric cipher.

Args:
name: Name to register the cipher under
cipher_class: Class of the cipher
        """
        cls._asymmetric_ciphers[name] = cipher_class