from abc import ABC, abstractmethod
import os
from ciphers.cipher import Cipher


class AsymmetricKey(ABC):
    """
Abstract base class for asymmetric keys.
"""

    @abstractmethod
    def import_key(self, key: str | bytes) -> None:
        """
Import a key from string or bytes.

Args:
key: The key to import
        """
        pass

    @abstractmethod
    def export_key(self) -> str:
        """
Export the key to a string format.

Returns:
The exported key as a string
        """
        pass

    def import_from_file(self, path: os.PathLike | str):
        """
Import a key from a file.

Args:
path: Path to the key file
        """
        with open(path, 'r') as f:
            key = f.read()
        self.import_key(key)

    def export_to_file(self, path: os.PathLike | str):
        """
Export the key to a file.

Args:
path: Path to save the key
        """
        key_pem = self.export_key()
        with open(path, 'w') as f:
            f.write(key_pem)


class AsymmetricCipher(Cipher):
    """
Abstract base class for asymmetric ciphers.
"""

    def __init__(self, public_key=None, private_key=None):
        """
Initialize an asymmetric cipher.

Args:
public_key: The public key for encryption
private_key: The private key for decryption
        """
        super().__init__()
        self.public_key = public_key
        self.private_key = private_key

    @abstractmethod
    def gen_keypair(cls, size: int) -> tuple:
        """
Generate a new keypair.

Args:
size: Size parameter for the key generation

Returns:
A tuple containing (private_key, public_key)
        """
        pass

    def _init_cipher(self, key: str) -> None:
        """
This method is not used for asymmetric ciphers as they use keypairs.
        """
        pass  # No initialization needed for asymmetric ciphers with a single key