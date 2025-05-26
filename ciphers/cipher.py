from abc import ABC, abstractmethod

class Cipher(ABC):
    """
    Abstract base class for all cipher implementations.
    """
    
    def __init__(self, key: str | None = None) -> None:
        """
        Initialize the cipher with an optional key.
        
        Args:
            key: The encryption/decryption key
        """
        self._key = key
        if key is not None:
            self._init_cipher(key)
    
    @property
    def key(self) -> str | None:
        """Get the current key"""
        return self._key
    
    @key.setter
    def key(self, new_key: str) -> None:
        """Set a new key and initialize the cipher with it"""
        self._key = new_key
        self._init_cipher(new_key)
    
    @abstractmethod
    def _init_cipher(self, key: str) -> None:
        """
        Initialize the cipher with the given key.
        
        Args:
            key: The encryption/decryption key
        """
        pass
    
    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using the cipher.
        
        Args:
            plaintext: The plaintext to encrypt
            
        Returns:
            Encrypted data, base64 encoded
        """
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using the cipher.
        
        Args:
            ciphertext: The ciphertext to decrypt (base64 encoded)
            
        Returns:
            Decrypted data
        """
        pass