import os
import base64
import json
import secrets
import hashlib
from typing import Tuple

from ciphers.asymetric import AsymmetricKey, AsymmetricCipher


class DHParameters:
    """
Diffie-Hellman parameters (prime p and generator g).
"""

    def __init__(self, p: int, g: int):
        """
Initialize Diffie-Hellman parameters.

Args:
p: A large prime number
g: A generator for the multiplicative group modulo p
        """
        self.p = p
        self.g = g

    def export(self) -> str:
        """
Export parameters to a string.

Returns:
JSON encoded parameters
        """
        params = {
            "p": self.p,
            "g": self.g
        }
        encoded = base64.b64encode(json.dumps(params).encode()).decode()
        return f"-----BEGIN DH PARAMETERS-----\n{encoded}\n-----END DH PARAMETERS-----"

    @classmethod
    def import_params(cls, params_str: str) -> 'DHParameters':
        """
Import parameters from a string.

Args:
params_str: The parameters string

Returns:
DHParameters object
        """
        lines = params_str.strip().split('\n')
        if lines[0] != "-----BEGIN DH PARAMETERS-----" or lines[-1] != "-----END DH PARAMETERS-----":
            raise ValueError("Invalid DH parameters format")

        encoded = ''.join(lines[1:-1])
        params_json = json.loads(base64.b64decode(encoded).decode())

        return cls(params_json["p"], params_json["g"])

    @classmethod
    def generate(cls, key_size: int = 2048) -> 'DHParameters':
        """
Generate new Diffie-Hellman parameters.

Args:
key_size: Size of the prime in bits

Returns:
DHParameters object with generated p and g
        """
        # For a real implementation, we would generate a safe prime here
        # For simplicity and to avoid long computation, we'll use pre-generated values
        if key_size <= 1024:
            # RFC 3526 MODP Group 2 (1024 bits)
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2
        elif key_size <= 2048:
            # RFC 3526 MODP Group 14 (2048 bits)
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2
        else:
            # RFC 3526 MODP Group 15 (3072 bits)
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
            g = 2

        return cls(p, g)


class DHPrivateKey(AsymmetricKey):
    """
Diffie-Hellman private key.
"""

    def __init__(self, params: DHParameters = None, private_value: int = None):
        """
Initialize a Diffie-Hellman private key.

Args:
params: DH parameters (p and g)
private_value: The private exponent
        """
        self.params = params
        self.private_value = private_value

    def generate_key(self, params: DHParameters) -> None:
        """
Generate a new private key using the given parameters.

Args:
params: DH parameters to use
        """
        self.params = params
        # Generate a random private key in the range [2, p-2]
        self.private_value = secrets.randbelow(params.p - 3) + 2

    def compute_public_key(self) -> 'DHPublicKey':
        """
Compute the corresponding public key.

Returns:
The public key
        """
        if self.params is None or self.private_value is None:
            raise ValueError("Parameters or private value not set")

        # Compute g^x mod p
        public_value = pow(self.params.g, self.private_value, self.params.p)
        return DHPublicKey(self.params, public_value)

    def compute_shared_secret(self, other_public_key: 'DHPublicKey') -> bytes:
        """
Compute the shared secret using the other party's public key.

Args:
other_public_key: The other party's public key

Returns:
The shared secret as bytes
        """
        if self.params is None or self.private_value is None:
            raise ValueError("Parameters or private value not set")

        # Verify that the other public key uses the same parameters
        if (self.params.p != other_public_key.params.p or
            self.params.g != other_public_key.params.g):
            raise ValueError("Incompatible DH parameters")

        # Compute (other_public_value)^private_value mod p
        shared_value = pow(other_public_key.public_value, self.private_value, self.params.p)

        # Convert to bytes and hash for better uniformity
        shared_bytes = shared_value.to_bytes((shared_value.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(shared_bytes).digest()

    def export_key(self) -> str:
        """
Export the private key.

Returns:
The key in PEM format
        """
        if self.params is None or self.private_value is None:
            raise ValueError("Parameters or private value not set")

        key_data = {
            "params": {
                "p": self.params.p,
                "g": self.params.g
            },
            "private_value": self.private_value
        }

        encoded = base64.b64encode(json.dumps(key_data).encode()).decode()
        return f"-----BEGIN DH PRIVATE KEY-----\n{encoded}\n-----END DH PRIVATE KEY-----"

    def import_key(self, key: str | bytes) -> None:
        """
Import a private key.

Args:
key: The key in PEM format
        """
        if isinstance(key, bytes):
            key = key.decode()

        lines = key.strip().split('\n')
        if lines[0] != "-----BEGIN DH PRIVATE KEY-----" or lines[-1] != "-----END DH PRIVATE KEY-----":
            raise ValueError("Invalid DH private key format")

        encoded = ''.join(lines[1:-1])
        key_data = json.loads(base64.b64decode(encoded).decode())

        params_data = key_data["params"]
        self.params = DHParameters(params_data["p"], params_data["g"])
        self.private_value = key_data["private_value"]


class DHPublicKey(AsymmetricKey):
    """
Diffie-Hellman public key.
"""

    def __init__(self, params: DHParameters = None, public_value: int = None):
        """
Initialize a Diffie-Hellman public key.

Args:
params: DH parameters (p and g)
public_value: The public value (g^x mod p)
        """
        self.params = params
        self.public_value = public_value

    def export_key(self) -> str:
        """
Export the public key.

Returns:
The key in PEM format
        """
        if self.params is None or self.public_value is None:
            raise ValueError("Parameters or public value not set")

        key_data = {
            "params": {
                "p": self.params.p,
                "g": self.params.g
            },
            "public_value": self.public_value
        }

        encoded = base64.b64encode(json.dumps(key_data).encode()).decode()
        return f"-----BEGIN DH PUBLIC KEY-----\n{encoded}\n-----END DH PUBLIC KEY-----"

    def import_key(self, key: str | bytes) -> None:
        """
Import a public key.

Args:
key: The key in PEM format
        """
        if isinstance(key, bytes):
            key = key.decode()

        lines = key.strip().split('\n')
        if lines[0] != "-----BEGIN DH PUBLIC KEY-----" or lines[-1] != "-----END DH PUBLIC KEY-----":
            raise ValueError("Invalid DH public key format")

        encoded = ''.join(lines[1:-1])
        key_data = json.loads(base64.b64decode(encoded).decode())

        params_data = key_data["params"]
        self.params = DHParameters(params_data["p"], params_data["g"])
        self.public_value = key_data["public_value"]


class DHCipher(AsymmetricCipher):
    """
Diffie-Hellman key exchange implementation.

This is not a true cipher but rather a key agreement protocol.
It can be used to establish a shared secret for symmetric encryption.
"""

    def __init__(self, private_key: DHPrivateKey = None, public_key: DHPublicKey = None):
        """
Initialize the Diffie-Hellman cipher.

Args:
private_key: Your private key
public_key: The other party's public key
        """
        super().__init__(public_key, private_key)

    @classmethod
    def gen_keypair(cls, size: int = 2048) -> Tuple[DHPrivateKey, DHPublicKey]:
        """
Generate a new Diffie-Hellman key pair.

Args:
size: Key size in bits

Returns:
Tuple of (private_key, public_key)
        """
        # Generate parameters
        params = DHParameters.generate(size)

        # Generate private key
        private_key = DHPrivateKey()
        private_key.generate_key(params)

        # Derive public key
        public_key = private_key.compute_public_key()

        return private_key, public_key

    def get_shared_secret(self) -> bytes:
        """
Compute the shared secret using the private key and the other party's public key.

Returns:
The shared secret
        """
        if self.private_key is None or self.public_key is None:
            raise ValueError("Both private and public keys must be set")

        return self.private_key.compute_shared_secret(self.public_key)

    def encrypt(self, message: bytes) -> bytes:
        """
This method is required by the AsymmetricCipher interface but doesn't make sense
for Diffie-Hellman, which is a key exchange protocol, not an encryption algorithm.

Instead, it demonstrates how to use the shared secret with AES for encryption.

Args:
message: The message to encrypt

Returns:
The encrypted message
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import secrets

        # Get the shared secret
        shared_secret = self.get_shared_secret()

        # Use the first 16 bytes as the AES key
        key = shared_secret[:16]

        # Generate a random 16-byte IV
        iv = secrets.token_bytes(16)

        # Encrypt with AES-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))

        # Combine IV and ciphertext
        result = iv + ciphertext

        return base64.b64encode(result)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
This method is required by the AsymmetricCipher interface but doesn't make sense
for Diffie-Hellman directly.

It demonstrates how to use the shared secret with AES for decryption.

Args:
ciphertext: The message to decrypt

Returns:
The decrypted message
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        # Get the shared secret
        shared_secret = self.get_shared_secret()

        # Use the first 16 bytes as the AES key
        key = shared_secret[:16]

        # Decode the base64 data
        data = base64.b64decode(ciphertext)

        # Extract IV (first 16 bytes) and ciphertext
        iv = data[:16]
        encrypted = data[16:]

        # Decrypt with AES-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)

        try:
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")