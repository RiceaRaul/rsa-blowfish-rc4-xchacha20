import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional

from ciphers.asymetric import AsymmetricKey, AsymmetricCipher


@dataclass
class Point:
    """
Point on an elliptic curve with coordinates (x, y).
None represents the point at infinity.
    """
    x: Optional[int] = None
    y: Optional[int] = None

    def is_at_infinity(self) -> bool:
        """Check if this is the point at infinity"""
        return self.x is None and self.y is None

    @staticmethod
    def at_infinity() -> 'Point':
        """Return the point at infinity"""
        return Point(None, None)


class ECCurve:
    """
Represents an elliptic curve in short Weierstrass form: y^2 = x^3 + ax + b (mod p)
"""

    def __init__(self, a: int, b: int, p: int, g_x: int, g_y: int, n: int):
        """
Initialize an elliptic curve.

Args:
a: Coefficient a in the curve equation
b: Coefficient b in the curve equation
p: The prime modulus
g_x: x-coordinate of the base point G
g_y: y-coordinate of the base point G
n: The order of the base point G
        """
        self.a = a
        self.b = b
        self.p = p
        self.g = Point(g_x, g_y)
        self.n = n

        # Verify that the base point is on the curve
        if not self.is_on_curve(self.g):
            raise ValueError("Base point G is not on the curve")

    def is_on_curve(self, point: Point) -> bool:
        """
Check if a point is on the curve.

Args:
point: The point to check

Returns:
True if the point is on the curve, False otherwise
        """
        if point.is_at_infinity():
            return True

        # Check if y^2 ≡ x^3 + ax + b (mod p)
        left = (point.y * point.y) % self.p
        right = (pow(point.x, 3, self.p) + (self.a * point.x) % self.p + self.b) % self.p
        return left == right

    def add_points(self, p1: Point, p2: Point) -> Point:
        """
Add two points on the curve.

Args:
p1: First point
p2: Second point

Returns:
The sum of p1 and p2
        """
        # Handle point at infinity cases
        if p1.is_at_infinity():
            return p2
        if p2.is_at_infinity():
            return p1

        # Handle the case where p1 = -p2
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            return Point.at_infinity()

        # Calculate the slope
        if p1.x == p2.x and p1.y == p2.y:
            # Tangent line (point doubling)
            slope = (3 * p1.x * p1.x + self.a) * pow(2 * p1.y, -1, self.p) % self.p
        else:
            # Line through two points
            slope = (p2.y - p1.y) * pow(p2.x - p1.x, -1, self.p) % self.p

        # Calculate the new point
        x3 = (slope * slope - p1.x - p2.x) % self.p
        y3 = (slope * (p1.x - x3) - p1.y) % self.p

        return Point(x3, y3)

    def scalar_multiply(self, k: int, point: Point) -> Point:
        """
Multiply a point by a scalar using the double-and-add algorithm.

Args:
k: The scalar
point: The point to multiply

Returns:
k * point
        """
        if k == 0 or point.is_at_infinity():
            return Point.at_infinity()

        result = Point.at_infinity()
        addend = Point(point.x, point.y)

        while k:
            if k & 1:
                # If the bit is set, add the current point to the result
                result = self.add_points(result, addend)

            # Double the point
            addend = self.add_points(addend, addend)

            # Shift to the next bit
            k >>= 1

        return result


# Define some standard curves (parameters from SEC 2)

# secp256r1 (P-256, prime256v1)
P256 = ECCurve(
    a=-3,
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    g_x=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    g_y=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
)

# secp384r1 (P-384)
P384 = ECCurve(
    a=-3,
    b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    g_x=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    g_y=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
    n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
)


class ECPublicKey(AsymmetricKey):
    """
ECC Public Key implementation.
"""

    def __init__(self, curve: ECCurve = P256, point: Point = None):
        """
Initialize an ECC public key.

Args:
curve: The elliptic curve to use
point: The public key point
        """
        self.curve = curve
        self.point = point

    def export_key(self) -> str:
        """
Export the key in PEM format.

Returns:
The key in PEM format
        """
        if self.point is None:
            raise ValueError("Public key point is not set")

        # Simple format: just encode the curve name, x and y coordinates
        # In a real implementation, this would use ASN.1 DER encoding
        if self.curve == P256:
            curve_name = "P256"
        elif self.curve == P384:
            curve_name = "P384"
        else:
            curve_name = "UNKNOWN"

        key_data = f"{curve_name}:{self.point.x}:{self.point.y}"
        encoded = base64.b64encode(key_data.encode()).decode()

        return f"-----BEGIN EC PUBLIC KEY-----\n{encoded}\n-----END EC PUBLIC KEY-----"

    def import_key(self, key: str | bytes) -> None:
        """
Import a key from PEM format.

Args:
key: The key in PEM format
        """
        if isinstance(key, bytes):
            key = key.decode()

        # Extract the base64-encoded data
        lines = key.strip().split('\n')
        if lines[0] != "-----BEGIN EC PUBLIC KEY-----" or lines[-1] != "-----END EC PUBLIC KEY-----":
            raise ValueError("Invalid EC public key format")

        encoded = ''.join(lines[1:-1])
        key_data = base64.b64decode(encoded).decode()

        # Parse the data
        parts = key_data.split(':')
        if len(parts) != 3:
            raise ValueError("Invalid EC public key data")

        curve_name, x, y = parts

        # Set the curve and point
        if curve_name == "P256":
            self.curve = P256
        elif curve_name == "P384":
            self.curve = P384
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")

        self.point = Point(int(x), int(y))

        # Verify that the point is on the curve
        if not self.curve.is_on_curve(self.point):
            raise ValueError("Imported point is not on the curve")


class ECPrivateKey(AsymmetricKey):
    """
ECC Private Key implementation.
"""

    def __init__(self, curve: ECCurve = P256, scalar: int = None):
        """
Initialize an ECC private key.

Args:
curve: The elliptic curve to use
scalar: The private key scalar
        """
        self.curve = curve
        self.scalar = scalar

    def get_public_key(self) -> ECPublicKey:
        """
Derive the public key from this private key.

Returns:
The corresponding public key
        """
        if self.scalar is None:
            raise ValueError("Private key scalar is not set")

        # Q = d * G
        point = self.curve.scalar_multiply(self.scalar, self.curve.g)
        return ECPublicKey(self.curve, point)

    def export_key(self) -> str:
        """
Export the key in PEM format.

Returns:
The key in PEM format
        """
        if self.scalar is None:
            raise ValueError("Private key scalar is not set")

        # Simple format: just encode the curve name and scalar
        # In a real implementation, this would use ASN.1 DER encoding
        if self.curve == P256:
            curve_name = "P256"
        elif self.curve == P384:
            curve_name = "P384"
        else:
            curve_name = "UNKNOWN"

        key_data = f"{curve_name}:{self.scalar}"
        encoded = base64.b64encode(key_data.encode()).decode()

        return f"-----BEGIN EC PRIVATE KEY-----\n{encoded}\n-----END EC PRIVATE KEY-----"

    def import_key(self, key: str | bytes) -> None:
        """
Import a key from PEM format.

Args:
key: The key in PEM format
        """
        if isinstance(key, bytes):
            key = key.decode()

        # Extract the base64-encoded data
        lines = key.strip().split('\n')
        if lines[0] != "-----BEGIN EC PRIVATE KEY-----" or lines[-1] != "-----END EC PRIVATE KEY-----":
            raise ValueError("Invalid EC private key format")

        encoded = ''.join(lines[1:-1])
        key_data = base64.b64decode(encoded).decode()

        # Parse the data
        parts = key_data.split(':')
        if len(parts) != 2:
            raise ValueError("Invalid EC private key data")

        curve_name, scalar = parts

        # Set the curve and scalar
        if curve_name == "P256":
            self.curve = P256
        elif curve_name == "P384":
            self.curve = P384
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")

        self.scalar = int(scalar)

        # Verify that the scalar is in the correct range
        if not 1 <= self.scalar < self.curve.n:
            raise ValueError("Private key scalar is not in the valid range")


class ECCCipher(AsymmetricCipher):
    """
Implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES).
"""

    def __init__(self, private_key: ECPrivateKey = None, public_key: ECPublicKey = None):
        """
Initialize the ECC cipher.

Args:
private_key: The private key for decryption
public_key: The public key for encryption
        """
        super().__init__(public_key, private_key)

    @classmethod
    def gen_keypair(cls, size: int = 256) -> Tuple[ECPrivateKey, ECPublicKey]:
        """
Generate an ECC keypair.

Args:
size: Key size in bits (256 for P-256, 384 for P-384)

Returns:
A tuple containing (private_key, public_key)
        """
        # Select the appropriate curve based on the size
        if size == 256:
            curve = P256
        elif size == 384:
            curve = P384
        else:
            raise ValueError(f"Unsupported key size: {size}. Use 256 or 384.")

        # Generate a random scalar in the range [1, n-1]
        scalar = secrets.randbelow(curve.n - 1) + 1

        # Create the private key
        private_key = ECPrivateKey(curve, scalar)

        # Derive the public key
        public_key = private_key.get_public_key()

        return private_key, public_key

    def encrypt(self, message: bytes) -> bytes:
        """
Encrypt a message using ECIES.

Args:
message: The message to encrypt

Returns:
The encrypted message, base64 encoded
        """
        if self.public_key is None:
            raise ValueError("Public key is not set")

        # Get the curve from the public key
        curve = self.public_key.curve

        # Generate an ephemeral key pair
        k = secrets.randbelow(curve.n - 1) + 1
        ephemeral_private = ECPrivateKey(curve, k)
        ephemeral_public = ephemeral_private.get_public_key()

        # Compute the shared secret
        shared_point = curve.scalar_multiply(k, self.public_key.point)
        if shared_point.is_at_infinity():
            raise ValueError("Computed shared secret is the point at infinity")

        # Derive a symmetric key from the shared secret
        # In a real implementation, we would use a proper key derivation function
        shared_secret = f"{shared_point.x}:{shared_point.y}".encode()
        symmetric_key = hashlib.sha256(shared_secret).digest()

        # Use the symmetric key to encrypt the message
        # This is a very simplified version of ECIES - in a real implementation,
        # we would use a proper symmetric encryption algorithm and MAC
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        # Use the first 16 bytes as the AES key and the next 16 bytes as the IV
        aes_key = symmetric_key[:16]
        iv = symmetric_key[16:]

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))

        # Combine the ephemeral public key and the ciphertext
        result = f"{ephemeral_public.point.x}:{ephemeral_public.point.y}:{base64.b64encode(ciphertext).decode()}"

        return base64.b64encode(result.encode())

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
Decrypt a message using ECIES.

Args:
ciphertext: The message to decrypt, base64 encoded

Returns:
The decrypted message
        """
        if self.private_key is None:
            raise ValueError("Private key is not set")

        # Decode the ciphertext
        decoded = base64.b64decode(ciphertext).decode()
        parts = decoded.split(':')
        if len(parts) != 3:
            raise ValueError("Invalid ciphertext format")

        # Extract the ephemeral public key and the encrypted message
        ephemeral_x = int(parts[0])
        ephemeral_y = int(parts[1])
        encrypted_message = base64.b64decode(parts[2])

        # Get the curve from the private key
        curve = self.private_key.curve

        # Create the ephemeral public key point
        ephemeral_point = Point(ephemeral_x, ephemeral_y)
        if not curve.is_on_curve(ephemeral_point):
            raise ValueError("Ephemeral point is not on the curve")

        # Compute the shared secret
        shared_point = curve.scalar_multiply(self.private_key.scalar, ephemeral_point)
        if shared_point.is_at_infinity():
            raise ValueError("Computed shared secret is the point at infinity")

        # Derive a symmetric key from the shared secret
        shared_secret = f"{shared_point.x}:{shared_point.y}".encode()
        symmetric_key = hashlib.sha256(shared_secret).digest()

        # Use the symmetric key to decrypt the message
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        # Use the first 16 bytes as the AES key and the next 16 bytes as the IV
        aes_key = symmetric_key[:16]
        iv = symmetric_key[16:]

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        try:
            decrypted = unpad(cipher.decrypt(encrypted_message), AES.block_size)
            return decrypted
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")