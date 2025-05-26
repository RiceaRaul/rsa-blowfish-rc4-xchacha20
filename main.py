import argparse

from instances.rsa import RSACipher, RSAPublicKey, RSAPrivateKey
from instances.ecc import ECCCipher, ECPublicKey, ECPrivateKey
from instances.dh import DHCipher, DHPublicKey, DHPrivateKey
from ciphers.cipher import Cipher
from ciphers.asymetric import AsymmetricCipher
from ciphers.factory import CipherFactory


def encrypt_asymmetric(cipher: AsymmetricCipher, key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
    Encryption with an asymmetric algorithm.

Args:
cipher: The asymmetric cipher to use
key: Public key in text format. Will only be used if key_file is None.
key_file: File containing the public key.
in_file: File containing the input to encrypt.
out_file: File where the encrypted output will be written.
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    if isinstance(cipher, RSACipher):
        public_key = RSAPublicKey()
        if key_file is not None:
            public_key.import_from_file(key_file)
        else:
            public_key.import_key(key)
        cipher.public_key = public_key
    elif isinstance(cipher, ECCCipher):
        public_key = ECPublicKey()
        if key_file is not None:
            public_key.import_from_file(key_file)
        else:
            public_key.import_key(key)
        cipher.public_key = public_key
    elif isinstance(cipher, DHCipher):
        # For DH, we need both keys for the key exchange
        # The "public key" here is the other party's public key
        public_key = DHPublicKey()
        if key_file is not None:
            public_key.import_from_file(key_file)
        else:
            public_key.import_key(key)
        cipher.public_key = public_key

        # We also need our private key
        # For demonstration, we'll generate a new one
        # In a real application, you'd want to load this from a file
        print("Generating private key for Diffie-Hellman...")
        private_key = DHPrivateKey()
        private_key.generate_key(public_key.params)
        cipher.private_key = private_key

        # This is our public key, which we would share with the other party
        our_public = private_key.compute_public_key()
        print("\nYour DH public key (share this with the other party):")
        print(our_public.export_key())

    cipher_output = cipher.encrypt(cipher_input)

    if out_file is None:
        print(cipher_output.decode())
        return

    with open(out_file, 'wb') as f:
        f.write(cipher_output)


def decrypt_asymmetric(cipher: AsymmetricCipher, key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
Decryption with an asymmetric algorithm.

Args:
cipher: The asymmetric cipher to use
key: Private key in text format. Will only be used if key_file is None.
key_file: File containing the private key.
in_file: File containing the input to decrypt.
out_file: File where the decrypted output will be written.
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    if isinstance(cipher, RSACipher):
        private_key = RSAPrivateKey()
        if key_file is not None:
            private_key.import_from_file(key_file)
        else:
            private_key.import_key(key)
        cipher.private_key = private_key
    elif isinstance(cipher, ECCCipher):
        private_key = ECPrivateKey()
        if key_file is not None:
            private_key.import_from_file(key_file)
        else:
            private_key.import_key(key)
        cipher.private_key = private_key
    elif isinstance(cipher, DHCipher):
        # For DH, we need both keys for the key exchange
        private_key = DHPrivateKey()
        if key_file is not None:
            private_key.import_from_file(key_file)
        else:
            private_key.import_key(key)
        cipher.private_key = private_key

        # We also need the other party's public key
        # For demo purposes, let's ask for it
        print("For Diffie-Hellman, we need the other party's public key.")
        other_pub_file = input("Enter path to the other party's public key file: ")
        public_key = DHPublicKey()
        public_key.import_from_file(other_pub_file)
        cipher.public_key = public_key

    cipher_output = cipher.decrypt(cipher_input)

    if out_file is None:
        if isinstance(cipher_output, bytes):
            print(cipher_output.decode())
        else:
            print(cipher_output)
        return

    with open(out_file, 'wb' if isinstance(cipher_output, bytes) else 'w') as f:
        f.write(cipher_output)


def encrypt_symmetric(cipher: Cipher, key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
Encrypts using a symmetric key algorithm.

Args:
cipher: Cipher instance to use
key: Symmetric key. Will only be used if key_file is None.
key_file: File containing the key.
in_file: File containing the input to encrypt.
out_file: File where the encrypted output will be written.
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    if key_file is not None:
        with open(key_file, 'r') as f:
            key = f.read()

    cipher.key = key
    cipher_output = cipher.encrypt(cipher_input)

    if out_file is None:
        print(cipher_output.decode())
        return

    with open(out_file, 'wb') as f:
        f.write(cipher_output)


def decrypt_symmetric(cipher: Cipher, key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
Decrypts using a symmetric key algorithm.

Args:
cipher: Cipher instance to use
key: Symmetric key. Will only be used if key_file is None.
key_file: File containing the key.
in_file: File containing the input to decrypt.
out_file: File where the decrypted output will be written.
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    if key_file is not None:
        with open(key_file, 'r') as f:
            key = f.read()

    cipher.key = key
    cipher_output = cipher.decrypt(cipher_input)

    if out_file is None:
        print(cipher_output.decode())
        return

    with open(out_file, 'wb') as f:
        f.write(cipher_output)


def encrypt(cipher_name: str, key: str, key_file: str, in_file: str, out_file: str):
    """
Generic encrypt function that dispatches to the appropriate specific encrypt function.

Args:
cipher_name: Name of the cipher to use
key: Key to use
key_file: File containing the key
in_file: Input file to encrypt
out_file: Output file for encrypted data
    """
    cipher = CipherFactory.get_cipher(cipher_name)

    if CipherFactory.is_asymmetric(cipher_name):
        encrypt_asymmetric(cipher, key, key_file, in_file, out_file)
    else:
        encrypt_symmetric(cipher, key, key_file, in_file, out_file)


def decrypt(cipher_name: str, key: str, key_file: str, in_file: str, out_file: str):
    """
Generic decrypt function that dispatches to the appropriate specific decrypt function.

Args:
cipher_name: Name of the cipher to use
key: Key to use
key_file: File containing the key
in_file: Input file to decrypt
out_file: Output file for decrypted data
    """
    cipher = CipherFactory.get_cipher(cipher_name)

    if CipherFactory.is_asymmetric(cipher_name):
        decrypt_asymmetric(cipher, key, key_file, in_file, out_file)
    else:
        decrypt_symmetric(cipher, key, key_file, in_file, out_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cipher', choices=['rsa', 'ecc', 'dh', 'rc4', 'blowfish'], required=True,
                        help='Which cipher to use')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true',
                       help='Encrypt the input')
    group.add_argument('-d', '--decrypt', action='store_true',
                       help='Decrypt the input')

    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('-k', '--key', type=str,
                           help='Key to use for encryption/decryption')
    key_group.add_argument('--keyfile', type=str,
                           help='File containing the key')

    parser.add_argument('--in', type=str, required=True,
                        help='Input file to encrypt/decrypt')
    parser.add_argument('--out', type=str,
                        help='Output file for encrypted/decrypted data')

    args = vars(parser.parse_args())

    if args['encrypt']:
        encrypt(args['cipher'], args['key'], args['keyfile'], args['in'], args['out'])
    else:
        decrypt(args['cipher'], args['key'], args['keyfile'], args['in'], args['out'])


if __name__ == '__main__':
    main()