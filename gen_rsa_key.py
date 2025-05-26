import argparse
from instances.rsa import RSACipher


def main():
    """
    Generate RSA keypair and save to files.
    """
    parser = argparse.ArgumentParser(description="Generate RSA keypair")
    parser.add_argument('-s', '--size', type=int, default=1024,
                        help='Size of the prime numbers for RSA generation in bits, default is 1024')
    parser.add_argument('--out', type=str, help="Path for the private key output file")
    parser.add_argument('--pubout', type=str, help="Path for the public key output file")

    args = parser.parse_args()

    private, public = RSACipher.gen_keypair(args.size)
    if args.out is None:
        print(private.export_key())
    else:
        private.export_to_file(args.out)
        print(f'Private key generated and saved to {args.out}')

    if args.pubout is None:
        print(public.export_key())
    else:
        public.export_to_file(args.pubout)
        print(f'Public key generated and saved to {args.pubout}')


if __name__ == '__main__':
    main()