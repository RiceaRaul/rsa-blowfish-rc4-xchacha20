import argparse
from instances.ecc import ECCCipher


def main():
    """
Generate ECC keypair and save to files.
    """
    parser = argparse.ArgumentParser(description="Generate ECC keypair")
    parser.add_argument('-s', '--size', type=int, default=256, choices=[256, 384],
                        help='Key size in bits (256 for P-256, 384 for P-384), default is 256')
    parser.add_argument('--out', type=str, help="Path for the private key output file")
    parser.add_argument('--pubout', type=str, help="Path for the public key output file")

    args = parser.parse_args()

    private, public = ECCCipher.gen_keypair(args.size)
    if args.out is None:
        print(private.export_key())
    else:
        private.export_to_file(args.out)
        print(f'ECC private key generated and saved to {args.out}')

    if args.pubout is None:
        print(public.export_key())
    else:
        public.export_to_file(args.pubout)
        print(f'ECC public key generated and saved to {args.pubout}')


if __name__ == '__main__':
    main()