import argparse
from instances.dh import DHCipher, DHParameters


def main():
    """
Generate Diffie-Hellman parameters and keys.
    """
    parser = argparse.ArgumentParser(description="Generate Diffie-Hellman parameters and keys")
    parser.add_argument('-s', '--size', type=int, default=2048, choices=[1024, 2048, 3072],
                        help='Key size in bits, default is 2048')
    parser.add_argument('--params', type=str, help="Path for the parameters output file")
    parser.add_argument('--out', type=str, help="Path for the private key output file")
    parser.add_argument('--pubout', type=str, help="Path for the public key output file")

    args = parser.parse_args()

    # Generate parameters if requested
    if args.params:
        params = DHParameters.generate(args.size)
        with open(args.params, 'w') as f:
            f.write(params.export())
        print(f'DH parameters generated and saved to {args.params}')

    # Generate key pair
    private, public = DHCipher.gen_keypair(args.size)

    if args.out is None:
        print(private.export_key())
    else:
        private.export_to_file(args.out)
        print(f'DH private key generated and saved to {args.out}')

    if args.pubout is None:
        print(public.export_key())
    else:
        public.export_to_file(args.pubout)
        print(f'DH public key generated and saved to {args.pubout}')


if __name__ == '__main__':
    main()