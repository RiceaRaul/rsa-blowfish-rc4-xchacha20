#!/bin/bash

echo "========================================"
echo "       DEMO ECC ENCRYPTION             "
echo "========================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Save original directory
ORIGINAL_DIR=$(pwd)

# Create demo directory
DEMO_DIR="demo_ecc_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

echo -e "${BLUE}📁 Created demo directory: $DEMO_DIR${NC}"
echo

# Check if we're in the right location
if [ ! -f "../gen_ecc_key.py" ]; then
    echo -e "${RED}❌ Error: gen_ecc_key.py not found. Make sure you're running from the project root.${NC}"
    cd "$ORIGINAL_DIR"
    exit 1
fi

# Demo for P-256 curve
echo -e "${PURPLE}🔸 DEMO WITH P-256 CURVE (256-bit)${NC}"
echo

# Step 1: Generate ECC key pair (P-256) with corrected script
echo -e "${YELLOW}🔑 Step 1: Generating ECC key pair (P-256, 256-bit)${NC}"

# Create a temporary fixed gen_ecc_key script
cat > gen_ecc_key_fixed.py << 'EOF'
import argparse
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

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
EOF

python3 gen_ecc_key_fixed.py -s 256 --out ecc_private_256.pem --pubout ecc_public_256.pem

if [ ! -f "ecc_private_256.pem" ] || [ ! -f "ecc_public_256.pem" ]; then
    echo -e "${RED}❌ Error: Failed to generate ECC P-256 keys${NC}"
    cd "$ORIGINAL_DIR"
    exit 1
fi

echo -e "${GREEN}✅ ECC P-256 keys generated successfully!${NC}"
echo

# Step 2: Create test message
echo -e "${YELLOW}📝 Step 2: Creating test message${NC}"
echo "ECC encryption with P-256 curve - secure and efficient!" > message_256.txt
echo -e "${GREEN}✅ Test message created: $(cat message_256.txt)${NC}"
echo

# Step 3: Encrypt the message
echo -e "${YELLOW}🔒 Step 3: Encrypting message with ECC public key (P-256)${NC}"

cat > encrypt_ecc_256.py << 'EOF'
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from instances.ecc import ECCCipher, ECPublicKey

def encrypt_message():
    # Read the message
    with open('message_256.txt', 'rb') as f:
        message = f.read()
    
    # Load public key
    public_key = ECPublicKey()
    public_key.import_from_file('ecc_public_256.pem')
    
    # Create cipher and encrypt
    cipher = ECCCipher(public_key=public_key)
    encrypted = cipher.encrypt(message)
    
    # Save encrypted message
    with open('encrypted_256.txt', 'wb') as f:
        f.write(encrypted)
    
    print("Message encrypted successfully with P-256!")

if __name__ == '__main__':
    encrypt_message()
EOF

python3 encrypt_ecc_256.py

if [ ! -f "encrypted_256.txt" ]; then
    echo -e "${RED}❌ Error: P-256 encryption failed${NC}"
    cd "$ORIGINAL_DIR"
    exit 1
fi

echo -e "${GREEN}✅ Message encrypted successfully with P-256!${NC}"
echo -e "${BLUE}📄 Encrypted content (base64):${NC}"
head -c 100 encrypted_256.txt && echo "..."
echo

# Step 4: Decrypt the message
echo -e "${YELLOW}🔓 Step 4: Decrypting message with ECC private key${NC}"

cat > decrypt_ecc_256.py << 'EOF'
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from instances.ecc import ECCCipher, ECPrivateKey

def decrypt_message():
    # Read the encrypted message
    with open('encrypted_256.txt', 'rb') as f:
        encrypted = f.read()
    
    # Load private key
    private_key = ECPrivateKey()
    private_key.import_from_file('ecc_private_256.pem')
    
    # Create cipher and decrypt
    cipher = ECCCipher(private_key=private_key)
    decrypted = cipher.decrypt(encrypted)
    
    # Save decrypted message
    with open('decrypted_256.txt', 'wb') as f:
        f.write(decrypted)
    
    print("Message decrypted successfully!")

if __name__ == '__main__':
    decrypt_message()
EOF

python3 decrypt_ecc_256.py

if [ ! -f "decrypted_256.txt" ]; then
    echo -e "${RED}❌ Error: P-256 decryption failed${NC}"
    cd "$ORIGINAL_DIR"
    exit 1
fi

echo -e "${GREEN}✅ Message decrypted successfully!${NC}"
echo -e "${BLUE}📄 Decrypted content:${NC}"
cat decrypted_256.txt
echo

# Step 5: Verify integrity for P-256
echo -e "${YELLOW}🔍 Step 5: Verifying integrity (P-256)${NC}"
if diff message_256.txt decrypted_256.txt > /dev/null; then
    echo -e "${GREEN}✅ SUCCESS: P-256 - Original and decrypted messages match perfectly!${NC}"
else
    echo -e "${RED}❌ ERROR: P-256 - Messages don't match!${NC}"
fi
echo

echo "----------------------------------------"
echo

# Demo for P-384 curve
echo -e "${PURPLE}🔸 DEMO WITH P-384 CURVE (384-bit)${NC}"
echo

# Step 6: Generate ECC key pair (P-384)
echo -e "${YELLOW}🔑 Step 6: Generating ECC key pair (P-384, 384-bit)${NC}"
python3 gen_ecc_key_fixed.py -s 384 --out ecc_private_384.pem --pubout ecc_public_384.pem

if [ ! -f "ecc_private_384.pem" ] || [ ! -f "ecc_public_384.pem" ]; then
    echo -e "${RED}❌ Error: Failed to generate ECC P-384 keys${NC}"
    cd "$ORIGINAL_DIR"
    exit 1
fi

echo -e "${GREEN}✅ ECC P-384 keys generated successfully!${NC}"
echo

# Step 7: Create test message for P-384
echo -e "${YELLOW}📝 Step 7: Creating test message for P-384${NC}"
echo "ECC encryption with P-384 curve - enhanced security with larger key size!" > message_384.txt
echo -e "${GREEN}✅ Test message created: $(cat message_384.txt)${NC}"
echo

# Step 8: Encrypt with P-384
echo -e "${YELLOW}🔒 Step 8: Encrypting message with ECC public key (P-384)${NC}"

cat > encrypt_ecc_384.py << 'EOF'
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from instances.ecc import ECCCipher, ECPublicKey

def encrypt_message():
    # Read the message
    with open('message_384.txt', 'rb') as f:
        message = f.read()
    
    # Load public key
    public_key = ECPublicKey()
    public_key.import_from_file('ecc_public_384.pem')
    
    # Create cipher and encrypt
    cipher = ECCCipher(public_key=public_key)
    encrypted = cipher.encrypt(message)
    
    # Save encrypted message
    with open('encrypted_384.txt', 'wb') as f:
        f.write(encrypted)
    
    print("Message encrypted successfully with P-384!")

if __name__ == '__main__':
    encrypt_message()
EOF

python3 encrypt_ecc_384.py

if [ ! -f "encrypted_384.txt" ]; then
    echo -e "${RED}❌ Error: P-384 encryption failed${NC}"
    cd "$ORIGINAL_DIR"
    exit 1
fi

echo -e "${GREEN}✅ Message encrypted successfully with P-384!${NC}"
echo

# Step 9: Decrypt with P-384
echo -e "${YELLOW}🔓 Step 9: Decrypting message with ECC private key (P-384)${NC}"

cat > decrypt_ecc_384.py << 'EOF'
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from instances.ecc import ECCCipher, ECPrivateKey

def decrypt_message():
    # Read the encrypted message
    with open('encrypted_384.txt', 'rb') as f:
        encrypted = f.read()
    
    # Load private key
    private_key = ECPrivateKey()
    private_key.import_from_file('ecc_private_384.pem')
    
    # Create cipher and decrypt
    cipher = ECCCipher(private_key=private_key)
    decrypted = cipher.decrypt(encrypted)
    
    # Save decrypted message
    with open('decrypted_384.txt', 'wb') as f:
        f.write(decrypted)
    
    print("Message decrypted successfully!")

if __name__ == '__main__':
    decrypt_message()
EOF

python3 decrypt_ecc_384.py

if [ ! -f "decrypted_384.txt" ]; then
    echo -e "${RED}❌ Error: P-384 decryption failed${NC}"
    cd "$ORIGINAL_DIR"
    exit 1
fi

echo -e "${GREEN}✅ Message decrypted successfully!${NC}"
echo -e "${BLUE}📄 Decrypted content:${NC}"
cat decrypted_384.txt
echo

# Step 10: Verify integrity for P-384
echo -e "${YELLOW}🔍 Step 10: Verifying integrity (P-384)${NC}"
if diff message_384.txt decrypted_384.txt > /dev/null; then
    echo -e "${GREEN}✅ SUCCESS: P-384 - Original and decrypted messages match perfectly!${NC}"
else
    echo -e "${RED}❌ ERROR: P-384 - Messages don't match!${NC}"
fi
echo

# Show comparison
echo -e "${BLUE}📊 Comparison between P-256 and P-384:${NC}"
echo
echo "P-256 files:"
echo "  Original message: $(wc -c < message_256.txt) bytes"
echo "  Encrypted message: $(wc -c < encrypted_256.txt) bytes"
echo "  Private key: $(wc -c < ecc_private_256.pem) bytes"
echo "  Public key: $(wc -c < ecc_public_256.pem) bytes"
echo
echo "P-384 files:"
echo "  Original message: $(wc -c < message_384.txt) bytes"
echo "  Encrypted message: $(wc -c < encrypted_384.txt) bytes"
echo "  Private key: $(wc -c < ecc_private_384.pem) bytes"
echo "  Public key: $(wc -c < ecc_public_384.pem) bytes"
echo

# Show key information
echo -e "${BLUE}🔑 ECC Key Information:${NC}"
echo
echo "P-256 Private key preview:"
head -2 ecc_private_256.pem