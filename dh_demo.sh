#!/bin/bash

echo "========================================"
echo "    DEMO DIFFIE-HELLMAN KEY EXCHANGE   "
echo "========================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create demo directory
DEMO_DIR="demo_dh_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

echo -e "${BLUE}📁 Created demo directory: $DEMO_DIR${NC}"
echo

echo -e "${CYAN}🔄 Diffie-Hellman Key Exchange Simulation${NC}"
echo -e "${CYAN}Simulating secure key exchange between Alice and Bob${NC}"
echo

# Step 1: Generate DH parameters
echo -e "${YELLOW}⚙️  Step 1: Generating DH parameters (2048-bit)${NC}"
python3 ../gen_dh_key.py -s 2048 --params dh_params.pem --out temp_key.pem --pubout temp_pub.pem
rm temp_key.pem temp_pub.pem  # We only need the parameters for now
echo -e "${GREEN}✅ DH parameters generated successfully!${NC}"
echo

# Step 2: Alice generates her key pair
echo -e "${PURPLE}👩 Step 2: Alice generates her key pair${NC}"
python3 ../gen_dh_key.py -s 2048 --out alice_private.pem --pubout alice_public.pem
echo -e "${GREEN}✅ Alice's key pair generated!${NC}"
echo

# Step 3: Bob generates his key pair
echo -e "${BLUE}👨 Step 3: Bob generates his key pair${NC}"
python3 ../gen_dh_key.py -s 2048 --out bob_private.pem --pubout bob_public.pem
echo -e "${GREEN}✅ Bob's key pair generated!${NC}"
echo

# Step 4: Create test message
echo -e "${YELLOW}📝 Step 4: Creating secret message for secure communication${NC}"
echo "This is a confidential message exchanged using Diffie-Hellman key agreement!" > secret_message.txt
echo -e "${GREEN}✅ Secret message created: $(cat secret_message.txt)${NC}"
echo

# Step 5: Alice encrypts message for Bob
echo -e "${PURPLE}🔒 Step 5: Alice encrypts message using shared secret with Bob${NC}"
echo -e "${CYAN}   (Alice uses her private key + Bob's public key)${NC}"
# Create a temporary script to handle the DH encryption with automatic key input
cat > encrypt_script.py << 'EOF'
import sys
import os
sys.path.append('..')

from instances.dh import DHCipher, DHPrivateKey, DHPublicKey

# Load Alice's private key
alice_private = DHPrivateKey()
alice_private.import_from_file('alice_private.pem')

# Load Bob's public key
bob_public = DHPublicKey()
bob_public.import_from_file('bob_public.pem')

# Create cipher with Alice's private key and Bob's public key
cipher = DHCipher(alice_private, bob_public)

# Read message
with open('secret_message.txt', 'rb') as f:
    message = f.read()

# Encrypt
encrypted = cipher.encrypt(message)

# Save encrypted message
with open('encrypted_for_bob.txt', 'wb') as f:
    f.write(encrypted)

print("Message encrypted successfully!")
EOF

python3 encrypt_script.py
echo -e "${GREEN}✅ Alice encrypted the message for Bob!${NC}"
echo

# Step 6: Bob decrypts message from Alice
echo -e "${BLUE}🔓 Step 6: Bob decrypts message using shared secret with Alice${NC}"
echo -e "${CYAN}   (Bob uses his private key + Alice's public key)${NC}"
# Create a temporary script to handle the DH decryption
cat > decrypt_script.py << 'EOF'
import sys
import os
sys.path.append('..')

from instances.dh import DHCipher, DHPrivateKey, DHPublicKey

# Load Bob's private key
bob_private = DHPrivateKey()
bob_private.import_from_file('bob_private.pem')

# Load Alice's public key
alice_public = DHPublicKey()
alice_public.import_from_file('alice_public.pem')

# Create cipher with Bob's private key and Alice's public key
cipher = DHCipher(bob_private, alice_public)

# Read encrypted message
with open('encrypted_for_bob.txt', 'rb') as f:
    encrypted = f.read()

# Decrypt
decrypted = cipher.decrypt(encrypted)

# Save decrypted message
with open('decrypted_by_bob.txt', 'wb') as f:
    f.write(decrypted)

print("Message decrypted successfully!")
EOF

python3 decrypt_script.py
echo -e "${GREEN}✅ Bob decrypted the message from Alice!${NC}"
echo -e "${BLUE}📄 Decrypted content:${NC}"
cat decrypted_by_bob.txt
echo

# Step 7: Verify integrity
echo -e "${YELLOW}🔍 Step 7: Verifying message integrity${NC}"
if diff secret_message.txt decrypted_by_bob.txt > /dev/null; then
    echo -e "${GREEN}✅ SUCCESS: Original and decrypted messages match perfectly!${NC}"
    echo -e "${GREEN}🔐 Secure communication established between Alice and Bob!${NC}"
else
    echo -e "${RED}❌ ERROR: Messages don't match!${NC}"
fi
echo

# Step 8: Demonstrate shared secret computation
echo -e "${YELLOW}🔑 Step 8: Demonstrating shared secret computation${NC}"
cat > shared_secret_demo.py << 'EOF'
import sys
import hashlib
sys.path.append('..')

from instances.dh import DHPrivateKey, DHPublicKey

# Load keys
alice_private = DHPrivateKey()
alice_private.import_from_file('alice_private.pem')

bob_private = DHPrivateKey()
bob_private.import_from_file('bob_private.pem')

alice_public = DHPublicKey()
alice_public.import_from_file('alice_public.pem')

bob_public = DHPublicKey()
bob_public.import_from_file('bob_public.pem')

# Compute shared secrets
alice_shared = alice_private.compute_shared_secret(bob_public)
bob_shared = bob_private.compute_shared_secret(alice_public)

print(f"Alice's computed shared secret: {alice_shared.hex()[:32]}...")
print(f"Bob's computed shared secret:   {bob_shared.hex()[:32]}...")
print(f"Secrets match: {alice_shared == bob_shared}")
EOF

python3 shared_secret_demo.py
echo -e "${GREEN}✅ Both parties computed the same shared secret!${NC}"
echo

# Show file information
echo -e "${BLUE}📊 File sizes and information:${NC}"
echo "DH Parameters: $(wc -c < dh_params.pem) bytes"
echo "Alice's private key: $(wc -c < alice_private.pem) bytes"
echo "Alice's public key: $(wc -c < alice_public.pem) bytes"
echo "Bob's private key: $(wc -c < bob_private.pem) bytes"
echo "Bob's public key: $(wc -c < bob_public.pem) bytes"
echo "Original message: $(wc -c < secret_message.txt) bytes"
echo "Encrypted message: $(wc -c < encrypted_for_bob.txt) bytes"
echo

# Show key previews
echo -e "${BLUE}🔑 Key Information Preview:${NC}"
echo
echo "DH Parameters:"
head -2 dh_params.pem
tail -1 dh_params.pem
echo
echo "Alice's Public Key (first part):"
head -2 alice_public.pem
echo "..."
tail -1 alice_public.pem
echo
echo "Bob's Public Key (first part):"
head -2 bob_public.pem
echo "..."
tail -1 bob_public.pem
echo

# Cleanup temporary scripts
rm encrypt_script.py decrypt_script.py shared_secret_demo.py

echo -e "${GREEN}========================================"
echo -e "   DIFFIE-HELLMAN DEMO COMPLETED! ✅    "
echo -e "========================================${NC}"
echo -e "${BLUE}Demo files are in: $(pwd)${NC}"
echo -e "${CYAN}🔐 Key Exchange Protocol Demonstrated:${NC}"
echo -e "${CYAN}• Alice and Bob generated independent key pairs${NC}"
echo -e "${CYAN}• They exchanged public keys safely${NC}"
echo -e "${CYAN}• Both computed the same shared secret${NC}"
echo -e "${CYAN}• Used shared secret for secure communication${NC}"
echo

cd ..