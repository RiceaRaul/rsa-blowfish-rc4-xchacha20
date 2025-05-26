#!/bin/bash

echo "========================================"
echo "       DEMO RSA ENCRYPTION             "
echo "========================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create demo directory
DEMO_DIR="demo_rsa_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

echo -e "${BLUE}📁 Created demo directory: $DEMO_DIR${NC}"
echo

# Step 1: Generate RSA key pair
echo -e "${YELLOW}🔑 Step 1: Generating RSA key pair (2048 bits)${NC}"
python3 ../gen_rsa_key.py -s 2048 --out rsa_private.pem --pubout rsa_public.pem
echo -e "${GREEN}✅ RSA keys generated successfully!${NC}"
echo

# Step 2: Create test message
echo -e "${YELLOW}📝 Step 2: Creating test message${NC}"
echo "This is a secret message for RSA encryption demo!" > message.txt
echo -e "${GREEN}✅ Test message created: $(cat message.txt)${NC}"
echo

# Step 3: Encrypt the message
echo -e "${YELLOW}🔒 Step 3: Encrypting message with RSA public key${NC}"
python3 ../main.py -c rsa -e --keyfile rsa_public.pem --in message.txt --out encrypted.txt
echo -e "${GREEN}✅ Message encrypted successfully!${NC}"
echo -e "${BLUE}📄 Encrypted content (base64):${NC}"
head -c 100 encrypted.txt && echo "..."
echo

# Step 4: Decrypt the message
echo -e "${YELLOW}🔓 Step 4: Decrypting message with RSA private key${NC}"
python3 ../main.py -c rsa -d --keyfile rsa_private.pem --in encrypted.txt --out decrypted.txt
echo -e "${GREEN}✅ Message decrypted successfully!${NC}"
echo -e "${BLUE}📄 Decrypted content:${NC}"
cat decrypted.txt
echo

# Step 5: Verify integrity
echo -e "${YELLOW}🔍 Step 5: Verifying integrity${NC}"
if diff message.txt decrypted.txt > /dev/null; then
    echo -e "${GREEN}✅ SUCCESS: Original and decrypted messages match perfectly!${NC}"
else
    echo -e "${RED}❌ ERROR: Messages don't match!${NC}"
fi
echo

# Show file sizes
echo -e "${BLUE}📊 File sizes:${NC}"
echo "Original message: $(wc -c < message.txt) bytes"
echo "Encrypted message: $(wc -c < encrypted.txt) bytes"
echo "Private key: $(wc -c < rsa_private.pem) bytes"
echo "Public key: $(wc -c < rsa_public.pem) bytes"
echo

# Show key information
echo -e "${BLUE}🔑 Key Information:${NC}"
echo "Private key preview:"
head -3 rsa_private.pem
echo "..."
tail -1 rsa_private.pem
echo
echo "Public key preview:"
head -3 rsa_public.pem
echo "..."
tail -1 rsa_public.pem
echo

echo -e "${GREEN}========================================"
echo -e "       RSA DEMO COMPLETED! ✅           "
echo -e "========================================${NC}"
echo -e "${BLUE}Demo files are in: $(pwd)${NC}"
echo

cd ..