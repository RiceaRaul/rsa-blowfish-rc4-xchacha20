---
marp: true
theme: default
paginate: true
backgroundColor: #ffffff
style: |
  section {
    font-size: 24px;
    padding: 35px;
  }
  h1 {
    font-size: 36px;
    color: #2B5CE6;
    margin-bottom: 20px;
  }
  h2 {
    font-size: 30px;
    color: #333;
    margin-bottom: 15px;
  }
  ul {
    font-size: 22px;
    line-height: 1.4;
  }
  li {
    margin-bottom: 8px;
  }
  table {
    font-size: 20px;
    margin: 15px auto;
  }
  p {
    font-size: 22px;
    line-height: 1.4;
  }
  strong {
    color: #1a1a1a;
  }
  code {
    font-size: 20px;
  }
  img {
    display: block;
    margin: 0 auto;
  }
  .columns {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 1rem;
  }
  .highlight {
    background: linear-gradient(90deg, #4CAF50, #45a049);
    color: white;
    padding: 10px;
    border-radius: 8px;
    margin: 10px 0;
    font-size: 20px;
  }
  .warning {
    background: linear-gradient(90deg, #ff9800, #f57c00);
    color: white;
    padding: 10px;
    border-radius: 8px;
    margin: 10px 0;
    font-size: 20px;
  }
  .example {
    background: #e3f2fd;
    border-left: 4px solid #2196F3;
    padding: 12px;
    margin: 8px 0;
    font-size: 20px;
  }
---

# Public Key Cryptography
## Fundamentals and Modern Implementations

**Ovidius University of Constanta**
**Faculty of Mathematics and Computer Science**

---

## Agenda

<div class="columns">

**Part I - Fundamentals**
- Introduction to asymmetric cryptography
- Symmetric vs Asymmetric
- Mathematical foundations

**Part II - Algorithms**
- RSA (Rivest-Shamir-Adleman)
- Diffie-Hellman Key Exchange
- ECC (Elliptic Curve Cryptography)

</div>

**Part III - Practical Applications**
- Real-world use cases
- Live demo with implementations

---

## Why Public Key Cryptography?

### The fundamental problem: **Key Distribution**

<div class="example">

**Scenario:** Alice and Bob want to communicate securely, but have never met.

**Problem with symmetric cryptography:**
- How do they share the secret key safely?
- What happens if there are 1000 participants?

</div>

### Solution: **Asymmetric Cryptography**
- Each user has a **key pair**
- **Public key** - can be distributed freely
- **Private key** - kept secret

---

## Fundamental Concepts

<div class="highlight">

**Trapdoor Functions**
- Easy to compute in one direction
- Very hard to reverse without secret information
- Easy to reverse with the "trapdoor" (private key)

</div>

### Required mathematical properties:

1. **Factorization** (RSA): `n = p × q`
2. **Discrete logarithm** (DH): `g^x mod p`
3. **Elliptic curves** (ECC): `P + Q` on elliptic curve

---

## Symmetric vs Asymmetric

<div class="columns">

**Symmetric (AES, DES)**
- Very fast
- Efficient for large volumes
- Key distribution problem
- Managing `n(n-1)/2` keys

**Asymmetric (RSA, ECC)**
- Solves distribution problem
- Digital signatures
- Non-repudiation
- Slower (10-1000x)
- Larger keys

</div>

### Optimal solution: **Hybrid Cryptography**

---

## RSA - Mathematical Foundations

<div class="example">

**Principle:** Difficulty of factoring large numbers

**Key Generation:**
1. Choose two large primes: `p` and `q`
2. Compute `n = p × q` (modulus)
3. Compute `φ(n) = (p-1)(q-1)`
4. Choose `e` such that `gcd(e, φ(n)) = 1`
5. Compute `d` such that `e × d ≡ 1 (mod φ(n))`

**Keys:** Public `(n, e)`, Private `(n, d)`

</div>

---

## RSA - Encryption/Decryption

<div class="columns">

**Encryption**
```
c = m^e mod n
```
- `m` = original message
- `c` = encrypted message
- `(n, e)` = public key

**Decryption**
```
m = c^d mod n
```
- `c` = encrypted message
- `m` = original message
- `(n, d)` = private key

</div>

### Why it works?
**Theorem:** `(m^e)^d ≡ m (mod n)`

---

## RSA - Practical Example

<div class="example">

**Key Generation:** (small numbers for demonstration)
- `p = 61, q = 53` → `n = 3233`
- `φ(n) = 60 × 52 = 3120`
- `e = 17`, `d = 2753`

**Encryption:** `m = 123`
- `c = 123^17 mod 3233 = 855`

**Decryption:**
- `m = 855^2753 mod 3233 = 123` ✓

</div>

---

## RSA - Advantages and Disadvantages

<div class="columns">

**Advantages**
- Conceptually simple
- Well-tested (45+ years)
- Universal support
- Digital signatures

**Disadvantages**
- Large keys (2048-4096 bits)
- Slow for large volumes
- Vulnerable to quantum attacks
- Requires OAEP padding

</div>

### Current Security
- **2048 bits** - security until 2030
- **3072+ bits** - extended security

---

## Diffie-Hellman Key Exchange

<div class="highlight">

**Problem solved:** How do Alice and Bob establish a shared secret key over an insecure channel?

</div>

### Mathematical foundations
**Principle:** Difficulty of computing discrete logarithm
- Given `g, p, g^x mod p`, it's hard to find `x`
- But `g^x mod p` is easy to compute

---

## Diffie-Hellman - Algorithm

<div class="example">

**Public setup:** `p` (large prime), `g` (generator)

**Alice:** Choose secret `a`, compute `A = g^a mod p`, send `A`
**Bob:** Choose secret `b`, compute `B = g^b mod p`, send `B`

**Shared secret key:**
- Alice: `K = B^a mod p = g^(ab) mod p`
- Bob: `K = A^b mod p = g^(ab) mod p`

</div>

### Numerical example
`p=23, g=5, a=6, b=15` → `A=8, B=19` → `K=2`

---

## Diffie-Hellman - Applications

### Internet Protocols
- **TLS/SSL** - HTTPS connections
- **IPSec VPN** - Secure tunnels
- **SSH** - Server connections

### Secure Messaging
- **Signal, WhatsApp** - Perfect Forward Secrecy
- **Telegram** - Secret Chats

<div class="warning">

**Vulnerability:** Man-in-the-Middle attacks
**Solution:** Authentication with certificates

</div>

---

## ECC - Elliptic Curve Cryptography

<div class="highlight">

**Principle:** Elliptic curve mathematics provides the same security with much smaller keys

</div>

### Elliptic curve equation
```
y² = x³ + ax + b (mod p)
```

| Security | RSA/DH | ECC |
|----------|--------|-----|
| 112-bit  | 2048   | 224 |
| 128-bit  | 3072   | 256 |
| 192-bit  | 7680   | 384 |

---

## ECC - Operations and Algorithms

### Point addition on curve
- **Geometric:** Line through P and Q intersects curve
- **Scalar Multiplication:** `k × P = P + P + ... + P` (k times)

### Main algorithms
- **ECDH** - Key exchange on elliptic curves
- **ECDSA** - Digital signatures (Bitcoin, SSL)
- **ECIES** - Complete hybrid encryption system

### Standard curves
- **P-256** (secp256r1) - Most widely used
- **P-384** (secp384r1) - High security

---

## ECC - Advantages and Applications

<div class="columns">

**Advantages**
- Very small keys
- Excellent performance
- Ideal for mobile/IoT
- Low energy consumption

**Applications**
- **Bitcoin** - ECDSA signatures
- **TLS 1.3** - ECDH key exchange
- **Smart Cards** - Small size
- **Mobile Apps** - WhatsApp, Signal

</div>

---

## Practical Applications - E-commerce

<div class="example">

**Scenario:** Online shopping

**1. HTTPS Connection (TLS):**
Browser and server perform **ECDH** key exchange

**2. Card Payment:**
Card data encrypted with **bank's public key**

**3. Transaction Confirmation:**
Bank signs with **ECDSA**

</div>

---

## Practical Applications - Messaging

<div class="example">

**Signal/WhatsApp - Perfect Forward Secrecy**

**1. Registration:** Generate permanent **ECDH** pair
**2. Conversation:** **Triple DH** - 3 simultaneous exchanges
**3. For each message:** New temporary **ECDH** keys

**Result:** Even if your phone is stolen, previous messages remain secure!

</div>

---

## Practical Applications - Blockchain

<div class="example">

**Bitcoin - Digital Wallet**

**Private key:** 256 random bits
**Public key:** Point on secp256k1 curve
**Bitcoin address:** Hash of public key

**Transaction:** Signed with **ECDSA**
**Verification:** Anyone can verify with public key

</div>

---

## Live Demo

<div class="highlight">

**What we will demonstrate:**

**1. RSA Demo**
- Generate 2048-bit keys
- Encrypt and decrypt message

**2. ECC Demo**
- Compare P-256 vs P-384
- Small key efficiency

**3. Diffie-Hellman Demo**
- Simulate Alice & Bob
- Shared secret computation

</div>

---

## Security Considerations

<div class="warning">

**Quantum Computing:**
- Shor's algorithm can break RSA and ECC
- Estimated timeline: 10-20 years
- Solution: **Post-Quantum Cryptography**

</div>

### Current best practices
- **RSA:** 2048+ bits, OAEP padding
- **ECC:** P-256+ curves, secure implementations
- **Key management:** Secure storage, periodic rotation

---

## Future of Cryptography

<div class="columns">

**Post-Quantum Crypto:**
- **Lattice-based** (Kyber)
- **Code-based** (McEliece)
- **Hash-based** (SPHINCS+)

**Other innovations:**
- **Homomorphic Encryption**
- **Zero-Knowledge Proofs**
- **Quantum Key Distribution**

</div>

### NIST Timeline: 2024-2030 migration to post-quantum algorithms

---

## Conclusions

<div class="highlight">

**Key takeaways:**
- **Asymmetric cryptography** solves key distribution
- **RSA** - solid and simple, but large keys
- **Diffie-Hellman** - revolutionary for key exchange
- **ECC** - the future: high security with small keys
- **Applications** are everywhere: web, mobile, blockchain

</div>

### Next steps
1. Experiment with demo implementations
2. Study modern protocols (TLS 1.3)
3. Follow post-quantum cryptography evolution

---

## Questions and Discussion

<div class="highlight">

**Questions for thought:**

1. Why not use only asymmetric cryptography?
2. How does quantum computing affect current security?
3. What are the RSA vs ECC trade-offs?
4. How does Perfect Forward Secrecy work?

</div>

**Thank you for your attention!**