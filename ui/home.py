"""Home page module for the cryptography demo application."""

import streamlit as st

def show_home():
    """Display the home page of the application."""
    st.markdown("""
    <div class="crypto-header">
        <h1>🔐 Public Key Cryptography Demo</h1>
        <p>Interactive demonstration of RSA, Diffie-Hellman, and ECC algorithms</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### 🔢 RSA Algorithm
        - **Security**: Based on integer factorization
        - **Key sizes**: 1024, 2048, 3072, 4096 bits
        - **Use cases**: Digital signatures, key exchange
        - **Performance**: Slower but widely supported
        """)
        
    with col2:
        st.markdown("""
        ### 🔄 Diffie-Hellman
        - **Security**: Based on discrete logarithm
        - **Purpose**: Key exchange + secure messaging
        - **Innovation**: First public key algorithm (1976)
        - **Perfect Forward Secrecy**: Session keys
        """)
        
    with col3:
        st.markdown("""
        ### 📈 Elliptic Curves
        - **Security**: Elliptic curve discrete log
        - **Efficiency**: Small keys, high security
        - **Modern**: Used in Bitcoin, TLS 1.3
        - **Performance**: Fast and mobile-friendly
        """)
    
    st.markdown("---")
    st.markdown("""
    ## 🚀 Getting Started
    
    1. **Choose an algorithm** from the sidebar
    2. **Generate keys** using the provided tools
    3. **Encrypt/decrypt messages** or **exchange keys**
    4. **Download your keys** for later use
    
    This demo uses the same implementations from the command-line tools.
    """) 