"""RSA page module for the cryptography demo application."""

import streamlit as st
import base64
from instances.rsa import RSACipher

def show_rsa_page():
    """Display the RSA page of the application."""
    st.markdown("""
    <div class="crypto-header">
        <h1>🔢 RSA Algorithm</h1>
        <p>Rivest-Shamir-Adleman Public Key Cryptosystem</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🔑 Key Generation", "🔒 Encryption", "🔓 Decryption"])
    
    with tab1:
        _show_key_generation()
    
    with tab2:
        _show_encryption()
    
    with tab3:
        _show_decryption()

def _show_key_generation():
    """Show the key generation tab content."""
    st.header("RSA Key Generation")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        key_size = st.selectbox(
            "Key Size (bits)",
            [1024, 2048, 3072, 4096],
            index=1
        )
        
        if st.button("🔑 Generate RSA Keys", type="primary"):
            with st.spinner(f"Generating {key_size}-bit RSA keys..."):
                try:
                    private_key, public_key = RSACipher.gen_keypair(key_size)
                    
                    # Store in session state
                    st.session_state.rsa_private = private_key
                    st.session_state.rsa_public = public_key
                    
                    st.success(f"✅ Generated {key_size}-bit RSA key pair!")
                    
                except Exception as e:
                    st.error(f"Error generating keys: {e}")
    
    with col2:
        if 'rsa_private' in st.session_state and 'rsa_public' in st.session_state:
            st.markdown("### 📋 Generated Keys")
            
            # Private key info
            st.markdown("**🔒 Private Key:**")
            private_pem = st.session_state.rsa_private.export_key()
            st.code(private_pem[:200] + "..." if len(private_pem) > 200 else private_pem, language="text")
            
            # Download button for private key
            st.download_button(
                "💾 Download Private Key",
                private_pem,
                file_name="rsa_private.pem",
                mime="text/plain"
            )
            
            # Public key info
            st.markdown("**🔓 Public Key:**")
            public_pem = st.session_state.rsa_public.export_key()
            st.code(public_pem[:200] + "..." if len(public_pem) > 200 else public_pem, language="text")
            
            # Download button for public key
            st.download_button(
                "💾 Download Public Key",
                public_pem,
                file_name="rsa_public.pem",
                mime="text/plain"
            )
            
            # Key information
            st.markdown("### 📊 Key Information")
            col_info1, col_info2 = st.columns(2)
            with col_info1:
                st.metric("Private Key Size", f"{len(private_pem)} bytes")
                st.metric("Key Length", f"{key_size} bits")
            with col_info2:
                st.metric("Public Key Size", f"{len(public_pem)} bytes")
                st.metric("Algorithm", "RSA-OAEP")

def _show_encryption():
    """Show the encryption tab content."""
    st.header("RSA Encryption")
    
    # Check if keys exist
    if 'rsa_public' not in st.session_state:
        st.warning("⚠️ Please generate RSA keys first in the Key Generation tab.")
        return
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📝 Input")
        
        # Message input
        message_input = st.text_area(
            "Message to encrypt:",
            placeholder="Enter your secret message here...",
            height=100
        )
        
        # File upload option
        st.markdown("**Or upload a file:**")
        uploaded_file = st.file_uploader(
            "Choose a file to encrypt",
            type=['txt', 'pdf', 'doc', 'docx'],
            key="encrypt_file"
        )
        
        if uploaded_file is not None:
            message_input = uploaded_file.read().decode('utf-8', errors='ignore')
            st.text_area("File content:", message_input, height=100, disabled=True)
        
        if st.button("🔒 Encrypt Message", type="primary") and message_input:
            with st.spinner("Encrypting message..."):
                try:
                    cipher = RSACipher(public_key=st.session_state.rsa_public)
                    encrypted = cipher.encrypt(message_input.encode('utf-8'))
                    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                    
                    st.session_state.rsa_encrypted = encrypted_b64
                    st.success("✅ Message encrypted successfully!")
                    
                except Exception as e:
                    st.error(f"Encryption error: {e}")
    
    with col2:
        st.subheader("🔒 Encrypted Output")
        
        if 'rsa_encrypted' in st.session_state:
            encrypted_text = st.session_state.rsa_encrypted
            st.code(encrypted_text, language="text")
            
            # Download encrypted message
            st.download_button(
                "💾 Download Encrypted Message",
                encrypted_text,
                file_name="encrypted_message.txt",
                mime="text/plain"
            )
            
            st.metric("Encrypted Size", f"{len(encrypted_text)} characters")

def _show_decryption():
    """Show the decryption tab content."""
    st.header("RSA Decryption")
    
    # Check if private key exists
    if 'rsa_private' not in st.session_state:
        st.warning("⚠️ Please generate RSA keys first in the Key Generation tab.")
        return
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("🔒 Encrypted Input")
        
        # Use encrypted message from previous tab or manual input
        if 'rsa_encrypted' in st.session_state:
            encrypted_input = st.text_area(
                "Encrypted message (Base64):",
                value=st.session_state.rsa_encrypted,
                height=150
            )
        else:
            encrypted_input = st.text_area(
                "Encrypted message (Base64):",
                placeholder="Paste your encrypted message here...",
                height=150
            )
        
        # File upload for encrypted message
        st.markdown("**Or upload encrypted file:**")
        encrypted_file = st.file_uploader(
            "Choose encrypted file",
            type=['txt'],
            key="decrypt_file"
        )
        
        if encrypted_file is not None:
            encrypted_input = encrypted_file.read().decode('utf-8')
        
        if st.button("🔓 Decrypt Message", type="primary") and encrypted_input:
            with st.spinner("Decrypting message..."):
                try:
                    cipher = RSACipher(private_key=st.session_state.rsa_private)
                    encrypted_bytes = base64.b64decode(encrypted_input)
                    decrypted_text = cipher.decrypt(encrypted_bytes)
                    
                    st.session_state.rsa_decrypted = decrypted_text
                    st.success("✅ Message decrypted successfully!")
                    
                except Exception as e:
                    st.error(f"Decryption error: {e}")
    
    with col2:
        st.subheader("📝 Decrypted Output")
        
        if 'rsa_decrypted' in st.session_state:
            decrypted_text = st.session_state.rsa_decrypted
            st.text_area("Decrypted message:", decrypted_text, height=150, disabled=True)
            
            # Download decrypted message
            st.download_button(
                "💾 Download Decrypted Message",
                decrypted_text,
                file_name="decrypted_message.txt",
                mime="text/plain"
            )
            
            st.metric("Original Size", f"{len(decrypted_text)} characters") 