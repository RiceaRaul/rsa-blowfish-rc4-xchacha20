"""ECC page module for the cryptography demo application."""

import streamlit as st
import base64
from instances.ecc import ECCCipher

def show_ecc_page():
    """Display the ECC page of the application."""
    st.markdown("""
    <div class="crypto-header">
        <h1>📈 Elliptic Curve Cryptography</h1>
        <p>High Security with Small Keys</p>
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
    st.header("ECC Key Generation")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        curve_size = st.selectbox(
            "Curve Size",
            [256, 384],
            format_func=lambda x: f"P-{x} ({x}-bit)"
        )
        
        if st.button("🔑 Generate ECC Keys", type="primary"):
            with st.spinner(f"Generating P-{curve_size} ECC keys..."):
                try:
                    private_key, public_key = ECCCipher.gen_keypair(curve_size)
                    
                    st.session_state.ecc_private = private_key
                    st.session_state.ecc_public = public_key
                    st.session_state.ecc_curve_size = curve_size
                    
                    st.success(f"✅ Generated P-{curve_size} ECC key pair!")
                    
                except Exception as e:
                    st.error(f"Error generating keys: {e}")
    
    with col2:
        if 'ecc_private' in st.session_state and 'ecc_public' in st.session_state:
            curve_size = st.session_state.ecc_curve_size
            st.markdown(f"### 📋 Generated P-{curve_size} Keys")
            
            # Private key
            private_pem = st.session_state.ecc_private.export_key()
            st.markdown("**🔒 Private Key:**")
            st.code(private_pem[:200] + "..." if len(private_pem) > 200 else private_pem, language="text")
            
            st.download_button(
                "💾 Download Private Key",
                private_pem,
                file_name=f"ecc_private_p{curve_size}.pem",
                mime="text/plain"
            )
            
            # Public key
            public_pem = st.session_state.ecc_public.export_key()
            st.markdown("**🔓 Public Key:**")
            st.code(public_pem[:200] + "..." if len(public_pem) > 200 else public_pem, language="text")
            
            st.download_button(
                "💾 Download Public Key",
                public_pem,
                file_name=f"ecc_public_p{curve_size}.pem",
                mime="text/plain"
            )
            
            # Comparison with RSA
            st.markdown("### 📊 ECC vs RSA Comparison")
            rsa_equivalent = {256: 3072, 384: 7680}[curve_size]
            col_ecc, col_rsa = st.columns(2)
            
            with col_ecc:
                st.metric(f"ECC P-{curve_size}", f"{len(private_pem)} bytes")
            
            with col_rsa:
                st.metric(f"RSA {rsa_equivalent}", f"~{rsa_equivalent//8*5} bytes", delta=f"-{rsa_equivalent//8*4} bytes")

def _show_encryption():
    """Show the encryption tab content."""
    st.header("ECC Encryption")
    
    if 'ecc_public' not in st.session_state:
        st.warning("⚠️ Please generate ECC keys first in the Key Generation tab.")
        return
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📝 Input")
        
        message_input = st.text_area(
            "Message to encrypt:",
            placeholder="Enter your message here...",
            height=100
        )
        
        # File upload option
        st.markdown("**Or upload a file:**")
        uploaded_file = st.file_uploader(
            "Choose a file to encrypt",
            type=['txt'],
            key="ecc_encrypt_file"
        )
        
        if uploaded_file is not None:
            message_input = uploaded_file.read().decode('utf-8', errors='ignore')
            st.text_area("File content:", message_input, height=100, disabled=True)
        
        if st.button("🔒 Encrypt with ECC", type="primary") and message_input:
            with st.spinner("Encrypting message..."):
                try:
                    cipher = ECCCipher(public_key=st.session_state.ecc_public)
                    encrypted = cipher.encrypt(message_input.encode('utf-8'))
                    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                    
                    st.session_state.ecc_encrypted = encrypted_b64
                    st.success("✅ Message encrypted successfully!")
                    
                except Exception as e:
                    st.error(f"Encryption error: {e}")
    
    with col2:
        st.subheader("🔒 Encrypted Output")
        
        if 'ecc_encrypted' in st.session_state:
            encrypted_text = st.session_state.ecc_encrypted
            st.code(encrypted_text, language="text")
            
            st.download_button(
                "💾 Download Encrypted Message",
                encrypted_text,
                file_name="ecc_encrypted_message.txt",
                mime="text/plain"
            )
            
            curve_size = st.session_state.ecc_curve_size
            st.metric("Encrypted Size", f"{len(encrypted_text)} characters")
            st.info(f"🔐 Encrypted using P-{curve_size} curve")

def _show_decryption():
    """Show the decryption tab content."""
    st.header("ECC Decryption")
    
    if 'ecc_private' not in st.session_state:
        st.warning("⚠️ Please generate ECC keys first in the Key Generation tab.")
        return
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("🔒 Encrypted Input")
        
        if 'ecc_encrypted' in st.session_state:
            encrypted_input = st.text_area(
                "Encrypted message (Base64):",
                value=st.session_state.ecc_encrypted,
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
            key="ecc_decrypt_file"
        )
        
        if encrypted_file is not None:
            encrypted_input = encrypted_file.read().decode('utf-8')
        
        if st.button("🔓 Decrypt with ECC", type="primary") and encrypted_input:
            with st.spinner("Decrypting message..."):
                try:
                    cipher = ECCCipher(private_key=st.session_state.ecc_private)
                    encrypted_bytes = base64.b64decode(encrypted_input)
                    decrypted = cipher.decrypt(encrypted_bytes)
                    # ECC decrypt returns bytes, so we need to decode it
                    decrypted_text = decrypted.decode('utf-8')
                    
                    st.session_state.ecc_decrypted = decrypted_text
                    st.success("✅ Message decrypted successfully!")
                    
                except Exception as e:
                    st.error(f"Decryption error: {e}")
    
    with col2:
        st.subheader("📝 Decrypted Output")
        
        if 'ecc_decrypted' in st.session_state:
            decrypted_text = st.session_state.ecc_decrypted
            st.text_area("Decrypted message:", decrypted_text, height=150, disabled=True)
            
            st.download_button(
                "💾 Download Decrypted Message",
                decrypted_text,
                file_name="ecc_decrypted_message.txt",
                mime="text/plain"
            )
            
            curve_size = st.session_state.ecc_curve_size
            st.metric("Original Size", f"{len(decrypted_text)} characters")
            st.info(f"🔓 Decrypted using P-{curve_size} curve") 