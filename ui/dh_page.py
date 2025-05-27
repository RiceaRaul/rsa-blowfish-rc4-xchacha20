"""Diffie-Hellman page module for the cryptography demo application."""

import streamlit as st
import base64
from instances.dh import DHCipher

def show_dh_page():
    """Display the Diffie-Hellman page of the application."""
    st.markdown("""
    <div class="crypto-header">
        <h1>🔄 Diffie-Hellman Key Exchange</h1>
        <p>Secure Key Agreement Protocol + Hybrid Messaging</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🔑 Key Generation", "🤝 Key Exchange Simulation", "💬 Secure Messaging"])
    
    with tab1:
        _show_key_generation()
    
    with tab2:
        _show_key_exchange()
    
    with tab3:
        _show_secure_messaging()

def _show_key_generation():
    """Show the key generation tab content."""
    st.header("Diffie-Hellman Parameters & Keys")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        key_size = st.selectbox(
            "Key Size (bits)",
            [1024, 2048, 3072],
            index=1
        )
        
        if st.button("🔑 Generate DH Keys", type="primary"):
            with st.spinner(f"Generating {key_size}-bit DH keys..."):
                try:
                    # Generate key pair
                    private_key, public_key = DHCipher.gen_keypair(key_size)
                    
                    # Store in session state
                    st.session_state.dh_private = private_key
                    st.session_state.dh_public = public_key
                    
                    st.success(f"✅ Generated {key_size}-bit DH key pair!")
                    
                except Exception as e:
                    st.error(f"Error generating keys: {e}")
    
    with col2:
        if 'dh_private' in st.session_state and 'dh_public' in st.session_state:
            st.markdown("### 📋 Generated Keys")
            
            # Private key
            private_pem = st.session_state.dh_private.export_key()
            st.markdown("**🔒 Private Key:**")
            st.code(private_pem[:200] + "..." if len(private_pem) > 200 else private_pem, language="text")
            
            st.download_button(
                "💾 Download Private Key",
                private_pem,
                file_name="dh_private.pem",
                mime="text/plain"
            )
            
            # Public key
            public_pem = st.session_state.dh_public.export_key()
            st.markdown("**🔓 Public Key:**")
            st.code(public_pem[:200] + "..." if len(public_pem) > 200 else public_pem, language="text")
            
            st.download_button(
                "💾 Download Public Key",
                public_pem,
                file_name="dh_public.pem",
                mime="text/plain"
            )

def _show_key_exchange():
    """Show the key exchange simulation tab content."""
    st.header("Key Exchange Simulation")
    st.markdown("Simulate a key exchange between Alice and Bob")
    
    col1, col2, col3 = st.columns([1, 0.2, 1])
    
    with col1:
        st.subheader("👩 Alice")
        
        if st.button("🔑 Generate Alice's Keys", key="alice_gen"):
            with st.spinner("Generating Alice's keys..."):
                try:
                    alice_private, alice_public = DHCipher.gen_keypair(2048)
                    st.session_state.alice_private = alice_private
                    st.session_state.alice_public = alice_public
                    st.success("✅ Alice's keys generated!")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        if 'alice_public' in st.session_state:
            alice_pub_pem = st.session_state.alice_public.export_key()
            st.markdown("**Alice's Public Key:**")
            st.code(alice_pub_pem[:100] + "...", language="text")
    
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("**🔄**", unsafe_allow_html=True)
        st.markdown("**Exchange**", unsafe_allow_html=True)
        st.markdown("**Public Keys**", unsafe_allow_html=True)
    
    with col3:
        st.subheader("👨 Bob")
        
        if st.button("🔑 Generate Bob's Keys", key="bob_gen"):
            with st.spinner("Generating Bob's keys..."):
                try:
                    bob_private, bob_public = DHCipher.gen_keypair(2048)
                    st.session_state.bob_private = bob_private
                    st.session_state.bob_public = bob_public
                    st.success("✅ Bob's keys generated!")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        if 'bob_public' in st.session_state:
            bob_pub_pem = st.session_state.bob_public.export_key()
            st.markdown("**Bob's Public Key:**")
            st.code(bob_pub_pem[:100] + "...", language="text")
    
    # Shared secret computation
    if ('alice_private' in st.session_state and 'alice_public' in st.session_state and 
        'bob_private' in st.session_state and 'bob_public' in st.session_state):
        
        st.markdown("---")
        
        if st.button("🤝 Compute Shared Secret", type="primary"):
            with st.spinner("Computing shared secrets..."):
                try:
                    # Alice computes shared secret using her private key and Bob's public key
                    alice_shared = st.session_state.alice_private.compute_shared_secret(
                        st.session_state.bob_public
                    )
                    
                    # Bob computes shared secret using his private key and Alice's public key
                    bob_shared = st.session_state.bob_private.compute_shared_secret(
                        st.session_state.alice_public
                    )
                    
                    st.session_state.alice_shared = alice_shared
                    st.session_state.bob_shared = bob_shared
                    
                    # Check if they match
                    if alice_shared == bob_shared:
                        st.success("🎉 Shared secrets match! Secure communication established.")
                    else:
                        st.error("❌ Shared secrets don't match! Something went wrong.")
                    
                except Exception as e:
                    st.error(f"Error computing shared secret: {e}")
        
        # Display shared secrets
        if 'alice_shared' in st.session_state and 'bob_shared' in st.session_state:
            col_a, col_b = st.columns(2)
            
            with col_a:
                st.markdown("**Alice's computed secret:**")
                alice_hex = st.session_state.alice_shared.hex()
                st.code(alice_hex[:32] + "...", language="text")
            
            with col_b:
                st.markdown("**Bob's computed secret:**")
                bob_hex = st.session_state.bob_shared.hex()
                st.code(bob_hex[:32] + "...", language="text")
            
            # Show if they match
            match_status = "✅ MATCH" if st.session_state.alice_shared == st.session_state.bob_shared else "❌ NO MATCH"
            st.markdown(f"**Status:** {match_status}")

def _show_secure_messaging():
    """Show the secure messaging tab content."""
    st.header("Secure Messaging with Shared Secret")
    st.markdown("Use the established shared secret to encrypt and decrypt messages")
    
    st.info("""
    🔍 **Educational Note**: This demonstrates **hybrid cryptography** - the core principle behind modern secure communications:
    1. **Diffie-Hellman** establishes the shared secret (asymmetric)
    2. **AES encryption** protects the actual message (symmetric)
    3. Best of both worlds: security + performance
    """)
    
    # Check if shared secret exists
    if ('alice_shared' not in st.session_state or 'bob_shared' not in st.session_state or
        st.session_state.alice_shared != st.session_state.bob_shared):
        st.warning("⚠️ Please complete the key exchange first to establish a shared secret.")
        return
    
    st.success("🔐 Shared secret established! You can now send encrypted messages.")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📤 Send Message (Alice → Bob)")
        
        # Message input
        alice_message = st.text_area(
            "Alice's message to Bob:",
            placeholder="Enter message to encrypt with shared secret...",
            height=100,
            key="alice_message_input"
        )
        
        # File upload option
        st.markdown("**Or upload a file:**")
        alice_file = st.file_uploader(
            "Choose file to encrypt",
            type=['txt', 'pdf', 'doc'],
            key="alice_file_upload"
        )
        
        if alice_file is not None:
            alice_message = alice_file.read().decode('utf-8', errors='ignore')
            st.text_area("File content:", alice_message, height=100, disabled=True, key="alice_file_content")
        
        if st.button("🔒 Encrypt Message (Alice)", type="primary") and alice_message:
            with st.spinner("Encrypting with shared secret..."):
                try:
                    # Create cipher with Alice's keys
                    alice_cipher = DHCipher(st.session_state.alice_private, st.session_state.bob_public)
                    encrypted = alice_cipher.encrypt(alice_message.encode('utf-8'))
                    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                    
                    st.session_state.alice_encrypted_message = encrypted_b64
                    st.success("✅ Message encrypted by Alice!")
                    
                except Exception as e:
                    st.error(f"Encryption error: {e}")
        
        # Display encrypted message
        if 'alice_encrypted_message' in st.session_state:
            st.markdown("**🔒 Encrypted Message:**")
            encrypted_msg = st.session_state.alice_encrypted_message
            st.code(encrypted_msg[:100] + "..." if len(encrypted_msg) > 100 else encrypted_msg, language="text")
            
            st.download_button(
                "💾 Download Encrypted Message",
                encrypted_msg,
                file_name="alice_encrypted_message.txt",
                mime="text/plain",
                key="download_alice_encrypted"
            )
    
    with col2:
        st.subheader("📥 Receive Message (Bob)")
        
        # Use encrypted message from Alice or manual input
        if 'alice_encrypted_message' in st.session_state:
            bob_encrypted_input = st.text_area(
                "Encrypted message for Bob:",
                value=st.session_state.alice_encrypted_message,
                height=150,
                key="bob_encrypted_input"
            )
        else:
            bob_encrypted_input = st.text_area(
                "Encrypted message for Bob:",
                placeholder="Paste encrypted message here...",
                height=150,
                key="bob_encrypted_input_manual"
            )
        
        # File upload for encrypted message
        st.markdown("**Or upload encrypted file:**")
        bob_encrypted_file = st.file_uploader(
            "Choose encrypted file",
            type=['txt'],
            key="bob_encrypted_file"
        )
        
        if bob_encrypted_file is not None:
            bob_encrypted_input = bob_encrypted_file.read().decode('utf-8')
        
        if st.button("🔓 Decrypt Message (Bob)", type="primary") and bob_encrypted_input:
            with st.spinner("Decrypting with shared secret..."):
                try:
                    # Create cipher with Bob's keys
                    bob_cipher = DHCipher(st.session_state.bob_private, st.session_state.alice_public)
                    encrypted_bytes = base64.b64decode(bob_encrypted_input)
                    decrypted = bob_cipher.decrypt(encrypted_bytes)
                    decrypted_text = decrypted.decode('utf-8')
                    
                    st.session_state.bob_decrypted_message = decrypted_text
                    st.success("✅ Message decrypted by Bob!")
                    
                except Exception as e:
                    st.error(f"Decryption error: {e}")
        
        # Display decrypted message
        if 'bob_decrypted_message' in st.session_state:
            st.markdown("**📝 Decrypted Message:**")
            decrypted_msg = st.session_state.bob_decrypted_message
            st.text_area("Bob received:", decrypted_msg, height=150, disabled=True, key="bob_decrypted_display")
            
            st.download_button(
                "💾 Download Decrypted Message",
                decrypted_msg,
                file_name="bob_decrypted_message.txt",
                mime="text/plain",
                key="download_bob_decrypted"
            ) 