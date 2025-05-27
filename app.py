"""Main application file for the cryptography demo."""

import streamlit as st
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import UI components
from ui import (
    show_home,
    show_rsa_page,
    show_dh_page,
    show_ecc_page,
    show_about_page,
    load_styles
)

def main():
    """Main application entry point."""
    # Page configuration
    st.set_page_config(
        page_title="Public Key Cryptography Demo",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Load custom styles
    load_styles()
    
    # Sidebar navigation
    st.sidebar.title("🔐 Cryptography Demo")
    st.sidebar.markdown("---")
    
    # Navigation
    page = st.sidebar.selectbox(
        "Choose Algorithm",
        ["Home", "RSA", "Diffie-Hellman", "Elliptic Curve (ECC)", "About"]
    )
    
    # Route to appropriate page
    if page == "Home":
        show_home()
    elif page == "RSA":
        show_rsa_page()
    elif page == "Diffie-Hellman":
        show_dh_page()
    elif page == "Elliptic Curve (ECC)":
        show_ecc_page()
    elif page == "About":
        show_about_page()

if __name__ == "__main__":
    main() 