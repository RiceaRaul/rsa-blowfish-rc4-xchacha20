"""About page module for the cryptography demo application."""

import streamlit as st
import pandas as pd

def show_about_page():
    """Display the about page of the application."""
    st.markdown("""
    <div class="crypto-header">
        <h1>📚 About This Demo</h1>
        <p>Educational Cryptography Implementation</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    ## 🎯 Purpose
    
    This interactive demo showcases the fundamental algorithms of public key cryptography:
    - **RSA**: The foundational public key algorithm
    - **Diffie-Hellman**: Revolutionary key exchange protocol + secure messaging
    - **ECC**: Modern, efficient elliptic curve cryptography
    
    ## 🔧 Implementation Details
    
    - **Language**: Python with cryptographic libraries
    - **Interface**: Streamlit for interactive web interface
    - **Security**: Production-grade implementations with proper padding
    - **Standards**: Following NIST recommendations for key sizes
    
    ## 📖 Educational Value
    
    This demo helps understand:
    - How public key cryptography solves the key distribution problem
    - The mathematical foundations of each algorithm
    - Practical considerations like key sizes and performance
    - Real-world applications and use cases
    - How key exchange enables secure messaging (hybrid cryptography)
    """)
    
    # Comparison table
    comparison_data = {
        "Algorithm": ["RSA-2048", "RSA-3072", "ECC P-256", "ECC P-384", "DH-2048"],
        "Security Level": ["112-bit", "128-bit", "128-bit", "192-bit", "112-bit"],
        "Key Size": ["2048 bits", "3072 bits", "256 bits", "384 bits", "2048 bits"],
        "Performance": ["Slow", "Slower", "Fast", "Fast", "Fast"],
        "Use Cases": ["Legacy, Compatibility", "High Security", "Modern Standard", "High Security", "Key Exchange + Messaging"]
    }
    
    df = pd.DataFrame(comparison_data)
    st.table(df)
    
    st.markdown("""
    ## 👨‍💻 Author
    
    **Ricea Ion Raul**  
    *Cyber Security and Machine Learning*  
    *Ovidius University of Constanta*
    
    ---
    
    *This project demonstrates the practical implementation of cryptographic algorithms 
    for educational purposes in cybersecurity curriculum.*
    """) 