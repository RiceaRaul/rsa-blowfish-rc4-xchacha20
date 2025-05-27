"""Module containing CSS styles for the application."""

import streamlit as st

def load_styles():
    """Load custom CSS styles for the application."""
    st.markdown("""
    <style>
        .stAlert > div {
            padding: 10px;
        }
        .key-box {
            background-color: #f0f2f6;
            padding: 10px;
            border-radius: 5px;
            border-left: 4px solid #4CAF50;
            margin: 10px 0;
        }
        .warning-box {
            background-color: #fff3cd;
            padding: 10px;
            border-radius: 5px;
            border-left: 4px solid #ff9800;
            margin: 10px 0;
        }
        .crypto-header {
            background: linear-gradient(90deg, #4CAF50, #45a049);
            color: white;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }
    </style>
    """, unsafe_allow_html=True) 