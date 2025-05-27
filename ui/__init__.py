"""
UI package for the cryptography demo application.
Contains modular components for each page and functionality.
"""

from .home import show_home
from .rsa_page import show_rsa_page
from .dh_page import show_dh_page
from .ecc_page import show_ecc_page
from .about import show_about_page
from .styles import load_styles

__all__ = [
    'show_home',
    'show_rsa_page',
    'show_dh_page',
    'show_ecc_page',
    'show_about_page',
    'load_styles'
] 