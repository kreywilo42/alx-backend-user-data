#!/usr/bin/env python3
"""
Encrypting passwords
"""
import bcrypt
from bcrypt import hashpw
"""
required modules
"""

# task 5


def hash_password(password: str) -> bytes:
    """
    :return: a byte string
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed

# task 6


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    :return: if hashed password matches provided password
    """
    if bcrypt.checkpw(password.encode(), hashed_password):
        return True
    return False
