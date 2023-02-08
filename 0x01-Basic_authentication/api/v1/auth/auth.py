#!/usr/bin/env python3
"""
Auth class
"""
from flask import request
from typing import List, TypeVar

"""
required module
"""


class Auth:
    """
    class Auth to manage API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        :return: False
        """
        if path is None:
            return True
        elif excluded_paths is None or excluded_paths == []:
            return True
        elif path in excluded_paths:
            return False
        else:
            for z in excluded_paths:
                if z.startswith(path):
                    return False
                if path.startswith(z):
                    return False
                if z[-1] == "*":
                    if path.startswith(z[:-1]):
                        return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        :return: None
        """
        if request is None:
            return None
        get_header = request.headers.get('Authorization')
        if get_header is None:
            return None
        return get_header

    def current_user(self, request=None) -> TypeVar('User'):
        """
        :return: None
        """
        return None
