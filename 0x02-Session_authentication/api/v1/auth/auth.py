#!/usr/bin/env python3
"""Module: authentition"""
from flask import request
from os import getenv
from typing import List, TypeVar


class Auth:
    """Authentication class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """returns True if the path is not in excluded_paths"""

        if path is not None and excluded_paths is not None:
            if path[-1] != "/":
                path = path + "/"
            if path in excluded_paths:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ validates all requests to secure the API"""
        if request is not None:
            dict_key = request.headers.get('Authorization')
            if dict_key is not None:
                return dict_key
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """returns the current user"""
        return None

    def session_cookie(self, request=None):
        """returns a cookie value from a request"""
        if request is not None:
            session_name = getenv('SESSION_NAME')
            cookie = request.cookies.get(session_name)
            return cookie
