#!/usr/bin/env python3
"""Auth module"""
import bcrypt
from uuid import uuid4
from db import DB
from user import User
from typing import ByteString
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """registers a user"""
        try:
            self._db.find_user_by(**{'email': email})
            raise ValueError('User {} already exists'.format(email))
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """validates a user login"""
        try:
            user = self._db.find_user_by(**{"email": email})
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """creates a user session"""
        try:
            user = self._db.find_user_by(**{"email": email})
            user.session_id = _generate_uuid()
            return user.session_id
        except NoResultFound:
            pass

    def get_user_from_session_id(self, session_id) -> User:
        """returns a user based on the session id"""
        try:
            user = self._db.find_user_by({"session_id": session_id})
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """destroys a users's session"""
        self._db.update_user(user_id, {"session_id": None})


def _hash_password(password: str) -> ByteString:
    """takes in a password string arguments and returns bytes"""
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(bytes, salt)


def _generate_uuid() -> str:
    """generates uuid"""
    return str(uuid4())
