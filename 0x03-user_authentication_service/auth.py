#!/usr/bin/env python3
""" Authentication """
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password: str) -> bytes:
    """ Hashes password """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """ Generates a new UUID """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Registers a new user """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            new_user = self._db.add_user(email, _hash_password(password))
            return new_user
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """ Validates user login """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)