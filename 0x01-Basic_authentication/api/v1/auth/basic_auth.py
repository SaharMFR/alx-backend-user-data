#!/usr/bin/env python3
""" Defines `BasicAuth` class """
from api.v1.auth.auth import Auth
from base64 import b64decode
from models.user import User


class BasicAuth(Auth):
    """ Basic Authentication class """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Returns the Base64 part of the `Authorization` header
        for a Basic Authentication.
        """
        if (authorization_header is None or
                not isinstance(authorization_header, str) or
                authorization_header[:6] != "Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """ Decodes the Base64 part of the `Authorization` header """
        if (base64_authorization_header is None or
                not isinstance(base64_authorization_header, str)):
            return None
        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
        Returns the user email and password from the Base64 decoded value.
        """
        if (decoded_base64_authorization_header is None or
                not isinstance(decoded_base64_authorization_header, str) or
                not (':' in decoded_base64_authorization_header)):
            return None, None

        colon_index = decoded_base64_authorization_header.index(':')
        email = decoded_base64_authorization_header[:colon_index]
        password = decoded_base64_authorization_header[colon_index + 1:]
        return email, password

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ Returns the `User` instance based on his email and password """
        if (user_email is None or user_pwd is None or
                not isinstance(user_email, str) or
                not isinstance(user_pwd, str)):
            return None

        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None
