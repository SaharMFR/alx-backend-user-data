#!/usr/bin/env python3
""" Defines `Auth` class """
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """ Authentication class """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines whether `path` is authorized or not """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        for excluded in excluded_paths:
            check: bool = path == excluded
            if excluded[-1] == '*':
                check: bool = path[:len(excluded) - 1] == excluded[:-1]
            if check:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Authorization """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Gets the current user """
        return None

    def session_cookie(self, request=None):
        """ Gets a cookie value from a request """
        if request is None:
            return None
        session_name = getenv('SESSION_NAME')
        return request.cookies.get(session_name, None)
