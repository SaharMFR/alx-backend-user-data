#!/usr/bin/env python3
""" Defines `Auth` class """
from flask import request
from typing import List, TypeVar


class Auth:
    """ Authentication class """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines whether `path` is authorized or not """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        for excluded in excluded_paths:
            if path == excluded:
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
