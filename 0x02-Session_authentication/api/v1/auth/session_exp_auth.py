#!/usr/bin/env python3
""" Defines `SessionExpAuth` class """
from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """ Session authentication class with expiration date to session ID """
    def __init__(self):
        """ Initialize a Session Exp Auth instance """
        try:
            session_duration = int(getenv('SESSION_DURATION'))
        except Exception:
            session_duration = 0

        self.session_duration = session_duration

    def create_session(self, user_id=None):
        """ Creates a new session """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        session_dictionary = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }

        self.user_id_by_session_id[session_id] = session_dictionary

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Gets the current user """
        if (session_id is None or session_id not
                in self.user_id_by_session_id.keys()):
            return None

        session_dictionary = self.user_id_by_session_id[session_id]

        if self.session_duration <= 0:
            return session_dictionary.get('user_id')

        created_at = session_dictionary.get('created_at')
        if created_at is None:
            return None
        expires_at = created_at + timedelta(seconds=self.session_duration)
        if expires_at < datetime.now():
            return None

        return session_dictionary.get('user_id')
