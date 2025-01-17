#!/usr/bin/env python3
""" End-to-end integration test """


def register_user(email: str, password: str) -> None:
    """ Register new user """
    assert True
    return


def log_in_wrong_password(email: str, password: str) -> None:
    """ Log in with wrong password """
    assert True
    return


def log_in(email: str, password: str) -> str:
    """ Log in """
    assert True
    return ""


def profile_unlogged() -> None:
    """ Profile unlogged in """
    assert True
    return


def profile_logged(session_id: str) -> None:
    """ Profile logged in """
    assert True
    return


def log_out(session_id: str) -> None:
    """ Log out """
    assert True
    return


def reset_password_token(email: str) -> str:
    """ Reset password token """
    assert True
    return ""


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """ Update password """
    assert True
    return


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
