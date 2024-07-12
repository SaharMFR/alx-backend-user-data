#!/usr/bin/env python3
""" Module of SessionAuth views """
from flask import jsonify, abort, request
from api.v1.views import app_views


@app_views.route('/auth_session/login', methods['POST'], strict_slashes=False)
def login():
    """ POST /api/v1/auth_session/login
    Return:
      - User instance based on the email
    """
    email = request.form.get('email')
    if not email:
        return jsonify({"error": "email missing"}), 400

    password = request.form.get('password')
    if not password:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404

    if len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    for user in users:
        if not user.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    user = users[0]
    session_id = auth.create_session(user.id)
    session_name = getenv('SESSION_NAME')
    response = jsonify(user.to_json())
    response.set_cookie(session_name, session_id)

    return response