#!/usr/bin/env python3
"""Module: Session Authentic views"""
from flask import request, jsonify, abort
from models.user import User
from api.v1.views import app_views
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login_user() -> str:
    """handles session authentication"""
    from api.v1.app import auth

    email = request.form.get('email')
    password = request.form.get('password')

    if email is None or len(email) == 0:
        return jsonify({"error": "email missing"}), 400
    if password is None or len(password) == 0:
        return jsonify({"error": "password missing"}), 400

    user = User.search({'email': email})
    if len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    if not user[0].is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    session_id = auth.create_session(user[0].id)

    result = jsonify(user[0].to_json())
    result.set_cookie(getenv('SESSION_NAME'), session_id)
    return result


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout_user() -> str:
    """deletes a user's session"""
    from api.v1.app import auth
    session_deleted = auth.destroy_session(request)
    print(session_deleted)
    if session_deleted:
        return jsonify({}), 200
    abort(404)
