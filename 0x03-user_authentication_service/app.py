#!/usr/bin/env python3
"""Module: app.py"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route('/')
def hello():
    """returns 'hello world' in french"""
    return jsonify(message='Bienvenue')


@app.route('/users', strict_slashes=False, methods=['POST'])
def users():
    """registers a user in the database"""
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"})


@app.route('/sessions', strict_slashes=False, methods=['POST'])
def login():
    """logins a user"""
    email = request.form.get('email')
    password = request.form.get('password')
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        output = jsonify({"email": email, "message": "logged in"})
        output.set_cookie("session_id", session_id)
        return output
    abort(401)


@app.route('/sessions', strict_slashes=False, methods=['DELETE'])
def logout():
    """logins a user"""
    cookie = request.cookies.get('session_id')
    if cookie is None:
        return cookie
    user = AUTH.get_user_from_session_id(cookie)
    if user:
        AUTH.destroy_session(user.id)
        return redirect('/')
    abort(403)


@app.route('/profile', strict_slashes=False, methods=['GET'])
def logout():
    """logins a user"""
    cookie = request.cookies.get('session_id')
    if cookie is None:
        return cookie
    user = AUTH.get_user_from_session_id(cookie)
    if user:
        return jsonify({"email": user.email})
    abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
