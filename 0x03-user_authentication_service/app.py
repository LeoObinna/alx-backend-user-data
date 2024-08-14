#!/usr/bin/env python3
"""A simple Flask app with user authentication features.
"""

from flask import Flask, jsonify, request, abort, redirect
from auth import Auth
import bcrypt

app = Flask(__name__)
AUTH = Auth()


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted hash of the password.
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """GET /
    
    Return:
        str: The home page's payload.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """POST /users
    
    Registers a new user.
    
    Return:
        str: The account creation payload.
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        hashed_password = _hash_password(password)
        AUTH.register_user(email, hashed_password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """POST /sessions
    
    Logs in a user if the credentials provided are correct, and creates a new session.
    
    Return:
        str: The account login payload.
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """DELETE /sessions
    
    Logs out a logged-in user and destroys their session.
    
    Return:
        str: Redirects to the home route.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """GET /profile
    
    Returns a user's email based on the session_id in the received cookies.
    
    Return:
        str: The user's profile information.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"email": user.email})


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    """POST /reset_password
    
    Generates a token for resetting a user's password.
    
    Return:
        str: The user's password reset payload.
    """
    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        abort(403)


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password() -> str:
    """PUT /reset_password
    
    Updates a user's password.
    
    Return:
        str: The user's password updated payload.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        hashed_password = _hash_password(new_password)
        AUTH.update_password(reset_token, hashed_password)
        return jsonify({"email": email, "message": "Password updated"})
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
