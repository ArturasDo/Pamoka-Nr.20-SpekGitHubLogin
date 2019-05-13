import json

import hashlib
import random
import uuid

from flask import Flask, render_template, request, make_response, redirect, url_for
from requests_oauthlib import OAuth2Session
from models import User
import os
# import secrets  # DELETE THIS LINE WHEN DEPLOYING TO A SERVER. THIS LINE IS FOR LOCALHOST ONLY!


app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    session_token = request.cookies.get("session_token")

    if session_token:
        user = User.fetch_one(query=["session_token", "==", session_token])
    else:
        user = None

    return render_template("index.html", user=user)


@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("user-name")
    email = request.form.get("user-email")
    password = request.form.get("user-password")

    # hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # create a secret number
    secret_number = random.randint(1, 30)

    # see if user already exists
    user = User.fetch_one(query=["email", "==", email])

    if not user:
        # create a User object
        user = User(name=name, email=email, secret_number=secret_number, password=hashed_password)
        user.create()  # save the object into a database

    # check if password is incorrect
    if hashed_password != user.password:
        return "KLAIDINAS SLAPTAŽODIS! Bandykite dar."
    elif hashed_password == user.password:
        session_token = str(uuid.uuid4())
        User.edit(obj_id=user.id, session_token=session_token)

        # save user's session token into a cookie
        response = make_response(redirect(url_for('index')))
        response.set_cookie("session_token", session_token, httponly=True, samesite='Strict')

        return response


@app.route("/result", methods=["POST"])
def result():
    guess = (request.form.get("guess"))
    if guess.upper() == "C":
        # message = "Thank you. Your game is over."
        message = "Ačiū. Žaidimo pabaiga."
        response = make_response(render_template("result.html", message=message))
        return response
    if guess.isdigit():
        pass
    else:
        message = "Jūs įvedėte raidę. Pakartokite."
        response = make_response(render_template("result.html", message=message))
        return response

    guess = int(request.form.get("guess"))

    session_token = request.cookies.get("session_token")

    # get user from the database based on her/his email address
    user = User.fetch_one(query=["session_token", "==", session_token])

    if guess == user.secret_number:
        message = "Sveikiname. Slaptas skaičius yra {0}".format(str(guess))

        # create a new random secret number
        new_secret = random.randint(1, 30)

        # update the user's secret number in the User collection
        User.edit(obj_id=user.id, secret_number=new_secret)
    elif guess > user.secret_number:
        message = "Bandykite mažesnį skaičių."
    elif guess < user.secret_number:
        message = "Bandykite didesnį skaičių."

    return render_template("result.html", message=message)


@app.route("/github/login")
def github_login():
    github = OAuth2Session(os.environ.get("GITHUB_CLIENT_ID"))  # prepare the GitHub OAuth session
    authorization_url, state = github.authorization_url("https://github.com/login/oauth/authorize")  # GitHub authorization URL

    response = make_response(redirect(authorization_url))  # redirect user to GitHub for authorization
    response.set_cookie("oauth_state", state, httponly=True, samesite='Strict')  # for CSRF purposes

    return response


@app.route("/github/callback")
def github_callback():
    github = OAuth2Session(os.environ.get("GITHUB_CLIENT_ID"), state=request.cookies.get("oauth_state"))
    token = github.fetch_token("https://github.com/login/oauth/access_token",
                               client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),
                               authorization_response=request.url)

    response = make_response(redirect(url_for('profile')))  # redirect to the profile page
    response.set_cookie("oauth_token", json.dumps(token), httponly=True, samesite='Strict')

    return response


@app.route("/profile")
def profile():
    github = OAuth2Session(os.environ.get("GITHUB_CLIENT_ID"), token=json.loads(request.cookies.get("oauth_token")))
    github_profile_data = github.get('https://api.github.com/user').json()

    return render_template("profile.html", github_profile_data=github_profile_data)


@app.route("/github/logout")
def logout():
    response = make_response(redirect(url_for('index')))  # redirect to the index page
    response.set_cookie("oauth_token", expires=0)  # delete the oauth_cookie to logout

    return response


if __name__ == '__main__':
    app.run(debug=True)