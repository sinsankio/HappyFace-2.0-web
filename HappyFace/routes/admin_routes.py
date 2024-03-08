import copy
import secrets
from datetime import datetime

from flask import Flask, request, render_template, redirect, url_for, session, make_response

from helper.api.admin_api_helper import AdminApiHelper
from helper.hash.hash_helper import HashHelper
from helper.validation.validation_helper import ValidationHelper

app = Flask(__name__)

app.secret_key = secrets.token_hex()


@app.route("/login", methods=["GET", "POST"])
def login():
    if _ := session.get("logged-admin"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        if login_cookie := request.cookies.get("admin-login"):
            if admin := AdminApiHelper.remember_me(login_cookie):
                session["logged-admin"] = admin
                return redirect(url_for("dashboard"))
            return render_template("admin-login.html")
        return render_template("admin-login.html")

    username = request.form["username"]
    password = request.form["password"]
    error = None

    if invalidity := ValidationHelper.is_invalid_password(password):
        error = invalidity
    if ValidationHelper.is_empty(username, password):
        error = "Invalid entries for username and password"

    if error:
        return render_template("admin-login.html", error=error, username=username, password=password)
    if admin := AdminApiHelper.login(username, password):
        if "remember-me" in request.form:
            new_admin = copy.copy(admin)
            secret_key = secrets.token_hex()
            auth_key = HashHelper.hash(secret_key)
            new_admin["username"] = username
            new_admin["password"] = password
            new_admin["authKey"] = secret_key

            if updated_admin := AdminApiHelper.update_with_credentials(admin, new_admin):
                session["logged-admin"] = updated_admin
                response = make_response(redirect(url_for("dashboard")))

                response.set_cookie("admin-login", auth_key, max_age=3600 * 24 * 7)
                return response
        session["logged-admin"] = admin
        return redirect(url_for("dashboard"))
    return render_template("admin-login.html", error="Invalid login", username=username, password=password)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if admin := session.get("logged-admin"):
        return render_template("admin-dashboard.html", admin=admin)
    return redirect(url_for("login"))


@app.route("/logout", methods=["GET"])
def logout():
    if admin := session.get("logged-admin"):
        new_admin = copy.copy(admin)
        new_admin["authKey"] = None

        if _ := AdminApiHelper.update(admin, new_admin):
            response = make_response(redirect(url_for("login")))

            session.clear()
            response.set_cookie("admin-login", expires=0)
            return response
    return redirect(url_for("login"))


@app.after_request
def add_no_cache_headers(response):
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/orgs/all", methods=["GET"])
def fetch_registered_organizations():
    if admin := session.get("logged-admin"):
        organizations = AdminApiHelper.fetch_organizations(admin)

        for organization in organizations:
            organization["registeredOn"] = datetime.fromisoformat(organization["registeredOn"])
        return render_template("admin-dashboard.html", organizations=organizations)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
