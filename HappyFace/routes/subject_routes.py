import copy
import secrets
from datetime import datetime

from flask import Flask, request, render_template, redirect, url_for, session, make_response

from helper.api.subject_api_helper import SubjectApiHelper
from helper.data_visualize.data_visualize_helper import DataVisualizeHelper
from helper.hash.hash_helper import HashHelper
from helper.media.image.image_helper import ImageHelper
from helper.validation.validation_helper import ValidationHelper

app = Flask(__name__)

app.secret_key = secrets.token_hex()
app.session_logged_subs = {}


@app.route("/login", methods=["GET", "POST"])
def login():
    if _ := session.get("logged-subject"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        if "sub-login" in request.cookies and "sub-org-auth" in request.cookies:
            sub_login_cookie = request.cookies.get("sub-login")
            sub_org_auth_cookie = request.cookies.get("sub-org-auth")

            if subject := SubjectApiHelper.remember_me(sub_org_auth_cookie, sub_login_cookie):
                session["logged-subject"] = subject["_id"]
                session["logged-subject-org-key"] = sub_org_auth_cookie
                app.session_logged_subs[subject["_id"]] = subject
                return redirect(url_for("dashboard"))
        return render_template("subject-login.html")

    org_key = request.form["org-key"]
    username = request.form["username"]
    password = request.form["password"]
    error = None

    if invalidity := ValidationHelper.is_invalid_password(password):
        error = invalidity
    if ValidationHelper.is_empty(org_key, username, password):
        error = "Not valid entries for organization key, username and password"

    if error:
        return render_template("subject-login.html", error=error, org_key=org_key, username=username, password=password)
    if subject := SubjectApiHelper.login(org_key, username, password):
        if "remember-me" in request.form:
            new_subject = copy.copy(subject)
            secret_key = secrets.token_hex()
            sub_login = HashHelper.hash(secret_key)
            sub_org_auth = HashHelper.hash(org_key)
            new_subject["username"] = username
            new_subject["password"] = password
            new_subject["authKey"] = secret_key

            if updated_subject := SubjectApiHelper.update_with_credentials(sub_org_auth, subject, new_subject):
                session["logged-subject"] = updated_subject["_id"]
                session["logged-subject-org-key"] = sub_org_auth
                app.session_logged_subs[updated_subject["_id"]] = updated_subject
                response = make_response(redirect(url_for("dashboard")))

                response.set_cookie("sub-login", sub_login, max_age=3600 * 24 * 7)
                response.set_cookie("sub-org-auth", sub_org_auth, max_age=3600 * 24 * 7)

                return response

        session["logged-subject"] = subject["_id"]
        session["logged-subject-org-key"] = HashHelper.hash(org_key)
        app.session_logged_subs[subject["_id"]] = subject

        return redirect(url_for("dashboard"))
    return render_template("subject-login.html", error="Invalid login", org_key=org_key, username=username, password=password)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if _ := session.get("logged-subject"):
        return render_template("subject-dashboard.html")
    return redirect(url_for("login"))


@app.route("/logout", methods=["GET"])
def logout():
    if subject := session.get("logged-subject"):
        subject_id = subject
        org_key = session.get("logged-subject-org-key")
        subject = app.session_logged_subs[subject]
        new_subject = copy.copy(subject)
        new_subject["authKey"] = None

        if _ := SubjectApiHelper.update(org_key, subject, new_subject):
            response = make_response(redirect(url_for("login")))

            session.clear()
            del app.session_logged_subs[subject_id]
            response.set_cookie("sub-login", expires=0)
            response.set_cookie("sub-org-auth", expires=0)
            return response
    return redirect(url_for("login"))


@app.after_request
def add_no_cache_headers(response):
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/profile", methods=["GET"])
def profile():
    if subject := session.get("logged-subject"):
        subject = app.session_logged_subs[subject]
        org_key = session.get("logged-subject-org-key")

        if profile := SubjectApiHelper.fetch(org_key, subject):
            profile["registeredOn"] = datetime.fromisoformat(profile["registeredOn"])
            return render_template("subject-dashboard.html", profile=profile)
    return redirect(url_for("login"))


@app.route("/update", methods=["GET", "POST"])
def update_credentials():
    if subject := session.get("logged-subject"):
        subject_id = subject
        subject = app.session_logged_subs[subject]
        org_key = session.get("logged-subject-org-key")

        if request.method == "GET":
            return render_template("subject-update.html")

        username = request.form["username"]
        password = request.form["password"]
        password_retype = request.form["password-retype"]

        username_error = password_error = password_retype_error = None

        if ValidationHelper.len_lt_check({username: 10}):
            username_error = "Username doesn't meet maximum length requirement"
        if invalidity := ValidationHelper.is_invalid_password(password):
            password_error = invalidity
        if ValidationHelper.is_empty(username):
            username_error = "Empty entry for username"
        if ValidationHelper.is_empty(password):
            password_error = "Empty entry for password"
        if not password_error and password != password_retype:
            password_retype_error = "Retyped password is not same as the password"

        if username_error or password_error or password_retype_error:
            return render_template(
                "subject-update.html",
                new_username=username,
                new_password=password,
                new_password_retype=password_retype,
                username_error=username_error,
                password_error=password_error,
                password_retype_error=password_retype_error
            )

        new_subject = copy.copy(subject)
        new_subject["username"] = username
        new_subject["password"] = password
        new_subject["authKey"] = None

        if new_subject := SubjectApiHelper.update_with_credentials(org_key, subject, new_subject):
            subject = new_subject
            response = make_response(redirect(url_for("login")))

            session.clear()
            del app.session_logged_subs[subject_id]
            response.set_cookie("sub-login", expires=0)
            response.set_cookie("sub-org-auth", expires=0)
            return response
    return redirect(url_for("login"))


@app.route("/emotions", methods=["GET", "POST"])
def fetch_emotion_engagement():
    if subject := session.get("logged-subject"):
        if request.method == "GET":
            return render_template("subject-dashboard.html", emotions=True)

        subject = app.session_logged_subs[subject]
        org_key = session.get("logged-subject-org-key")
        hours_before = request.form["hours-before"]
        weeks_before = request.form["weeks-before"]
        months_before = request.form["months-before"]
        years_before = request.form["years-before"]

        hours_before_error = weeks_before_error = months_before_error = years_before_error = None

        if ValidationHelper.alpha_str_check(hours_before):
            hours_before_error = "Invalid entry for hours before"
        if ValidationHelper.alpha_str_check(weeks_before):
            weeks_before_error = "Invalid entry for weeks before"
        if ValidationHelper.alpha_str_check(months_before):
            months_before_error = "Invalid entry for months before"
        if ValidationHelper.alpha_str_check(years_before):
            years_before_error = "Invalid entry for years before"

        if hours_before_error or weeks_before_error or months_before_error or years_before_error:
            return render_template(
                "subject-dashboard.html",
                hours_before=hours_before,
                weeks_before=weeks_before,
                months_before=months_before,
                years_before=years_before,
                hours_before_error=hours_before_error,
                weeks_before_error=weeks_before_error,
                months_before_error=months_before_error,
                years_before_error=years_before_error,
                emotions=True
            )

        hours = int(hours_before)
        weeks = int(weeks_before)
        months = int(months_before)
        years = int(years_before)

        if emotion_engagement := SubjectApiHelper.fetch_emotion_engagement(org_key, subject, hours, weeks, months,
                                                                                years):
            emotion_engagement = {emotion: prob * 100 for emotion, prob in emotion_engagement.items()}
            emotion_engagement_bar_plt_img = DataVisualizeHelper.plot_emotion_engagement_bar(emotion_engagement)
            emotion_engagement_bar_plt_str = ImageHelper.encode_np(emotion_engagement_bar_plt_img)
            emotion_engagement_pie_plt_str = ImageHelper.encode_np(
                DataVisualizeHelper.plot_emotion_engagement_pie(
                    emotion_engagement
                )
            )
            return render_template(
                "subject-dashboard.html",
                hours_before=hours_before,
                weeks_before=weeks_before,
                months_before=months_before,
                years_before=years_before,
                emotions=True,
                emotion_engagement_bar_plt=emotion_engagement_bar_plt_str,
                emotion_engagement_pie_plt=emotion_engagement_pie_plt_str
            )
        return render_template(
            "subject-dashboard.html",
            emotions=True,
            emotion_engagement_na="Requested emotional engagement not available"
        )
    return redirect(url_for("login"))


@app.route("/consultancy-chat", methods=["GET", "POST"])
def chat_consultancy():
    if subject := session.get("logged-subject"):
        subject = app.session_logged_subs[subject]
        org_key = session.get("logged-subject-org-key")

        if request.method == "GET":
            if consultancy := SubjectApiHelper.fetch_latest_consultancy(org_key, subject):
                consultancy["consultedOn"] = datetime.fromisoformat(consultancy["consultedOn"])

                for message in consultancy["chat"]:
                    message["sentOn"] = datetime.fromisoformat(message["sentOn"])
                return render_template("subject-assistant-chat.html", consultancy=consultancy)
            return render_template("subject-dashboard.html", consultancy_na="No any consultations available")

        message = request.form["message"]

        if ValidationHelper.is_empty(message):
            if consultancy := SubjectApiHelper.fetch_latest_consultancy(org_key, subject):
                consultancy["consultedOn"] = datetime.fromisoformat(consultancy["consultedOn"])

                for message in consultancy["chat"]:
                    message["sentOn"] = datetime.fromisoformat(message["sentOn"])
                return render_template(
                    "subject-assistant-chat.html",
                    message_error="Empty entry for message",
                    consultancy=consultancy
                )
        if consultancy := SubjectApiHelper.chat_with_assistant(org_key, subject, message):
            consultancy["consultedOn"] = datetime.fromisoformat(consultancy["consultedOn"])

            for message in consultancy["chat"]:
                message["sentOn"] = datetime.fromisoformat(message["sentOn"])
            return render_template("subject-assistant-chat.html", consultancy=consultancy)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5002)
