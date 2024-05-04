import copy
import html
import os
import secrets
from datetime import datetime

from flask import Flask, request, render_template, redirect, url_for, session, make_response
from werkzeug.utils import secure_filename

from helper.api.organization_api_helper import OrganizationApiHelper
from helper.data_visualize.data_visualize_helper import DataVisualizeHelper
from helper.fake.fake_word_helper import FakeWordHelper
from helper.hash.hash_helper import HashHelper
from helper.key.random_key_helper import RandomKeyHelper
from helper.media.image.image_helper import ImageHelper
from helper.validation.validation_helper import ValidationHelper

app = Flask(__name__)

app.secret_key = secrets.token_hex()
app.session_logged_orgs = {}


@app.route("/login", methods=["GET", "POST"])
def login():
    if _ := session.get("logged-organization"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        if login_cookie := request.cookies.get("organization-login"):
            if organization := OrganizationApiHelper.remember_me(login_cookie):
                session["logged-organization"] = organization["_id"]
                app.session_logged_orgs[organization["_id"]] = organization
                return redirect(url_for("dashboard"))
            return render_template("organization-login.html")
        return render_template("organization-login.html")

    org_key = request.form["org-key"]
    password = request.form["password"]
    error = None

    if invalidity := ValidationHelper.is_invalid_password(password):
        error = invalidity
    if ValidationHelper.is_empty(org_key, password):
        error = "Not valid entries for organization key and password"

    if error:
        return render_template("organization-login.html", error=error, org_key=org_key, password=password)
    if organization := OrganizationApiHelper.login(org_key, password):
        if "remember-me" in request.form:
            new_organization = copy.copy(organization)
            secret_key = secrets.token_hex()
            auth_key = HashHelper.hash(secret_key)
            new_organization["orgKey"] = org_key
            new_organization["password"] = password
            new_organization["authKey"] = secret_key

            if updated_organization := OrganizationApiHelper.update_with_credentials(organization, new_organization):
                session["logged-organization"] = updated_organization["_id"]
                app.session_logged_orgs[updated_organization["_id"]] = updated_organization
                response = make_response(redirect(url_for("dashboard")))

                response.set_cookie("organization-login", auth_key, max_age=3600 * 24 * 7)
                return response
        session["logged-organization"] = organization["_id"]
        app.session_logged_orgs[organization["_id"]] = organization
        return redirect(url_for("dashboard"))
    return render_template("organization-login.html", error="Invalid login", org_key=org_key, password=password)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]
        return render_template("organization-dashboard.html", organization=organization)
    return redirect(url_for("login"))


@app.route("/logout", methods=["GET"])
def logout():
    if organization := session.get("logged-organization"):
        organization_id = organization
        organization = app.session_logged_orgs[organization]
        new_organization = copy.copy(organization)
        new_organization["authKey"] = None

        if _ := OrganizationApiHelper.update(organization, new_organization):
            response = make_response(redirect(url_for("login")))

            session.clear()
            del app.session_logged_orgs[organization_id]
            response.set_cookie("organization-login", expires=0)
            return response
    return redirect(url_for("login"))


@app.after_request
def add_no_cache_headers(response):
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/profile", methods=["GET"])
def profile():
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]
        profile = copy.copy(organization)
        profile["registeredOn"] = datetime.fromisoformat(profile["registeredOn"])
        return render_template("organization-dashboard.html", profile=profile)
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if _ := session.get("logged-organization"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("organization-register.html")

    name = request.form["name"]
    address = request.form["address"]
    business_reg = request.form["business-reg"]
    owner = request.form["owner"]
    email = request.form["email"]
    password = request.form["password"]
    password_retype = request.form["password-retype"]

    logo_img_file = None
    name_error = address_error = business_reg_error = owner_error = email_error = password_error = \
        password_retype_error = None

    if 'logo-img-file' in request.files:
        logo_img_file = request.files["logo-img-file"]

        if logo_img_file.filename:
            logo_img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], logo_img_file.filename))

    if not ValidationHelper.len_lt_check({name: 50}):
        name_error = "Too long entry for name"
    if not ValidationHelper.len_lt_check({address: 100}):
        address_error = "Too long entry for address"
    if not ValidationHelper.len_lt_check({business_reg: 50}):
        business_reg_error = "Too long entry for business registration ID"
    if not ValidationHelper.len_lt_check({owner: 50}):
        owner_error = "Too long entry for owner"
    if not ValidationHelper.alpha_str_check(name):
        name_error = "Invalid type for name"
    if not ValidationHelper.alpha_str_check(address):
        address_error = "Invalid type for address"
    if not ValidationHelper.alpha_str_check(owner):
        owner_error = "Invalid type for owner"
    if not ValidationHelper.email_format_check(email):
        email_error = "Invalid format for email"
    if invalidity := ValidationHelper.is_invalid_password(password):
        password_error = invalidity
    if ValidationHelper.is_empty(name):
        name_error = "Empty entry for name"
    if ValidationHelper.is_empty(address):
        address_error = "Empty entry for address"
    if ValidationHelper.is_empty(email):
        email_error = "Empty entry for email"
    if ValidationHelper.is_empty(password):
        password_error = "Empty entry for password"
    if not password_error and password != password_retype:
        password_retype_error = "Retyped password is not same as the password"

    if name_error or address_error or business_reg_error or owner_error or email_error or password_error or \
            password_retype_error:
        return render_template(
            "organization-register.html",
            name=name,
            address=address,
            business_reg=business_reg,
            owner=owner,
            email=email,
            password=password,
            password_retype=password_retype,
            name_error=name_error,
            address_error=address_error,
            business_reg_error=business_reg_error,
            owner_error=owner_error,
            email_error=email_error,
            password_error=password_error,
            password_retype_error=password_retype_error
        )

    display_logo = None

    if logo_img_file:
        display_logo = ImageHelper.encode(os.path.join(app.config["UPLOAD_FOLDER"], logo_img_file.filename))

    organization = {
        "name": html.escape(name),
        "address": html.escape(address),
        "businessReg": html.escape(business_reg) if business_reg else None,
        "owner": html.escape(owner) if owner else None,
        "email": html.escape(email),
        "password": password
    }

    if display_logo:
        organization["displayLogo"] = display_logo
    if organization := OrganizationApiHelper.register(organization):
        return render_template("organization-register.html", success_reg_org_key=organization["orgKey"])


@app.route("/update-basic", methods=["GET", "POST"])
def update_basic():
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if request.method == "GET":
            return render_template("organization-update-basic.html", update_organization=organization)

        name = request.form["name"]
        address = request.form["address"]
        business_reg = request.form["business-reg"]
        owner = request.form["owner"]
        email = request.form["email"]
        logo_img_file = None
        name_error = address_error = business_reg_error = owner_error = email_error = None

        if "logo-img-file" in request.files:
            logo_img_file = request.files["logo-img-file"]

            if logo_img_file.filename:
                logo_img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], logo_img_file.filename))

        if ValidationHelper.len_gt_check({name: 50}):
            name_error = "Too long entry for name"
        if ValidationHelper.len_gt_check({address: 100}):
            address_error = "Too long entry for address"
        if ValidationHelper.len_gt_check({business_reg: 50}):
            business_reg_error = "Too long entry for business registration ID"
        if ValidationHelper.len_gt_check({owner: 50}):
            owner_error = "Too long entry for owner"
        if not ValidationHelper.alpha_str_check(name):
            name_error = "Invalid type for name"
        if not ValidationHelper.alpha_str_check(address):
            address_error = "Invalid type for address"
        if not ValidationHelper.alpha_str_check(owner):
            owner_error = "Invalid type for owner"
        if not ValidationHelper.email_format_check(email):
            email_error = "Invalid format for email"
        if ValidationHelper.is_empty(name):
            name_error = "Empty entry for name"
        if ValidationHelper.is_empty(address):
            address_error = "Empty entry for address"
        if ValidationHelper.is_empty(email):
            email_error = "Empty entry for email"

        if name_error or address_error or business_reg_error or owner_error or email_error:
            update_organization = copy.copy(organization)
            update_organization["name"] = name
            update_organization["address"] = address
            update_organization["businessReg"] = business_reg
            update_organization["owner"] = owner
            update_organization["email"] = email
            return render_template(
                "organization-update-basic.html",
                name_error=name_error,
                address_error=address_error,
                business_reg_error=business_reg_error,
                owner_error=owner_error,
                email_error=email_error,
                update_organization=update_organization
            )

        display_logo = None

        if logo_img_file:
            display_logo = ImageHelper.encode(os.path.join(app.config["UPLOAD_FOLDER"], logo_img_file.filename))

        new_organization = copy.copy(organization)
        new_organization["name"] = html.escape(name)
        new_organization["address"] = html.escape(address)
        new_organization["businessReg"] = html.escape(business_reg)
        new_organization["owner"] = html.escape(owner)
        new_organization["email"] = html.escape(email)
        new_organization["displayLogo"] = display_logo or new_organization["displayLogo"]

        if updated_organization := OrganizationApiHelper.update(organization, new_organization):
            app.session_logged_orgs[organization["_id"]] = updated_organization
            return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/update-credentials", methods=["GET", "POST"])
def update_credentials():
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if request.method == "GET":
            return render_template("organization-update-credentials.html")

        password = request.form["password"]
        password_retype = request.form["password-retype"]

        password_error = password_retype_error = None

        if invalidity := ValidationHelper.is_invalid_password(password):
            password_error = invalidity
        if ValidationHelper.is_empty(password):
            password_error = "Empty entry for password"
        if not password_error and password != password_retype:
            password_retype_error = "Retyped password is not same as the password"

        if password_error or password_retype_error:
            return render_template(
                "organization-update-credentials.html",
                password_error=password_error,
                password_retype_error=password_retype_error,
                new_password=password,
                new_password_retype=password_retype
            )

        new_organization = copy.copy(organization)
        new_org_key = RandomKeyHelper.generate_random_key()
        new_organization["orgKey"] = new_org_key
        new_organization["password"] = password
        new_organization["authKey"] = ""

        if _ := OrganizationApiHelper.update_with_credentials(organization, new_organization):
            response = make_response(
                render_template("organization-update-credentials.html", updated_new_org_key=new_org_key),
            )

            session.clear()
            del app.session_logged_orgs[organization["_id"]]
            response.set_cookie("organization-login", expires=0)
            return response
    return redirect(url_for("login"))


@app.route("/delete/<random_fake_word>", methods=["POST"])
@app.route("/delete", methods=["GET"])
def delete(random_fake_word=None):
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if request.method == "GET":
            random_fake_word = FakeWordHelper.generate_random_fake_word()
            return render_template("organization-delete.html", random_fake_word=random_fake_word)

        re_type = request.form["re-type"]

        if re_type == random_fake_word:
            if _ := OrganizationApiHelper.delete(organization):
                response = make_response(redirect(url_for("login")))

                session.clear()
                del app.session_logged_orgs[organization["_id"]]
                response.set_cookie("organization-login", expires=0)

                return response

        random_fake_word = FakeWordHelper.generate_random_fake_word()
        return render_template("organization-delete.html", delete_error="Deletion is not confirmed",
                               random_fake_word=random_fake_word)
    return redirect(url_for("login"))


@app.route("/emotions", methods=["GET", "POST"])
def fetch_emotion_engagement():
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if request.method == "GET":
            return render_template("organization-dashboard.html", emotions=True)

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
                "organization-dashboard.html",
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

        if emotion_engagement := OrganizationApiHelper.fetch_emotion_engagement(organization, hours, weeks, months,
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
                "organization-dashboard.html",
                hours_before=hours_before,
                weeks_before=weeks_before,
                months_before=months_before,
                years_before=years_before,
                emotions=True,
                emotion_engagement_bar_plt=emotion_engagement_bar_plt_str,
                emotion_engagement_pie_plt=emotion_engagement_pie_plt_str
            )
        return render_template(
            "organization-dashboard.html",
            emotions=True,
            emotion_engagement_na="Requested emotional engagement not available"
        )
    return redirect(url_for("login"))


@app.route("/register-subject", methods=["GET", "POST"])
def register_subject():
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if request.method == "GET":
            return render_template("subject-register.html")

        name = request.form["name"]
        address = request.form["address"]
        dob_year, dob_month, dob_day = request.form["dob-year"], request.form["dob-month"], request.form["dob-day"]
        gender = request.form["gender"]
        email = request.form["email"]
        face_snap_dir_uri = request.form["face-snap-dir-uri"]
        salary = request.form["salary"]
        dp_img_file = None
        username = request.form["username"]
        password = request.form["password"]
        password_retype = request.form["password-retype"]
        hidden_diseases = []
        family_category = request.form["family-category"]
        family_monthly_expenses = request.form["family-monthly-expenses"]
        family_monthly_income = request.form["family-monthly-income"]
        family_num_members = request.form["family-num-members"]
        family_num_jobs = request.form["family-num-jobs"]

        if "dp-img-file" in request.files:
            dp_img_file = request.files["dp-img-file"]

            if dp_img_file.filename:
                dp_img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], dp_img_file.filename))

        if "hypertension" in request.form:
            hidden_diseases.append(request.form["hypertension"])
        if "type-2-diabetes" in request.form:
            hidden_diseases.append(request.form["type-2-diabetes"])
        if "chronic-kidney" in request.form:
            hidden_diseases.append(request.form["chronic-kidney"])
        if "osteoporosis" in request.form:
            hidden_diseases.append(request.form["osteoporosis"])
        if "hepatitis-c" in request.form:
            hidden_diseases.append(request.form["hepatitis-c"])
        if "celiac-disease" in request.form:
            hidden_diseases.append(request.form["celiac-disease"])
        if "chlamydia-gonorrhea" in request.form:
            hidden_diseases.append(request.form["chlamydia-gonorrhea"])
        if "hiv-aids" in request.form:
            hidden_diseases.append(request.form["hiv-aids"])
        if "NAFLD" in request.form:
            hidden_diseases.append(request.form["NAFLD"])
        if "depression" in request.form:
            hidden_diseases.append(request.form["depression"])

        name_error = address_error = dob_error = email_error = face_snap_dir_uri_error = salary_error = username_error = \
            password_error = password_retype_error = family_monthly_expenses_error = family_monthly_income_error = \
            family_num_members_error = family_num_jobs_error = None

        if not ValidationHelper.alpha_str_check(name):
            name_error = "Invalid entry for name"
        if ValidationHelper.len_gt_check({name: 20}):
            name_error = "Name doesn't meet maximum length requirement"
        if ValidationHelper.len_lt_check({username: 10}):
            username_error = "Username doesn't meet maximum length requirement"
        if not ValidationHelper.alpha_str_check(address):
            address_error = "Invalid entry for address"
        if not ValidationHelper.date_check(f"{dob_year}-{dob_month}-{dob_day}"):
            dob_error = "Invalid format for date of birth"
        if not ValidationHelper.numeric_str_check(dob_year, dob_month, dob_day):
            dob_error = "Invalid entry for date of birth"
        if not ValidationHelper.email_format_check(email):
            email_error = "Invalid entry for email"
        if not ValidationHelper.numeric_str_check(salary):
            salary_error = "Invalid entry for salary"
        if invalidity := ValidationHelper.is_invalid_password(password):
            password_error = invalidity
        if not ValidationHelper.numeric_str_check(family_monthly_expenses):
            family_monthly_expenses_error = "Invalid entry for monthly expenses"
        if not ValidationHelper.numeric_str_check(family_monthly_income):
            family_monthly_income_error = "Invalid entry for monthly income"
        if not ValidationHelper.numeric_str_check(family_num_members):
            family_num_members_error = "Invalid entry for number of members"
        if not ValidationHelper.numeric_str_check(family_num_jobs):
            family_num_jobs_error = "Invalid entry for number of jobs"
        if ValidationHelper.is_empty(name):
            name_error = "Empty entry for name"
        if ValidationHelper.is_empty(address):
            address_error = "Empty entry for address"
        if ValidationHelper.is_empty(dob_year, dob_month, dob_day):
            dob_error = "Empty entry for date of birth"
        if ValidationHelper.is_empty(email):
            email_error = "Empty entry for email"
        if ValidationHelper.is_empty(face_snap_dir_uri):
            face_snap_dir_uri_error = "Empty entry for face snap directory name"
        if ValidationHelper.is_empty(salary):
            salary_error = "Empty entry for salary"
        if ValidationHelper.is_empty(username):
            username_error = "Empty entry for username"
        if ValidationHelper.is_empty(password):
            password_error = "Empty entry for password"
        if ValidationHelper.is_empty(family_monthly_expenses):
            family_monthly_expenses_error = "Empty entry for monthly expenses"
        if ValidationHelper.is_empty(family_monthly_income):
            family_monthly_income_error = "Empty entry for monthly income"
        if ValidationHelper.is_empty(family_num_members):
            family_num_members_error = "Empty entry for number of members"
        if ValidationHelper.is_empty(family_num_jobs):
            family_num_jobs_error = "Empty entry for number of occupations"
        if not password_error and password != password_retype:
            password_retype_error = "Retyped password is not same as the password"

        if name_error or address_error or dob_error or email_error or face_snap_dir_uri_error or salary_error or \
                username_error or password_error or password_retype_error or family_monthly_expenses_error or \
                family_monthly_income_error or family_num_members_error or family_num_jobs_error:
            return render_template(
                "subject-register.html",
                name_error=name_error,
                address_error=address_error,
                dob_error=dob_error,
                email_error=email_error,
                face_snap_dir_uri_error=face_snap_dir_uri_error,
                salary_error=salary_error,
                username_error=username_error,
                password_error=password_error,
                password_retype_error=password_retype_error,
                family_monthly_expenses_error=family_monthly_expenses_error,
                family_monthly_income_error=family_monthly_income_error,
                family_num_members_error=family_num_members_error,
                family_num_jobs_error=family_num_jobs_error,
                name=name,
                address=address,
                gender=gender,
                dob_year=dob_year,
                dob_month=dob_month,
                dob_day=dob_day,
                email=email,
                face_snap_dir_uri=face_snap_dir_uri,
                salary=salary,
                username=username,
                password=password,
                password_retype=password_retype,
                family_category=family_category,
                family_monthly_expenses=family_monthly_expenses,
                family_monthly_income=family_monthly_income,
                family_num_members=family_num_members,
                family_num_jobs=family_num_jobs,
                hidden_diseases=hidden_diseases
            )

        dp_img = None
        subject = {
            "username": html.escape(username),
            "password": html.escape(password),
            "name": html.escape(name),
            "address": html.escape(address),
            "dob": ValidationHelper.date_check(f"{dob_year}-{dob_month}-{dob_day}").strftime("%Y-%m-%d"),
            "gender": gender,
            "email": html.escape(email),
            "salary": int(salary),
            "hiddenDiseases": hidden_diseases,
            "family": {
                "category": family_category,
                "monthlyCummExpenses": int(family_monthly_expenses),
                "monthlyCummIncome": int(family_monthly_income),
                "numMembers": int(family_num_members),
                "numOccupations": int(family_num_jobs)
            },
            "faceSnapDirURI": html.escape(face_snap_dir_uri)
        }
        if dp_img_file:
            dp_img = ImageHelper.encode(os.path.join(app.config["UPLOAD_FOLDER"], dp_img_file.filename))
        if dp_img:
            subject["displayPhoto"] = dp_img
        if subject := OrganizationApiHelper.register_subject(organization, subject):
            organization["subjects"].append(subject[0])
            return redirect("dashboard")
    return redirect(url_for("login"))


@app.route("/subjects", methods=["GET"])
def fetch_subjects():
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if subjects := OrganizationApiHelper.fetch_subjects(organization):
            for subject in subjects:
                subject["_id"] = OrganizationApiHelper.encrypt(subject["_id"])
                subject["registeredOn"] = datetime.fromisoformat(subject["registeredOn"])
            return render_template("organization-dashboard.html", subjects=subjects)
        return render_template("organization-dashboard.html", subject_na="No any subject available")
    return redirect(url_for("login"))


@app.route("/update-subject", methods=["POST"])
@app.route("/update-subject/<sid>", methods=["GET"])
def update_subject(sid: str = None):
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if request.method == "GET":
            sid = OrganizationApiHelper.decrypt(sid)
            subject = [subject for subject in organization["subjects"] if subject["_id"] == sid][0]
            dob = subject["dob"].strip().split("-")
            return render_template(
                "organization-subject-update.html",
                id=OrganizationApiHelper.encrypt(sid),
                name=subject["name"],
                address=subject["address"],
                gender=subject["gender"],
                dob_year=dob[0],
                dob_month=dob[1],
                dob_day=dob[2],
                email=subject["email"],
                face_snap_dir_uri=subject["faceSnapDirURI"],
                salary=subject["salary"],
                family_category=subject["family"]["category"],
                family_monthly_expenses=subject["family"]["monthlyCummExpenses"],
                family_monthly_income=subject["family"]["monthlyCummIncome"],
                family_num_members=subject["family"]["numMembers"],
                family_num_jobs=subject["family"]["numOccupations"],
                hidden_diseases=subject["hiddenDiseases"]
            )
        sid = OrganizationApiHelper.decrypt(request.form["sid"])
        subject = [subject for subject in organization["subjects"] if subject["_id"] == sid][0]
        name = request.form["name"]
        address = request.form["address"]
        dob_year, dob_month, dob_day = request.form["dob-year"], request.form["dob-month"], request.form["dob-day"]
        gender = request.form["gender"]
        email = request.form["email"]
        face_snap_dir_uri = request.form["face-snap-dir-uri"]
        salary = request.form["salary"]
        dp_img_file = None
        hidden_diseases = []
        family_category = request.form["family-category"]
        family_monthly_expenses = request.form["family-monthly-expenses"]
        family_monthly_income = request.form["family-monthly-income"]
        family_num_members = request.form["family-num-members"]
        family_num_jobs = request.form["family-num-jobs"]

        if "dp-img-file" in request.files:
            dp_img_file = request.files["dp-img-file"]

            if dp_img_file.filename:
                filename = secure_filename(dp_img_file.filename)
                dp_img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        if "hypertension" in request.form:
            hidden_diseases.append(request.form["hypertension"])
        if "type-2-diabetes" in request.form:
            hidden_diseases.append(request.form["type-2-diabetes"])
        if "chronic-kidney" in request.form:
            hidden_diseases.append(request.form["chronic-kidney"])
        if "osteoporosis" in request.form:
            hidden_diseases.append(request.form["osteoporosis"])
        if "hepatitis-c" in request.form:
            hidden_diseases.append(request.form["hepatitis-c"])
        if "celiac-disease" in request.form:
            hidden_diseases.append(request.form["celiac-disease"])
        if "chlamydia-gonorrhea" in request.form:
            hidden_diseases.append(request.form["chlamydia-gonorrhea"])
        if "hiv-aids" in request.form:
            hidden_diseases.append(request.form["hiv-aids"])
        if "NAFLD" in request.form:
            hidden_diseases.append(request.form["NAFLD"])
        if "depression" in request.form:
            hidden_diseases.append(request.form["depression"])

        name_error = address_error = dob_error = email_error = face_snap_dir_uri_error = salary_error = \
            family_monthly_expenses_error = family_monthly_income_error = family_num_members_error = \
            family_num_jobs_error = None

        if not ValidationHelper.alpha_str_check(name):
            name_error = "Invalid entry for name"
        if ValidationHelper.len_gt_check({name: 20}):
            name_error = "Name doesn't meet maximum length requirement"
        if not ValidationHelper.alpha_str_check(address):
            address_error = "Invalid entry for address"
        if not ValidationHelper.date_check(f"{dob_year}-{dob_month}-{dob_day}"):
            dob_error = "Invalid format for date of birth"
        if not ValidationHelper.numeric_str_check(dob_year, dob_month, dob_day):
            dob_error = "Invalid entry for date of birth"
        if not ValidationHelper.email_format_check(email):
            email_error = "Invalid entry for email"
        if not ValidationHelper.numeric_str_check(salary):
            salary_error = "Invalid entry for salary"
        if not ValidationHelper.numeric_str_check(family_monthly_expenses):
            family_monthly_expenses_error = "Invalid entry for monthly expenses"
        if not ValidationHelper.numeric_str_check(family_monthly_income):
            family_monthly_income_error = "Invalid entry for monthly income"
        if not ValidationHelper.numeric_str_check(family_num_members):
            family_num_members_error = "Invalid entry for number of members"
        if not ValidationHelper.numeric_str_check(family_num_jobs):
            family_num_jobs_error = "Invalid entry for number of jobs"
        if ValidationHelper.is_empty(name):
            name_error = "Empty entry for name"
        if ValidationHelper.is_empty(address):
            address_error = "Empty entry for address"
        if ValidationHelper.is_empty(dob_year, dob_month, dob_day):
            dob_error = "Empty entry for date of birth"
        if ValidationHelper.is_empty(email):
            email_error = "Empty entry for email"
        if ValidationHelper.is_empty(face_snap_dir_uri):
            face_snap_dir_uri_error = "Empty entry for face snap directory name"
        if ValidationHelper.is_empty(salary):
            salary_error = "Empty entry for salary"
        if ValidationHelper.is_empty(family_monthly_expenses):
            family_monthly_expenses_error = "Empty entry for monthly expenses"
        if ValidationHelper.is_empty(family_monthly_income):
            family_monthly_income_error = "Empty entry for monthly income"
        if ValidationHelper.is_empty(family_num_members):
            family_num_members_error = "Empty entry for number of members"
        if ValidationHelper.is_empty(family_num_jobs):
            family_num_jobs_error = "Empty entry for number of occupations"

        if name_error or address_error or dob_error or email_error or face_snap_dir_uri_error or salary_error or \
                family_monthly_expenses_error or family_monthly_income_error or family_num_members_error or \
                family_num_jobs_error:
            return render_template(
                "organization-subject-update.html",
                id=OrganizationApiHelper.encrypt(sid),
                name_error=name_error,
                address_error=address_error,
                dob_error=dob_error,
                email_error=email_error,
                face_snap_dir_uri_error=face_snap_dir_uri_error,
                salary_error=salary_error,
                family_monthly_expenses_error=family_monthly_expenses_error,
                family_monthly_income_error=family_monthly_income_error,
                family_num_members_error=family_num_members_error,
                family_num_jobs_error=family_num_jobs_error,
                name=name,
                address=address,
                gender=gender,
                dob_year=dob_year,
                dob_month=dob_month,
                dob_day=dob_day,
                email=email,
                face_snap_dir_uri=face_snap_dir_uri,
                salary=salary,
                family_category=family_category,
                family_monthly_expenses=family_monthly_expenses,
                family_monthly_income=family_monthly_income,
                family_num_members=family_num_members,
                family_num_jobs=family_num_jobs,
                hidden_diseases=hidden_diseases
            )

        dp_img = None
        subject["name"] = html.escape(name)
        subject["address"] = html.escape(address)
        subject["dob"] = ValidationHelper.date_check(f"{dob_year}-{dob_month}-{dob_day}").strftime("%Y-%m-%d")
        subject["gender"] = gender
        subject["email"] = html.escape(email)
        subject["salary"] = int(salary)
        subject["hiddenDiseases"] = hidden_diseases
        subject["family"] = {
            "category": family_category,
            "monthlyCummExpenses": int(family_monthly_expenses),
            "monthlyCummIncome": int(family_monthly_income),
            "numMembers": int(family_num_members),
            "numOccupations": int(family_num_jobs)
        }
        subject["faceSnapDirURI"] = html.escape(face_snap_dir_uri)

        if dp_img_file:
            dp_img = ImageHelper.encode(os.path.join(app.config["UPLOAD_FOLDER"], dp_img_file.filename))
        if dp_img:
            subject["displayPhoto"] = dp_img

        if new_subject := OrganizationApiHelper.update_subject(organization, subject):
            subject = new_subject
            return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/delete-subject/<random_fake_word>", methods=["POST"])
@app.route("/delete-subject/<sid>", methods=["GET"])
def delete_subject(random_fake_word: str = None, sid: str = None):
    if organization := session.get("logged-organization"):
        organization = app.session_logged_orgs[organization]

        if request.method == "GET":
            random_fake_word = FakeWordHelper.generate_random_fake_word()
            return render_template("subject-delete.html", random_fake_word=random_fake_word, id=sid)

        re_type = request.form["re-type"]
        sid = request.form["sid"]

        if re_type == random_fake_word:
            sid = OrganizationApiHelper.decrypt(sid)
            subject = [subject for subject in organization["subjects"] if subject["_id"] == sid][0]

            if _ := OrganizationApiHelper.delete_subject(organization, subject):
                organization["subjects"].remove(subject)
                return redirect(url_for("dashboard"))

        random_fake_word = FakeWordHelper.generate_random_fake_word()
        return render_template("subject-delete.html", delete_error="Deletion is not confirmed",
                               random_fake_word=random_fake_word, id=sid)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.config["UPLOAD_FOLDER"] = "routes/uploads"
    app.run(debug=True, port=5001)
