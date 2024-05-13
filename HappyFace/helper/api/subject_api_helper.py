from helper.api.api_call_config_helper import ApiCallConfigHelper
from helper.hash.hash_helper import HashHelper
from helper.request.request_helper import RequestHelper, HttpRequest


class SubjectApiHelper:
    @staticmethod
    def login(org_key: str, username: str, password: str) -> dict | None:
        url = ApiCallConfigHelper.SUBJECT_API_ENDPOINT
        data = {
            "orgKey": HashHelper.hash(org_key),
            "username": HashHelper.hash(username),
            "password": HashHelper.hash(password)
        }

        if subject := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return subject

    @staticmethod
    def fetch(org_key: str, subject: dict) -> dict | None:
        url = ApiCallConfigHelper.SUBJECT_API_ENDPOINT
        data = {
            "orgKey": org_key,
            "username": subject["username"],
            "password": subject["password"]
        }

        if subject := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return subject

    @staticmethod
    def remember_me(org_auth_key: str, auth_key: str) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}/remember"
        data = {
            "basicRememberMe": {
                "authKey": org_auth_key
            },
            "subAuthKey": auth_key
        }

        if subject := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return subject

    @staticmethod
    def update_with_credentials(org_key: str, subject: dict, new_subject: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}/credentials"
        data = {
            "subject": {
                "orgKey": org_key,
                "username": subject["username"],
                "password": subject["password"]
            },
            "newSubject": new_subject
        }

        if subject := RequestHelper.perform_request(HttpRequest.PUT, url, data=data):
            return subject

    @staticmethod
    def update(org_key: str, subject: dict, new_subject: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}"
        data = {
            "subject": {
                "orgKey": org_key,
                "username": subject["username"],
                "password": subject["password"]
            },
            "newSubject": new_subject
        }

        if subject := RequestHelper.perform_request(HttpRequest.PUT, url, data=data):
            return subject

    @staticmethod
    def fetch_emotion_engagement(org_key: str, subject: dict, hours: int = 0, weeks: int = 0, months: int = 0,
                                 years: int = 0) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}/emotions"
        params = {
            "hours": hours,
            "weeks": weeks,
            "months": months,
            "years": years
        }
        data = {
            "orgKey": org_key,
            "username": subject["username"],
            "password": subject["password"]
        }

        if emotion_engagement := RequestHelper.perform_request(HttpRequest.POST, url, params=params, data=data):
            return emotion_engagement

    @staticmethod
    def fetch_latest_consultancy(org_key: str, subject: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}/consultation"
        data = {
            "orgKey": org_key,
            "username": subject["username"],
            "password": subject["password"]
        }

        if consultancy := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return consultancy

    @staticmethod
    def chat_with_assistant(org_key: str, subject: dict, message: str) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}/consultation/chat"
        data = {
            "subject": {
                "orgKey": org_key,
                "username": subject["username"],
                "password": subject["password"]
            },
            "message": {
                "sender": "friend",
                "receiver": "emotionistant",
                "body": message
            }
        }

        if consultancy := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return consultancy

    @staticmethod
    def request_special_consideration(org_key: str, subject: dict, message: str) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}/scr"
        data = {
            "subject": {
                "username": subject["username"],
                "password": subject["password"],
                "orgKey": org_key
            },
            "specialConsiderationRequest": {
                "message": message
            }
        }

        if analysis := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return analysis

    @staticmethod
    def fetch_responded_special_consideration_requests(org_key: str, subject: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}/scr-responses"
        data = {
            "username": subject["username"],
            "password": subject["password"],
            "orgKey": org_key
        }

        if responded_scrs := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return responded_scrs
