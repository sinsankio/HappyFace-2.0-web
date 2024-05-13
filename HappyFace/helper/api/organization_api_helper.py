from helper.api.api_call_config_helper import ApiCallConfigHelper
from helper.hash.hash_helper import HashHelper
from helper.request.request_helper import RequestHelper, HttpRequest


class OrganizationApiHelper:
    @staticmethod
    def login(org_key: str, password: str) -> dict | None:
        url = ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT
        data = {
            "orgKey": HashHelper.hash(org_key),
            "password": HashHelper.hash(password)
        }

        if organization := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return organization

    @staticmethod
    def remember_me(auth_key: str) -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/remember"
        data = {
            "authKey": auth_key
        }

        if organization := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return organization

    @staticmethod
    def update_with_credentials(organization: dict, new_organization: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/credentials"
        data = {
            "organization": {
                "orgKey": organization["orgKey"],
                "password": organization["password"]
            },
            "newOrganization": new_organization
        }

        if organization := RequestHelper.perform_request(HttpRequest.PUT, url, data=data):
            return organization

    @staticmethod
    def update(organization: dict, new_organization: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}"
        data = {
            "organization": {
                "orgKey": organization["orgKey"],
                "password": organization["password"]
            },
            "newOrganization": new_organization
        }

        if organization := RequestHelper.perform_request(HttpRequest.PUT, url, data=data):
            return organization

    @staticmethod
    def register(organization: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/new"

        if organization := RequestHelper.perform_request(HttpRequest.POST, url, data=organization):
            return organization

    @staticmethod
    def delete(organization: dict) -> int | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}"
        data = {
            "orgKey": organization["orgKey"],
            "password": organization["password"]
        }

        if status := RequestHelper.perform_request(HttpRequest.DELETE, url, data=data):
            return status

    @staticmethod
    def fetch_emotion_engagement(organization: dict, hours: int = 0, weeks: int = 0, months: int = 0, years: int = 0) \
            -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/emotions"
        params = {
            "hours": hours,
            "weeks": weeks,
            "months": months,
            "years": years
        }
        data = {
            "orgKey": organization["orgKey"],
            "password": organization["password"]
        }

        if emotion_engagement := RequestHelper.perform_request(HttpRequest.POST, url, params=params, data=data):
            return emotion_engagement

    @staticmethod
    def register_subject(organization: dict, subject: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/subjects/new"
        data = {
            "organization": {
                "orgKey": organization["orgKey"],
                "password": organization["password"]
            },
            "subjects": [subject]
        }

        if subject := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return subject

    @staticmethod
    def fetch_subjects(organization: dict) -> list[dict] | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/subjects/all"
        data = {
            "orgKey": organization["orgKey"],
            "password": organization["password"]
        }

        if subjects := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return subjects

    @staticmethod
    def update_subject(organization: dict, subject: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}"
        data = {
            "subject": {
                "username": subject["username"],
                "password": subject["password"],
                "orgKey": organization["orgKey"]
            },
            "newSubject": subject
        }

        if subject := RequestHelper.perform_request(HttpRequest.PUT, url, data=data):
            return subject

    @staticmethod
    def delete_subject(organization: dict, subject: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.SUBJECT_API_ENDPOINT}"
        data = {
            "orgKey": organization["orgKey"],
            "password": organization["password"]
        }
        params = {
            "subId": OrganizationApiHelper.encrypt(subject["_id"])
        }

        if status := RequestHelper.perform_request(HttpRequest.DELETE, url, params=params, data=data):
            return status

    @staticmethod
    def fetch_special_consideration_requests(organization: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/scr"
        data = {
            "orgKey": organization["orgKey"],
            "password": organization["password"]
        }

        if sc_requests := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return sc_requests

    @staticmethod
    def make_responses_for_special_consideration_requests(organization: dict, scr_responses: list[dict]) -> dict | None:
        url = f"{ApiCallConfigHelper.ORGANIZATION_API_ENDPOINT}/scr-response"
        data = {
            "organization": {
                "orgKey": organization["orgKey"],
                "password": organization["password"]
            },
            "scrResponses": scr_responses
        }

        if organization := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return organization

    @staticmethod
    def encrypt(content: str) -> str | None:
        url = f"{ApiCallConfigHelper.UTILITY_API_ENDPOINT}/encrypt"
        params = {
            "content": content
        }

        if encrypted := RequestHelper.perform_request(HttpRequest.GET, url, params=params):
            return encrypted

    @staticmethod
    def decrypt(content: str) -> str | None:
        url = f"{ApiCallConfigHelper.UTILITY_API_ENDPOINT}/decrypt"
        params = {
            "content": content
        }

        if decrypted := RequestHelper.perform_request(HttpRequest.GET, url, params=params):
            return decrypted
