from helper.api.api_call_config_helper import ApiCallConfigHelper
from helper.hash.hash_helper import HashHelper
from helper.request.request_helper import RequestHelper, HttpRequest


class AdminApiHelper:
    @staticmethod
    def login(username: str, password: str) -> dict | None:
        url = ApiCallConfigHelper.BASE_URL
        data = {
            "username": HashHelper.hash(username),
            "password": HashHelper.hash(password)
        }

        if admin := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return admin

    @staticmethod
    def remember_me(auth_key: str) -> dict | None:
        url = f"{ApiCallConfigHelper.BASE_URL}/remember"
        data = {
            "authKey": auth_key
        }

        if admin := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return admin

    @staticmethod
    def update_with_credentials(admin: dict, new_admin: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.BASE_URL}/credentials"
        data = {
            "admin": {
                "username": admin["username"],
                "password": admin["password"]
            },
            "new_admin": new_admin
        }

        if admin := RequestHelper.perform_request(HttpRequest.PUT, url, data=data):
            return admin

    @staticmethod
    def update(admin: dict, new_admin: dict) -> dict | None:
        url = f"{ApiCallConfigHelper.BASE_URL}"
        data = {
            "admin": {
                "username": admin["username"],
                "password": admin["password"]
            },
            "new_admin": new_admin
        }

        if admin := RequestHelper.perform_request(HttpRequest.PUT, url, data=data):
            return admin

    @staticmethod
    def fetch_organizations(admin: dict) -> list[dict]:
        url = f"{ApiCallConfigHelper.BASE_URL}/orgs/all"
        data = {
            "username": admin["username"],
            "password": admin["password"]
        }

        if organizations := RequestHelper.perform_request(HttpRequest.POST, url, data=data):
            return organizations
