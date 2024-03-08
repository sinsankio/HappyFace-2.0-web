from helper.api.api_call_config_helper import ApiCallConfigHelper
from helper.request.request_helper import RequestHelper, HttpRequest


class HashHelper:
    @staticmethod
    def hash(content: str) -> str:
        url = f"{ApiCallConfigHelper.UTILITY_API_ENDPOINT}/hash"
        params = {
            "content": content
        }

        if hashed := RequestHelper.perform_request(HttpRequest.GET, url, params=params):
            return hashed
