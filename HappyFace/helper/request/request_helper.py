from enum import Enum
from typing import Any

import requests


class HttpRequest(Enum):
    GET = 0,
    POST = 1,
    PUT = 2,
    DELETE = 3


class RequestHelper:
    @staticmethod
    def perform_request(request: HttpRequest, url: str, data: dict = None, params: dict = None) -> Any | None:
        if request == HttpRequest.GET:
            response = requests.get(url, params=params)
        elif request == HttpRequest.POST:
            response = requests.post(url, params=params, json=data)
        elif request == HttpRequest.PUT:
            response = requests.put(url, params=params, json=data)
        else:
            response = requests.delete(url, params=params, json=data)

        if response.status_code == 200:
            response = response.json()

            return response
