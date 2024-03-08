import base64

import cv2
import numpy as np


class ImageHelper:
    @staticmethod
    def encode(img_uri: str) -> str | None:
        with open(img_uri, "rb") as file:
            return base64.b64encode(file.read()).decode("utf-8")

    @staticmethod
    def encode_np(np_img: np.ndarray, enc_format: str = ".jpg") -> str | None:
        if np_img is not None:
            _, img_data = cv2.imencode(enc_format, np_img)
            return base64.b64encode(img_data).decode("utf-8")
