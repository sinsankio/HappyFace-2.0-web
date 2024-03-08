import secrets
import string


class RandomKeyHelper:
    @staticmethod
    def generate_random_key(length=15) -> str:
        alphabet = string.ascii_letters + string.digits
        key = ''.join(secrets.choice(alphabet) for _ in range(length))

        return f"hf-v1-{key}"
