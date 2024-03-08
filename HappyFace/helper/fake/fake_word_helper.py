import secrets
import string


class FakeWordHelper:
    @staticmethod
    def generate_random_fake_word(length=8):
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
