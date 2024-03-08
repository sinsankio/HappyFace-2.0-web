import re
from datetime import datetime


class ValidationHelper:
    @staticmethod
    def is_empty(*entries) -> bool:
        return any(not entry or entry and entry.isspace() for entry in entries)

    @staticmethod
    def len_gt_check(entries: dict) -> bool:
        return all(len(entry) >= size for entry, size in entries.items())

    @staticmethod
    def len_lt_check(entries: dict) -> bool:
        return all(len(entry) <= size for entry, size in entries.items())

    @staticmethod
    def alpha_str_check(*entries) -> bool:
        return not any(entry.isdigit() for entry in entries)

    @staticmethod
    def numeric_str_check(*entries) -> bool:
        return all(entry.isdigit() for entry in entries)

    @staticmethod
    def email_format_check(*entries):
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        return all(re.match(pattern, entry) for entry in entries)

    @staticmethod
    def date_check(date: str, format: str = "%Y-%m-%d"):
        try:
            return datetime.strptime(date, format)
        except ValueError:
            return False

    @staticmethod
    def is_invalid_password(password: str) -> str | None:
        if not any(char.isupper() for char in password):
            return "Password should contain at least one uppercase"
        if not any(char.islower() for char in password):
            return "Password should contain at least one lowercase"
        if not any(char.isdigit() for char in password):
            return "Password should contain at least one digit"
        if not re.search(r"[!@#$%^&*()_+={}\[\]:;<>,.?~`\\|/\-]", password):
            return "Password should contain at least one special character"
        if ' ' in password:
            return "Password should not contain any spaces"
