"""各类字段的合法性校验，供生成器自检与测试使用。"""
import re
from datetime import date

ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
ID_CHECK_CHARS = "10X98765432"

_MOBILE_RE = re.compile(r"^1[3-9]\d{9}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_AMOUNT_RE = re.compile(r"^-?\d+\.\d{2}$")
_CN_NAME_RE = re.compile(r"^[一-鿿]{2,4}$")


def is_valid_cn_name(value):
    return bool(_CN_NAME_RE.match(value))


def is_valid_mobile(value):
    return bool(_MOBILE_RE.match(value))


def is_valid_email(value):
    return bool(_EMAIL_RE.match(value)) and len(value) <= 254


def luhn_ok(number):
    if not number.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check_digit(prefix):
    """给定卡号前若干位，算出使整体过 Luhn 的校验位。"""
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def id_check_char(body17):
    total = sum(int(c) * w for c, w in zip(body17, ID_WEIGHTS))
    return ID_CHECK_CHARS[total % 11]


def is_valid_id(value):
    if len(value) != 18 or not value[:17].isdigit():
        return False
    if value[17].upper() not in ID_CHECK_CHARS:
        return False
    if id_check_char(value[:17]) != value[17].upper():
        return False
    try:
        date(int(value[6:10]), int(value[10:12]), int(value[12:14]))
    except ValueError:
        return False
    return True


def is_valid_date(value):
    try:
        date.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_amount(value):
    return bool(_AMOUNT_RE.match(value))
