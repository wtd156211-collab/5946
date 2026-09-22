"""各列类型的可逆变换。

所有变换都是 (子密钥, 类型, 原值) 的确定性函数：
- 同一原值在任何列、任何批次映射结果相同（tweak 只含类型，不含列名/行号）；
- 不同原值不会碰撞（FPE 是置换）；
- 拿着同一密钥可逆推出原值；
- 换密钥则映射全变。

值域外的异常值（如含生僻字符的姓名）走 fallback：确定性的伪随机合法假值，
原值加密后写入还原清单，还原时优先查清单。
"""

import hashlib
import re
from datetime import date, timedelta
from decimal import Decimal

from .fpe import FPE, derive_subkey, encode_text, decode_text

CJK_ALPHABET = "".join(chr(c) for c in range(0x4E00, 0xA000))  # 20992 个 CJK 统一表意文字
CJK_INDEX = {ch: i for i, ch in enumerate(CJK_ALPHABET)}
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALNUM_INDEX = {ch: i for i, ch in enumerate(ALNUM)}
ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_INDEX = {ch: i for i, ch in enumerate(ALPHA)}

MOBILE_RE = re.compile(r"1[3-9]\d{9}\Z")
PAN_RE = re.compile(r"\d{13,19}\Z")
ID_RE = re.compile(r"\d{17}[\dXx]\Z")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\Z")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]+")

ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
ID_CHECK_CHARS = "10X98765432"
ID_BIRTH_START = date(1900, 1, 1)
ID_BIRTH_DAYS = (date(2024, 12, 31) - ID_BIRTH_START).days + 1  # 固定常数，与运行日期无关

NAME_MIN_LEN = 2
NAME_MAX_LEN = 4


class FallbackNeeded(Exception):
    """原值不在该类型的严格值域内，需走清单兜底。"""


def luhn_check_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:  # 从右往左第 1、3、5... 位（校验位补在最右后这些位要翻倍）
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def id_check_char(body17: str) -> str:
    return ID_CHECK_CHARS[sum(int(a) * w for a, w in zip(body17, ID_WEIGHTS)) % 11]


class Transformer:
    """持有主密钥，提供逐值的 mask / unmask。全部无状态（除有界缓存），可流式使用。"""

    CACHE_LIMIT = 200_000  # 缓存有上限，内存不随行数增长

    def __init__(self, master_key: bytes):
        if len(master_key) < 16:
            raise ValueError("master key too short, need at least 16 bytes")
        self._key = master_key
        self._cache = {}
        raw = int.from_bytes(derive_subkey(master_key, b"date-shift"), "big") % 730
        shift = raw - 365
        self.date_shift = shift if shift != 0 else 365  # [-365,-1] U [1,365]，恒非零

    # ---- 通用 FPE 入口 -------------------------------------------------

    def _fpe(self, purpose: bytes, modulus: int) -> FPE:
        return FPE(derive_subkey(self._key, purpose), purpose, modulus)

    def _fpe_str(self, purpose: bytes, s: str, alphabet: str, index: dict) -> str:
        base = len(alphabet)
        fpe = self._fpe(purpose + bytes([len(s)]), base ** len(s))
        return decode_text(fpe.encrypt(encode_text(s, alphabet, index)), alphabet, len(s))

    def _unfpe_str(self, purpose: bytes, s: str, alphabet: str, index: dict) -> str:
        base = len(alphabet)
        fpe = self._fpe(purpose + bytes([len(s)]), base ** len(s))
        return decode_text(fpe.decrypt(encode_text(s, alphabet, index)), alphabet, len(s))

    # ---- 各类型 mask ---------------------------------------------------

    def mask(self, ctype: str, value: str) -> str:
        key = ("m", ctype, value)
        hit = self._cache.get(key)
        if hit is None:
            hit = self._dispatch(ctype, value, True)
            if len(self._cache) < self.CACHE_LIMIT:
                self._cache[key] = hit
        return hit

    def unmask(self, ctype: str, value: str) -> str:
        key = ("u", ctype, value)
        hit = self._cache.get(key)
        if hit is None:
            hit = self._dispatch(ctype, value, False)
            if len(self._cache) < self.CACHE_LIMIT:
                self._cache[key] = hit
        return hit

    def _dispatch(self, ctype: str, value: str, forward: bool) -> str:
        handler = _HANDLERS[ctype]
        return handler(self, value) if forward else _UNHANDLERS[ctype](self, value)

    # cn_name：长度不变，逐字符落在 CJK 区间，整体做一次 FPE
    def _mask_name(self, v: str) -> str:
        if not (NAME_MIN_LEN <= len(v) <= NAME_MAX_LEN) or any(c not in CJK_INDEX for c in v):
            raise FallbackNeeded(v)
        return self._fpe_str(b"cn_name", v, CJK_ALPHABET, CJK_INDEX)

    def _unmask_name(self, v: str) -> str:
        return self._unfpe_str(b"cn_name", v, CJK_ALPHABET, CJK_INDEX)

    # cn_mobile：1[3-9]xxxxxxxxx，值域 7*10^9
    def _mask_mobile(self, v: str) -> str:
        if not MOBILE_RE.fullmatch(v):
            raise FallbackNeeded(v)
        idx = (int(v[1]) - 3) * 10**9 + int(v[2:])
        out = self._fpe(b"cn_mobile", 7 * 10**9).encrypt(idx)
        return "1" + str(out // 10**9 + 3) + "%09d" % (out % 10**9)

    def _unmask_mobile(self, v: str) -> str:
        idx = (int(v[1]) - 3) * 10**9 + int(v[2:])
        out = self._fpe(b"cn_mobile", 7 * 10**9).decrypt(idx)
        return "1" + str(out // 10**9 + 3) + "%09d" % (out % 10**9)

    # email：local 与每个域名标签内的 [A-Za-z0-9] 游程分别做定长 FPE，
    # 顶级标签只用字母表，其余字符原样保留；整体仍是合法邮箱且映射单射
    def _mask_email(self, v: str) -> str:
        if not EMAIL_RE.fullmatch(v):
            raise FallbackNeeded(v)
        return self._email_map(v, True)

    def _unmask_email(self, v: str) -> str:
        return self._email_map(v, False)

    def _email_map(self, v: str, forward: bool) -> str:
        local, domain = v.split("@")
        labels = domain.split(".")
        parts = [("local", local)] + [("tld" if i == len(labels) - 1 else "label", lab)
                                      for i, lab in enumerate(labels)]
        out = []
        for kind, text in parts:
            alpha, idx = (ALPHA, ALPHA_INDEX) if kind == "tld" else (ALNUM, ALNUM_INDEX)
            purpose = b"email-" + kind.encode()
            def sub(m):
                s = m.group(0)
                f = self._fpe_str if forward else self._unfpe_str
                return f(purpose, s, alpha, idx)
            out.append(ALNUM_RUN_RE.sub(sub, text))
        return out[0] + "@" + ".".join(out[1:])

    # pan：除末位校验位外做 FPE，重算 Luhn 校验位
    def _mask_pan(self, v: str) -> str:
        if not PAN_RE.fullmatch(v):
            raise FallbackNeeded(v)
        return self._pan_map(v, True)

    def _unmask_pan(self, v: str) -> str:
        return self._pan_map(v, False)

    def _pan_map(self, v: str, forward: bool) -> str:
        body = v[:-1]
        fpe = self._fpe(b"pan" + bytes([len(v)]), 10 ** len(body))
        n = fpe.encrypt(int(body)) if forward else fpe.decrypt(int(body))
        new_body = "%0*d" % (len(body), n)
        return new_body + luhn_check_digit(new_body)

    # cn_id：地址码、出生日期（1900-2024 真实日期区间）、顺序码分别 FPE，重算校验位
    def _mask_id(self, v: str) -> str:
        return self._id_map(v, True)

    def _unmask_id(self, v: str) -> str:
        return self._id_map(v, False)

    def _id_map(self, v: str, forward: bool) -> str:
        if not ID_RE.fullmatch(v):
            raise FallbackNeeded(v)
        addr, birth, seq = v[:6], v[6:14], v[14:17]
        try:
            bd = date(int(birth[:4]), int(birth[4:6]), int(birth[6:8]))
        except ValueError:
            raise FallbackNeeded(v)
        days = (bd - ID_BIRTH_START).days
        if not 0 <= days < ID_BIRTH_DAYS:
            raise FallbackNeeded(v)
        f_addr = self._fpe(b"id-addr", 10**6)
        f_birth = self._fpe(b"id-birth", ID_BIRTH_DAYS)
        f_seq = self._fpe(b"id-seq", 10**3)
        op = lambda f, x: f.encrypt(x) if forward else f.decrypt(x)
        new_addr = "%06d" % op(f_addr, int(addr))
        new_birth = (ID_BIRTH_START + timedelta(days=op(f_birth, days))).strftime("%Y%m%d")
        new_seq = "%03d" % op(f_seq, int(seq))
        body = new_addr + new_birth + new_seq
        return body + id_check_char(body)

    # date：整体平移密钥派生的固定天数，保序
    def _mask_date(self, v: str) -> str:
        return self._date_map(v, True)

    def _unmask_date(self, v: str) -> str:
        return self._date_map(v, False)

    def _date_map(self, v: str, forward: bool) -> str:
        if not DATE_RE.fullmatch(v):
            raise FallbackNeeded(v)
        try:
            d = date(int(v[:4]), int(v[5:7]), int(v[8:10]))
        except ValueError:
            raise FallbackNeeded(v)
        delta = self.date_shift if forward else -self.date_shift
        return (d + timedelta(days=delta)).isoformat()

    # decimal_cny：以分为单位，在 10^(d-2) 大小的分块内做 FPE。
    # 单射、可逆、扰动幅度 < ~10%、数量级（分的位数）严格不变。
    def _mask_amount(self, v: str) -> str:
        return self._amount_map(v, True)

    def _unmask_amount(self, v: str) -> str:
        return self._amount_map(v, False)

    def _amount_map(self, v: str, forward: bool) -> str:
        try:
            dec = Decimal(v)
        except ArithmeticError:
            raise FallbackNeeded(v)
        cents_dec = dec * 100
        if cents_dec != cents_dec.to_integral_value():
            raise FallbackNeeded(v)  # 超过两位小数，无法保真
        cents = int(cents_dec)
        sign = "-" if cents < 0 else ""
        c = abs(cents)
        if c == 0:
            return "0.00"
        if c < 100:
            block, base = 100, 0  # 不足 1 元：在 [0,100) 内置换，绝对偏差 < 1 元
        else:
            block = 10 ** (len(str(c)) - 2)
            base = (c // block) * block
        fpe = self._fpe(b"amount" + str(block).encode(), block)
        n = fpe.encrypt(c - base) if forward else fpe.decrypt(c - base)
        out = base + n
        return "%s%d.%02d" % (sign, out // 100, out % 100)


_HANDLERS = {
    "cn_name": Transformer._mask_name,
    "cn_mobile": Transformer._mask_mobile,
    "email": Transformer._mask_email,
    "pan": Transformer._mask_pan,
    "cn_id": Transformer._mask_id,
    "date": Transformer._mask_date,
    "decimal_cny": Transformer._mask_amount,
}

_UNHANDLERS = {
    "cn_name": Transformer._unmask_name,
    "cn_mobile": Transformer._unmask_mobile,
    "email": Transformer._unmask_email,
    "pan": Transformer._unmask_pan,
    "cn_id": Transformer._unmask_id,
    "date": Transformer._unmask_date,
    "decimal_cny": Transformer._unmask_amount,
}


def _prf_bytes(key: bytes, purpose: bytes, value: str, n: int) -> bytes:
    sub = derive_subkey(key, b"fallback-" + purpose)
    seed = value.encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(sub + seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _digits(data: bytes, n: int) -> str:
    return "".join(str(b % 10) for b in data[:n])


def _fallback_generators():
    def cn_name(key, v):
        raw = _prf_bytes(key, b"cn_name", v, 4)
        return "".join(CJK_ALPHABET[int.from_bytes(raw[i:i+2], "big") % len(CJK_ALPHABET)]
                       for i in (0, 2))

    def cn_mobile(key, v):
        raw = _prf_bytes(key, b"cn_mobile", v, 10)
        return "1" + str(3 + raw[0] % 7) + _digits(raw[1:], 9)

    def email(key, v):
        raw = _prf_bytes(key, b"email", v, 12)
        return "".join(ALNUM[b % len(ALNUM)] for b in raw) + "@masked.example"

    def pan(key, v):
        raw = _prf_bytes(key, b"pan", v, 15)
        body = "62" + _digits(raw, 13)
        return body + luhn_check_digit(body)

    def cn_id(key, v):
        raw = _prf_bytes(key, b"cn_id", v, 12)
        addr = "11" + _digits(raw[0:4], 4)
        birth = (ID_BIRTH_START + timedelta(
            days=int.from_bytes(raw[4:8], "big") % ID_BIRTH_DAYS)).strftime("%Y%m%d")
        seq = _digits(raw[8:11], 3)
        body = addr + birth + seq
        return body + id_check_char(body)

    def date_(key, v):
        raw = _prf_bytes(key, b"date", v, 4)
        return (date(2020, 1, 1) + timedelta(days=int.from_bytes(raw, "big") % 3653)).isoformat()

    def decimal_cny(key, v):
        raw = _prf_bytes(key, b"decimal_cny", v, 4)
        cents = int.from_bytes(raw, "big") % 100000
        return "%d.%02d" % (cents // 100, cents % 100)

    return {
        "cn_name": cn_name, "cn_mobile": cn_mobile, "email": email, "pan": pan,
        "cn_id": cn_id, "date": date_, "decimal_cny": decimal_cny,
    }


_FALLBACKS = _fallback_generators()


def _fallback_mask(self, ctype: str, value: str) -> str:
    """值域外异常值的兜底：同一 (key, type, value) 恒得同一合法假值。"""
    return _FALLBACKS[ctype](self._key, value)


Transformer.fallback_mask = _fallback_mask
