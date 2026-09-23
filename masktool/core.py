"""脱敏核心：密钥派生映射、合法假值生成、还原清单、流式文件处理。

映射原理：masked = F(HMAC-SHA256(key, purpose|col_type|original|counter))。
同一密钥下同一原值必然得到同一结果；换密钥则整套映射全部改变。
不同原值若撞到同一结果，counter 递增重试，由还原清单保证按列唯一。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import date, timedelta
from decimal import Decimal, ROUND_HALF_UP

from .validators import ID_WEIGHTS, ID_CHECK_CHARS, luhn_check_digit

SURNAMES = (
    "王李张刘陈杨黄赵吴周徐孙马朱胡郭何罗高林郑梁谢宋唐许韩冯邓曹彭"
    "曾肖田董潘袁蔡蒋余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖"
    "贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱"
)
GIVEN_CHARS = (
    "伟强磊军洋勇艳杰娟涛明超秀兰霞平刚桂英华玉萍红梅兰竹菊芳娜敏"
    "静文辉力健永安康成思雨欣子轩浩然梓涵一诺依诺建国志远春燕金凤"
    "晓东海涛文静雅琪梦琪子墨雨泽天佑沐宸若汐艺涵欣怡诗涵俊杰嘉懿"
)
ID_REGIONS = (
    "110101", "110105", "120101", "310104", "310110", "320106", "320505",
    "330103", "330203", "350102", "420106", "430104", "440103", "440305",
    "510107", "520102", "610113", "610104",
)
EMAIL_LOCAL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

CACHE_LIMIT = 500_000


def generate_key():
    """生成 32 字节随机密钥，返回 hex 字符串（写入密钥文件）。"""
    return secrets.token_hex(32)


def load_key(text):
    key = bytes.fromhex(text.strip())
    if len(key) < 16:
        raise ValueError("密钥太短，至少 16 字节（32 个 hex 字符）")
    return key


def _prf_bytes(key, purpose, col_type, original, counter, nbytes):
    seed = b"|".join([
        purpose,
        col_type.encode("utf-8"),
        original.encode("utf-8"),
        str(counter).encode("ascii"),
    ])
    out = bytearray()
    block = 0
    while len(out) < nbytes:
        out += hmac.new(key, seed + b"|" + str(block).encode("ascii"),
                        hashlib.sha256).digest()
        block += 1
    return bytes(out[:nbytes])


def _tag(key, col_type, original):
    return hmac.new(
        key,
        b"tag|" + col_type.encode("utf-8") + b"|" + original.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _xor_crypt(key, tag, data):
    stream = bytearray()
    block = 0
    while len(stream) < len(data):
        stream += hmac.new(
            key,
            b"enc|" + tag.encode("ascii") + b"|" + str(block).encode("ascii"),
            hashlib.sha256,
        ).digest()
        block += 1
    return bytes(a ^ b for a, b in zip(data, stream))


# ---------------------------------------------------------------- 假值生成

def _gen_cn_name(key, original, counter):
    raw = _prf_bytes(key, b"mask", "cn_name", original, counter, 4)
    surname = SURNAMES[raw[0] % len(SURNAMES)]
    given_len = 1 + raw[1] % 2
    given = "".join(GIVEN_CHARS[raw[2 + i] % len(GIVEN_CHARS)]
                    for i in range(given_len))
    return surname + given


def _gen_cn_mobile(key, original, counter):
    raw = _prf_bytes(key, b"mask", "cn_mobile", original, counter, 10)
    return ("1" + "3456789"[raw[0] % 7]
            + "".join(str(raw[1 + i] % 10) for i in range(9)))


def _gen_email(key, original, counter):
    raw = _prf_bytes(key, b"mask", "email", original, counter, 13)
    local_len = 8 + raw[0] % 5
    local = "".join(EMAIL_LOCAL_ALPHABET[b % len(EMAIL_LOCAL_ALPHABET)]
                    for b in raw[1:1 + local_len])
    domain = original.rsplit("@", 1)[1] if "@" in original else "example.com"
    return local + "@" + domain


def _gen_pan(key, original, counter):
    raw = _prf_bytes(key, b"mask", "pan", original, counter, 13)
    prefix = "62" + "".join(str(b % 10) for b in raw)
    return prefix + luhn_check_digit(prefix)


def _gen_cn_id(key, original, counter):
    raw = _prf_bytes(key, b"mask", "cn_id", original, counter, 8)
    region = ID_REGIONS[raw[0] % len(ID_REGIONS)]
    year = 1950 + int.from_bytes(raw[1:3], "big") % 56
    month = 1 + raw[3] % 12
    day = 1 + raw[4] % 28
    seq = "{:03d}".format(int.from_bytes(raw[5:8], "big") % 1000)
    body = "{}{:04d}{:02d}{:02d}{}".format(region, year, month, day, seq)
    total = sum(int(c) * w for c, w in zip(body, ID_WEIGHTS))
    return body + ID_CHECK_CHARS[total % 11]


def _gen_amount(key, original, counter):
    raw = _prf_bytes(key, b"mask", "decimal_cny", original, counter, 4)
    bp = int.from_bytes(raw, "big") % 2001 - 1000  # -10.00% .. +10.00%
    value = Decimal(original) * Decimal(10000 + bp) / Decimal(10000)
    return str(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


_GENERATORS = {
    "cn_name": _gen_cn_name,
    "cn_mobile": _gen_cn_mobile,
    "email": _gen_email,
    "pan": _gen_pan,
    "cn_id": _gen_cn_id,
    "decimal_cny": _gen_amount,
}


def derive_date_offset(key):
    """从密钥派生全局日期位移（天），非零，范围 ±3650。"""
    digest = hmac.new(key, b"date-shift", hashlib.sha256).digest()
    days = int.from_bytes(digest[:4], "big") % 3650 + 1
    return -days if digest[4] % 2 else days


# ---------------------------------------------------------------- 还原清单

class Manifest:
    """SQLite 还原清单：磁盘存储，内存占用与行数无关。

    entries 每行存 (col_type, masked, tag, enc)：
    - masked  脱敏后的值，还原时按它反查；
    - tag     HMAC(key, "tag"|col_type|original)，无密钥不可反推原值；
    - enc     原值 UTF-8 与 HMAC 派生密钥流异或后的密文，无密钥不可读。
    """

    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS entries ("
            " col_type TEXT NOT NULL,"
            " masked TEXT NOT NULL,"
            " tag TEXT NOT NULL,"
            " enc BLOB NOT NULL,"
            " PRIMARY KEY (col_type, masked))")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS meta ("
            " k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        self._pending = 0

    def find_by_masked(self, col_type, masked):
        return self.conn.execute(
            "SELECT tag, enc FROM entries WHERE col_type=? AND masked=?",
            (col_type, masked)).fetchone()

    def insert(self, col_type, masked, tag, enc):
        self.conn.execute(
            "INSERT INTO entries (col_type, masked, tag, enc)"
            " VALUES (?, ?, ?, ?)",
            (col_type, masked, tag, sqlite3.Binary(enc)))
        self._pending += 1
        if self._pending >= 1000:
            self.conn.commit()
            self._pending = 0

    def get_meta(self, k):
        row = self.conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else None

    def set_meta(self, k, v):
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (k, v))

    def close(self):
        self.conn.commit()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------- 脱敏器

class Masker:
    def __init__(self, key, manifest, columns):
        self.key = key
        self.manifest = manifest
        self.rules = {c["name"]: c for c in columns}
        self._cache = {}
        offset = manifest.get_meta("date_offset_days")
        if offset is None:
            offset = str(derive_date_offset(key))
            manifest.set_meta("date_offset_days", offset)
        self.date_offset = int(offset)

    # -- 单向映射（带冲突重试，保证按列唯一） --

    def _mapped(self, col_type, original):
        cache_key = (col_type, original)
        hit = self._cache.get(cache_key)
        if hit is not None:
            return hit
        tag = _tag(self.key, col_type, original)
        generate = _GENERATORS[col_type]
        counter = 0
        while True:
            candidate = generate(self.key, original, counter)
            if candidate == original:  # 不允许恒等映射
                counter += 1
                continue
            row = self.manifest.find_by_masked(col_type, candidate)
            if row is None:
                enc = _xor_crypt(self.key, tag, original.encode("utf-8"))
                self.manifest.insert(col_type, candidate, tag, enc)
                break
            if row[0] == tag:
                break  # 之前已映射过，结果一致
            counter += 1  # 撞到了别的原值，重试
        if len(self._cache) >= CACHE_LIMIT:
            self._cache.clear()
        self._cache[cache_key] = candidate
        return candidate

    # -- 日期位移 --

    def _shift_date(self, value, sign):
        shifted = date.fromisoformat(value) + timedelta(
            days=sign * self.date_offset)
        return shifted.isoformat()

    # -- 字段级接口 --

    def mask_field(self, col_name, value):
        rule = self.rules[col_name]
        kind = rule["mask"]
        if kind == "keep" or value == "":
            return value
        if kind == "shift":
            return self._shift_date(value, +1)
        return self._mapped(rule["type"], value)

    def restore_field(self, col_name, value):
        rule = self.rules[col_name]
        kind = rule["mask"]
        if kind == "keep" or value == "":
            return value
        if kind == "shift":
            return self._shift_date(value, -1)
        row = self.manifest.find_by_masked(rule["type"], value)
        if row is None:
            raise KeyError(
                "还原清单中找不到 {} 列的值 {!r}，"
                "请确认使用了生成该文件时的同一份清单".format(col_name, value))
        tag, enc = row
        return _xor_crypt(self.key, tag, bytes(enc)).decode("utf-8")


# ---------------------------------------------------------------- 文件处理

def process_file(masker, fin, fout, direction):
    """逐行流式处理 CSV，内存占用与行数无关。

    仅支持简单 CSV：字段内不含逗号、引号、换行（生产导出通常满足）。
    逐字节保留行尾与未脱敏列，保证 restore 后与原文件一字节不差。
    """
    transform = (masker.mask_field if direction == "mask"
                 else masker.restore_field)
    header = fin.readline()
    if not header:
        return
    fout.write(header)
    names = header[:-1].split(",") if header.endswith("\n") else header.split(",")
    names = [n.rstrip("\r") for n in names]
    for col in names:
        if col not in masker.rules:
            raise ValueError("列 {!r} 不在列定义中".format(col))
    for lineno, line in enumerate(fin, start=2):
        if line.endswith("\r\n"):
            body, eol = line[:-2], "\r\n"
        elif line.endswith("\n"):
            body, eol = line[:-1], "\n"
        else:
            body, eol = line, ""
        if not body:
            fout.write(line)
            continue
        if '"' in body:
            raise ValueError(
                "第 {} 行含引号，仅支持无引号的简单 CSV".format(lineno))
        fields = body.split(",")
        if len(fields) != len(names):
            raise ValueError(
                "第 {} 行字段数 {} 与表头 {} 不一致".format(
                    lineno, len(fields), len(names)))
        out = [transform(col, value) for col, value in zip(names, fields)]
        fout.write(",".join(out) + eol)
