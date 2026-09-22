"""还原清单（manifest）：JSONL 格式，一行一条记录。

记录类型：
- header   ：版本、数据集、密钥指纹、列定义哈希、创建时间
- file     ：每个脱敏输出文件的行数、原始文件/脱敏文件的 SHA-256（用于还原后逐字节校验）
- fallback ：值域外异常值的加密原值（masked 值 -> 加密原值）

清单本身不泄露原值：
- fallback 里的原值用密钥派生的流密码加密（HMAC-SHA256 计数器模式），并带完整性标签；
- file 记录只存整文件哈希，不含任何字段值；
- 没有密钥，清单里读不出任何原始字段。
"""

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

from .fpe import derive_subkey

FORMAT_VERSION = 1


def key_fingerprint(master_key: bytes) -> str:
    return hashlib.sha256(master_key).hexdigest()[:16]


def _keystream(subkey: bytes, masked: str, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(
            subkey + b"mf" + masked.encode("utf-8") + counter.to_bytes(4, "big")
        ).digest()
        counter += 1
    return bytes(out[:n])


def encrypt_original(master_key: bytes, masked: str, original: str) -> dict:
    """用 masked 值作关联标识加密原值（masked 在清单内唯一，无需随机 nonce）。"""
    subkey = derive_subkey(master_key, b"manifest-enc")
    data = original.encode("utf-8")
    ks = _keystream(subkey, masked, len(data))
    ct = bytes(a ^ b for a, b in zip(data, ks))
    tag = hmac.new(subkey, b"tag" + masked.encode("utf-8") + ct, hashlib.sha256).hexdigest()
    return {"original_enc": base64.b64encode(ct).decode("ascii"), "tag": tag}


def decrypt_original(master_key: bytes, masked: str, record: dict) -> str:
    subkey = derive_subkey(master_key, b"manifest-enc")
    ct = base64.b64decode(record["original_enc"])
    tag = hmac.new(subkey, b"tag" + masked.encode("utf-8") + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, record["tag"]):
        raise ValueError("manifest record integrity check failed (wrong key or corrupted)")
    ks = _keystream(subkey, masked, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks)).decode("utf-8")


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ManifestWriter:
    """追加式写入，跨多个脱敏文件复用同一份清单。"""

    def __init__(self, path, master_key: bytes, dataset: str, columns_sha256: str):
        self.path = path
        self.key = master_key
        fresh = not os.path.exists(path) or os.path.getsize(path) == 0
        self._fh = open(path, "a", encoding="utf-8")
        if fresh:
            self._write({
                "kind": "header",
                "version": FORMAT_VERSION,
                "dataset": dataset,
                "key_fingerprint": key_fingerprint(master_key),
                "columns_sha256": columns_sha256,
                "created": datetime.now(timezone.utc).isoformat(),
            })

    def _write(self, record: dict):
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()

    def add_fallback(self, ctype: str, masked: str, original: str):
        record = {"kind": "fallback", "type": ctype, "masked": masked}
        record.update(encrypt_original(self.key, masked, original))
        self._write(record)

    def add_file(self, out_path: str, rows: int, original_sha256: str, masked_sha256: str):
        self._write({
            "kind": "file",
            "path": os.path.basename(out_path),
            "rows": rows,
            "original_sha256": original_sha256,
            "masked_sha256": masked_sha256,
        })

    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Manifest:
    """还原时读取清单：校验密钥指纹，提供 fallback 查询与文件级哈希校验。"""

    def __init__(self, path, master_key: bytes):
        self.fallbacks = {}
        self.files = []
        header_seen = False
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                kind = rec.get("kind")
                if kind == "header":
                    header_seen = True
                    if rec.get("key_fingerprint") != key_fingerprint(master_key):
                        raise ValueError("密钥指纹与清单不匹配：还原密钥不是脱敏时用的那把")
                elif kind == "fallback":
                    self.fallbacks[(rec["type"], rec["masked"])] = rec
                elif kind == "file":
                    self.files.append(rec)
        if not header_seen:
            raise ValueError("清单缺少 header 记录，文件可能损坏")

    def lookup(self, ctype: str, masked: str, master_key: bytes):
        rec = self.fallbacks.get((ctype, masked))
        if rec is None:
            return None
        return decrypt_original(master_key, masked, rec)

    def find_file(self, masked_sha256: str):
        for rec in self.files:
            if rec.get("masked_sha256") == masked_sha256:
                return rec
        return None
