"""基于 Feistel 网络 + cycle-walking 的格式保留加密。

对任意模数 M，encrypt/decrypt 在 [0, M) 上互为逆置换：
- 确定性：同一 (key, tweak, x) 恒得同一结果；
- 单射：不同 x 不会撞到同一结果；
- 密钥相关：换密钥得到完全不同的置换。
轮函数用 SHA-256（hashlib 为 C 实现，兼顾速度）。
"""

import hashlib
import hmac

ROUNDS = 6


def derive_subkey(master_key: bytes, purpose: bytes) -> bytes:
    return hmac.new(master_key, purpose, hashlib.sha256).digest()


class FPE:
    """对整数区间 [0, modulus) 的可逆置换。"""

    def __init__(self, subkey: bytes, tweak: bytes, modulus: int):
        if modulus < 1:
            raise ValueError("modulus must be >= 1")
        self.modulus = modulus
        self.subkey = subkey
        self.tweak = tweak
        bits = max(2, (modulus - 1).bit_length())
        bits += bits % 2
        self.half = bits // 2
        self.mask = (1 << self.half) - 1
        self._rbytes = (self.half + 7) // 8

    def _round(self, r: int, i: int) -> int:
        msg = self.tweak + bytes([i]) + r.to_bytes(self._rbytes, "big")
        return int.from_bytes(hashlib.sha256(self.subkey + msg).digest(), "big") & self.mask

    def _enc_bits(self, x: int) -> int:
        left = x >> self.half
        right = x & self.mask
        for i in range(ROUNDS):
            left, right = right, left ^ self._round(right, i)
        return (left << self.half) | right

    def _dec_bits(self, x: int) -> int:
        left = x >> self.half
        right = x & self.mask
        for i in reversed(range(ROUNDS)):
            left, right = right ^ self._round(left, i), left
        return (left << self.half) | right

    def encrypt(self, x: int) -> int:
        if not 0 <= x < self.modulus:
            raise ValueError("input out of range")
        if self.modulus == 1:
            return 0
        y = self._enc_bits(x)
        while y >= self.modulus:
            y = self._enc_bits(y)
        return y

    def decrypt(self, y: int) -> int:
        if not 0 <= y < self.modulus:
            raise ValueError("input out of range")
        if self.modulus == 1:
            return 0
        x = self._dec_bits(y)
        while x >= self.modulus:
            x = self._dec_bits(x)
        return x


def encode_text(s: str, alphabet: str, index: dict) -> int:
    n = 0
    base = len(alphabet)
    for ch in s:
        n = n * base + index[ch]
    return n


def decode_text(n: int, alphabet: str, length: int) -> str:
    base = len(alphabet)
    chars = []
    for _ in range(length):
        n, r = divmod(n, base)
        chars.append(alphabet[r])
    return "".join(reversed(chars))
