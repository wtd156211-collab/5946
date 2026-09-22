import csv
import json
import os
import re
import tempfile
import unittest
from datetime import date
from decimal import Decimal

from datamask.fpe import FPE, derive_subkey
from datamask.manifest import Manifest, ManifestWriter, sha256_file
from datamask.pipeline import load_columns, mask_file, mask_rows, restore_file, _plan
from datamask.transforms import Transformer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLUMNS = os.path.join(ROOT, "samples", "columns.json")
BATCH1 = os.path.join(ROOT, "samples", "export-batch-1.csv")
BATCH2 = os.path.join(ROOT, "samples", "export-batch-2.csv")

KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))

MOBILE_RE = re.compile(r"1[3-9]\d{9}\Z")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\Z")
AMOUNT_RE = re.compile(r"-?\d+\.\d{2}\Z")
ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
ID_CHECK_CHARS = "10X98765432"


def luhn_ok(s):
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def id_ok(s):
    if not re.fullmatch(r"\d{17}[\dX]", s):
        return False
    if ID_CHECK_CHARS[sum(int(a) * w for a, w in zip(s[:17], ID_WEIGHTS)) % 11] != s[17]:
        return False
    b = s[6:14]
    try:
        date(int(b[:4]), int(b[4:6]), int(b[6:8]))
    except ValueError:
        return False
    return True


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


class MaskedFilesMixin(unittest.TestCase):
    """脱敏两份样例并还原，供多个测试复用。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.tmp.name
        cls.key_path = os.path.join(d, "key.b64")
        import base64
        with open(cls.key_path, "w") as fh:
            fh.write(base64.b64encode(KEY_A).decode() + "\n")
        cls.manifest = os.path.join(d, "manifest.jsonl")
        cls.m1 = os.path.join(d, "m1.csv")
        cls.m2 = os.path.join(d, "m2.csv")
        cls.r1 = os.path.join(d, "r1.csv")
        cls.r2 = os.path.join(d, "r2.csv")
        mask_file(COLUMNS, KEY_A, BATCH1, cls.m1, cls.manifest)
        mask_file(COLUMNS, KEY_A, BATCH2, cls.m2, cls.manifest)
        restore_file(COLUMNS, KEY_A, cls.m1, cls.r1, cls.manifest)
        restore_file(COLUMNS, KEY_A, cls.m2, cls.r2, cls.manifest)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


class TestValidity(MaskedFilesMixin):
    """脱敏后的字段必须仍是合法值。"""

    def check_rows(self, rows):
        for row in rows:
            self.assertRegex(row["phone"], MOBILE_RE)
            self.assertTrue(luhn_ok(row["bank_card"]), row["bank_card"])
            self.assertTrue(id_ok(row["id_card"]), row["id_card"])
            self.assertRegex(row["email"], EMAIL_RE)
            self.assertRegex(row["name"], r"[一-鿿]{2,4}\Z")
            y, m, d = map(int, row["order_date"].split("-"))
            date(y, m, d)  # 真实存在的日期，非法会抛异常
            self.assertRegex(row["order_amount"], AMOUNT_RE)

    def test_batch1_valid(self):
        self.check_rows(read_rows(self.m1))

    def test_batch2_valid(self):
        self.check_rows(read_rows(self.m2))

    def test_amount_magnitude_preserved(self):
        """金额量级不变（分位数位数一致），扰动幅度有限。"""
        orig = read_rows(BATCH1) + read_rows(BATCH2)
        masked = read_rows(self.m1) + read_rows(self.m2)
        for o, m in zip(orig, masked):
            oc = int(Decimal(o["order_amount"]) * 100)
            mc = int(Decimal(m["order_amount"]) * 100)
            if oc == 0:
                self.assertEqual(mc, 0)
            else:
                self.assertEqual(len(str(oc)), len(str(mc)))
                self.assertLessEqual(abs(mc - oc), max(1, oc // 10 + 1))


class TestDeterminismAndInjectivity(MaskedFilesMixin):
    def test_same_value_same_masked_across_files(self):
        """同一客户在两批文件里的所有字段映射结果一致。"""
        b1 = {r["customer_id"]: r for r in read_rows(BATCH1)}
        b2 = {r["customer_id"]: r for r in read_rows(BATCH2)}
        m1 = {r["customer_id"]: r for r in read_rows(self.m1)}
        m2 = {r["customer_id"]: r for r in read_rows(self.m2)}
        shared = set(b1) & set(b2)
        self.assertTrue(shared, "样例里应有跨文件重叠的客户")
        for cid in shared:
            for col in ("name", "phone", "email", "bank_card", "id_card"):
                if b1[cid][col] == b2[cid][col]:
                    self.assertEqual(m1[cid][col], m2[cid][col],
                                     "%s 的 %s 跨文件映射不一致" % (cid, col))

    def test_distinct_values_no_collision(self):
        """不同原值不得撞到同一结果（对账不能多出重复）。"""
        rows = read_rows(self.m1) + read_rows(self.m2)
        orig = read_rows(BATCH1) + read_rows(BATCH2)
        for col in ("phone", "email", "bank_card", "id_card"):
            o = [r[col] for r in orig]
            m = [r[col] for r in rows]
            self.assertEqual(len(set(o)), len(set(m)), col)

    def test_unique_column_stays_unique(self):
        rows = read_rows(self.m1)
        phones = [r["phone"] for r in rows]
        self.assertEqual(len(phones), len(set(phones)))

    def test_reference_keys_untouched(self):
        """keep 列原样保留，两文件间的引用关系不断。"""
        for src, masked in ((BATCH1, self.m1), (BATCH2, self.m2)):
            for o, m in zip(read_rows(src), read_rows(masked)):
                self.assertEqual(o["customer_id"], m["customer_id"])
                self.assertEqual(o["order_id"], m["order_id"])

    def test_date_order_preserved(self):
        orig = sorted(r["order_date"] for r in read_rows(BATCH1))
        by_orig = {}
        for o, m in zip(read_rows(BATCH1), read_rows(self.m1)):
            by_orig[o["order_date"]] = m["order_date"]
        masked_sorted = [by_orig[d] for d in orig]
        self.assertEqual(masked_sorted, sorted(masked_sorted))
        self.assertNotEqual(orig, masked_sorted)  # 确实发生了位移


class TestRoundTrip(MaskedFilesMixin):
    def test_byte_identical_restore(self):
        self.assertEqual(sha256_file(BATCH1), sha256_file(self.r1))
        self.assertEqual(sha256_file(BATCH2), sha256_file(self.r2))

    def test_manifest_verification_ok(self):
        rows, verification = restore_file(COLUMNS, KEY_A, self.m1, self.r1, self.manifest)
        self.assertIsNotNone(verification)
        self.assertTrue(verification["ok"])


class TestKeyDependence(unittest.TestCase):
    VALUES = {
        "cn_name": "罗娜",
        "cn_mobile": "13466431365",
        "email": "order8678@shop.example.org",
        "pan": "6296912342978539",
        "cn_id": "32010619800801738X",
        "date": "2026-03-08",
        "decimal_cny": "4486.11",
    }

    def test_key_change_changes_every_type(self):
        """换一把密钥，同一原值的映射结果必须变（不是固定偏移）。"""
        ta, tb = Transformer(KEY_A), Transformer(KEY_B)
        for ctype, value in self.VALUES.items():
            self.assertNotEqual(ta.mask(ctype, value), tb.mask(ctype, value), ctype)

    def test_deterministic_per_key(self):
        t1, t2 = Transformer(KEY_A), Transformer(KEY_A)
        for ctype, value in self.VALUES.items():
            self.assertEqual(t1.mask(ctype, value), t2.mask(ctype, value), ctype)

    def test_roundtrip_per_type(self):
        t = Transformer(KEY_A)
        for ctype, value in self.VALUES.items():
            self.assertEqual(t.unmask(ctype, t.mask(ctype, value)), value, ctype)

    def test_date_shift_nonzero_and_bounded(self):
        t = Transformer(KEY_A)
        self.assertNotEqual(t.date_shift, 0)
        self.assertLessEqual(abs(t.date_shift), 365)


class TestFPE(unittest.TestCase):
    def test_bijection_small_modulus(self):
        key = derive_subkey(KEY_A, b"test")
        for modulus in (1, 2, 7, 100, 1000, 20992, 10**6):
            fpe = FPE(key, b"t", modulus)
            mapped = [fpe.encrypt(x) for x in range(modulus)]
            self.assertEqual(sorted(mapped), list(range(modulus)), modulus)
            for x, y in enumerate(mapped):
                self.assertEqual(fpe.decrypt(y), x)

    def test_large_modulus_sample(self):
        fpe = FPE(derive_subkey(KEY_A, b"test"), b"t", 7 * 10**9)
        seen = set()
        for x in range(0, 7 * 10**9, 10**9):
            y = fpe.encrypt(x)
            self.assertNotIn(y, seen)
            seen.add(y)
            self.assertEqual(fpe.decrypt(y), x)


class TestFallbackAndManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_out_of_domain_value_roundtrip(self):
        """值域外异常值走清单兜底，还原后逐字节一致。"""
        src = os.path.join(self.dir, "weird.csv")
        with open(BATCH1, encoding="utf-8") as fh:
            lines = fh.readlines()
        parts = lines[1].rstrip("\n").split(",")
        parts[2] = "Alice"          # 非 CJK 姓名
        parts[8] = "12.345"         # 超过两位小数的金额
        lines[1] = ",".join(parts) + "\n"
        with open(src, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        masked = os.path.join(self.dir, "masked.csv")
        restored = os.path.join(self.dir, "restored.csv")
        manifest = os.path.join(self.dir, "manifest.jsonl")
        mask_file(COLUMNS, KEY_A, src, masked, manifest)
        rows, verification = restore_file(COLUMNS, KEY_A, masked, restored, manifest)
        self.assertEqual(sha256_file(src), sha256_file(restored))
        # 清单里应当有 fallback 记录
        with open(manifest, encoding="utf-8") as fh:
            kinds = [json.loads(l)["kind"] for l in fh]
        self.assertIn("fallback", kinds)

    def test_manifest_does_not_leak_originals(self):
        """清单文件里搜不到任何原始字段值。"""
        masked = os.path.join(self.dir, "masked.csv")
        manifest = os.path.join(self.dir, "manifest.jsonl")
        mask_file(COLUMNS, KEY_A, BATCH1, masked, manifest)
        with open(manifest, "rb") as fh:
            blob = fh.read().decode("utf-8")
        for row in read_rows(BATCH1):
            for col in ("name", "phone", "email", "bank_card", "id_card"):
                self.assertNotIn(row[col], blob)

    def test_wrong_key_rejected(self):
        masked = os.path.join(self.dir, "masked.csv")
        manifest = os.path.join(self.dir, "manifest.jsonl")
        mask_file(COLUMNS, KEY_A, BATCH1, masked, manifest)
        with self.assertRaises(ValueError):
            restore_file(COLUMNS, KEY_B, masked,
                         os.path.join(self.dir, "out.csv"), manifest)


class TestStreaming(unittest.TestCase):
    def test_mask_rows_is_lazy(self):
        """逐行处理：传入生成器，不物化整个输入。"""
        _dataset, columns = load_columns(COLUMNS)
        plan = _plan(columns)
        transformer = Transformer(KEY_A)
        consumed = []

        def gen():
            for i in range(5):
                consumed.append(i)
                yield ["C1", "SO1", "罗娜", "13466431365",
                       "a@b.co", "6296912342978539",
                       "32010619800801738X", "2026-03-08", "4486.11"]

        it = mask_rows(gen(), plan, transformer, lambda *a: None)
        self.assertEqual(consumed, [])
        next(it)
        self.assertEqual(consumed, [0])  # 只消费了一行

    def test_cache_bounded(self):
        t = Transformer(KEY_A)
        self.assertLessEqual(t.CACHE_LIMIT, 1_000_000)


if __name__ == "__main__":
    unittest.main()
