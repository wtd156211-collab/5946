import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from datetime import date
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from masktool import Masker, Manifest, generate_key, load_key, process_file
from masktool import validators
from masktool.core import derive_date_offset

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLES = os.path.join(REPO, "samples")
BATCH1 = os.path.join(SAMPLES, "export-batch-1.csv")
BATCH2 = os.path.join(SAMPLES, "export-batch-2.csv")

with open(os.path.join(SAMPLES, "columns.json"), encoding="utf-8") as fh:
    COLUMNS = json.load(fh)["columns"]

KEY = load_key(generate_key())
OTHER_KEY = load_key(generate_key())

VALIDATORS = {
    "cn_name": validators.is_valid_cn_name,
    "cn_mobile": validators.is_valid_mobile,
    "email": validators.is_valid_email,
    "pan": validators.luhn_ok,
    "cn_id": validators.is_valid_id,
    "date": validators.is_valid_date,
    "decimal_cny": validators.is_valid_amount,
}


def read_rows(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


class MaskedRun(unittest.TestCase):
    """对两份样例跑一次脱敏，供多个用例复用。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masktool-test-")
        cls.manifest_path = os.path.join(cls.tmp, "manifest.sqlite3")
        cls.out1 = os.path.join(cls.tmp, "masked-1.csv")
        cls.out2 = os.path.join(cls.tmp, "masked-2.csv")
        cls.manifest = Manifest(cls.manifest_path)
        masker = Masker(KEY, cls.manifest, COLUMNS)
        for src, dst in ((BATCH1, cls.out1), (BATCH2, cls.out2)):
            with open(src, encoding="utf-8", newline="") as fin, \
                    open(dst, "w", encoding="utf-8", newline="") as fout:
                process_file(masker, fin, fout, "mask")

    @classmethod
    def tearDownClass(cls):
        cls.manifest.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)


class TestValidity(MaskedRun):
    def test_all_masked_fields_pass_validation(self):
        for path in (self.out1, self.out2):
            for row in read_rows(path):
                for col in COLUMNS:
                    if col["mask"] != "valid-fake":
                        continue
                    value = row[col["name"]]
                    check = VALIDATORS[col["type"]]
                    self.assertTrue(
                        check(value),
                        "{} 列的值 {!r} 未通过校验".format(col["name"], value))

    def test_masked_values_differ_from_originals(self):
        orig = read_rows(BATCH1)
        masked = read_rows(self.out1)
        for o, m in zip(orig, masked):
            for col in COLUMNS:
                if col["mask"] in ("valid-fake", "shift", "jitter"):
                    self.assertNotEqual(o[col["name"]], m[col["name"]],
                                        "列 {} 未被改变".format(col["name"]))


class TestConsistency(MaskedRun):
    def test_same_original_maps_same_across_files(self):
        rows1 = {r["customer_id"]: r for r in read_rows(self.out1)}
        rows2 = {r["customer_id"]: r for r in read_rows(self.out2)}
        shared = set(rows1) & set(rows2)
        self.assertTrue(shared, "样例中应有跨文件重叠的客户")
        for cid in shared:
            for field in ("name", "phone", "email", "bank_card", "id_card"):
                self.assertEqual(rows1[cid][field], rows2[cid][field],
                                 "客户 {} 的 {} 跨文件不一致".format(cid, field))

    def test_reference_keys_unchanged(self):
        for src, dst in ((BATCH1, self.out1), (BATCH2, self.out2)):
            orig, masked = read_rows(src), read_rows(dst)
            self.assertEqual([r["customer_id"] for r in orig],
                             [r["customer_id"] for r in masked])
            self.assertEqual([r["order_id"] for r in orig],
                             [r["order_id"] for r in masked])

    def test_distinct_originals_do_not_collide(self):
        masked = read_rows(self.out1) + read_rows(self.out2)
        orig = read_rows(BATCH1) + read_rows(BATCH2)
        for field in ("phone", "email", "bank_card", "id_card"):
            pairs = {}
            for o, m in zip(orig, masked):
                if m[field] in pairs and pairs[m[field]] != o[field]:
                    self.fail("不同原值 {!r} 与 {!r} 撞到同一结果 {!r}".format(
                        pairs[m[field]], o[field], m[field]))
                pairs[m[field]] = o[field]

    def test_unique_columns_stay_unique(self):
        for src, dst in ((BATCH1, self.out1), (BATCH2, self.out2)):
            orig, masked = read_rows(src), read_rows(dst)
            for field in ("phone", "email", "bank_card", "id_card"):
                before = len({r[field] for r in orig})
                after = len({r[field] for r in masked})
                self.assertEqual(before, after,
                                 "{} 列脱敏前后唯一值数量 {} != {}".format(
                                     field, before, after))


class TestDatesAndAmounts(MaskedRun):
    def test_date_order_preserved_and_constant_shift(self):
        orig = read_rows(BATCH1)
        masked = read_rows(self.out1)
        deltas = set()
        pairs = []
        for o, m in zip(orig, masked):
            d_o = date.fromisoformat(o["order_date"])
            d_m = date.fromisoformat(m["order_date"])
            deltas.add((d_m - d_o).days)
            pairs.append((d_o, d_m))
        self.assertEqual(len(deltas), 1, "所有日期应位移相同天数")
        self.assertNotEqual(deltas.pop(), 0)
        ordered = sorted(pairs)
        self.assertEqual([m for _, m in ordered],
                         sorted(m for _, m in pairs),
                         "日期先后顺序被打乱")

    def test_amount_jitter_keeps_magnitude(self):
        orig = read_rows(BATCH1)
        masked = read_rows(self.out1)
        for o, m in zip(orig, masked):
            before = Decimal(o["order_amount"])
            after = Decimal(m["order_amount"])
            self.assertTrue(validators.is_valid_amount(m["order_amount"]))
            ratio = abs(after - before) / before
            self.assertLessEqual(ratio, Decimal("0.1001"),
                                 "{} -> {} 超出 ±10%".format(before, after))


class TestRoundTrip(MaskedRun):
    def test_restore_is_byte_exact(self):
        for src, masked_path in ((BATCH1, self.out1), (BATCH2, self.out2)):
            restored = os.path.join(self.tmp, "restored.csv")
            masker = Masker(KEY, self.manifest, COLUMNS)
            with open(masked_path, encoding="utf-8", newline="") as fin, \
                    open(restored, "w", encoding="utf-8", newline="") as fout:
                process_file(masker, fin, fout, "restore")
            with open(src, "rb") as fh:
                expected = fh.read()
            with open(restored, "rb") as fh:
                self.assertEqual(fh.read(), expected,
                                 "{} 还原后与原文件不一致".format(src))


class TestKeyBehaviour(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masktool-key-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _mask_batch1(self, key):
        manifest = Manifest(os.path.join(self.tmp, generate_key() + ".db"))
        self.addCleanup(manifest.close)
        masker = Masker(key, manifest, COLUMNS)
        out = io.StringIO()
        with open(BATCH1, encoding="utf-8", newline="") as fin:
            process_file(masker, fin, out, "mask")
        out.seek(0)
        return list(csv.DictReader(out))

    def test_different_key_gives_different_mapping(self):
        rows_a = self._mask_batch1(KEY)
        rows_b = self._mask_batch1(OTHER_KEY)
        changed = 0
        total = 0
        for a, b in zip(rows_a, rows_b):
            for col in COLUMNS:
                if col["mask"] == "keep":
                    continue
                total += 1
                if a[col["name"]] != b[col["name"]]:
                    changed += 1
                # 高熵字段换密钥后必须每个都变（巧合概率可忽略）
                if col["type"] in ("cn_mobile", "email", "pan", "cn_id"):
                    self.assertNotEqual(a[col["name"]], b[col["name"]],
                                        "列 {} 换密钥后映射未变".format(col["name"]))
        # 姓名池与金额扰动档位有限，允许极少量巧合相同，但绝大多数必须变
        self.assertGreater(changed / total, 0.95,
                           "换密钥后改变比例过低：{}/{}".format(changed, total))

    def test_date_offset_depends_on_key(self):
        self.assertNotEqual(derive_date_offset(KEY), derive_date_offset(OTHER_KEY))

    def test_same_key_reproduces_mapping_in_fresh_run(self):
        first = self._mask_batch1(KEY)
        second = self._mask_batch1(KEY)
        self.assertEqual(first, second)


class TestManifestSecrecy(MaskedRun):
    def test_manifest_does_not_contain_originals(self):
        self.manifest.close()
        with open(self.manifest_path, "rb") as fh:
            blob = fh.read()
        type(self).manifest = Manifest(self.manifest_path)  # 供后续用例继续使用
        # 清单按设计会存脱敏后的值（作为反查键），假姓名取自常见姓名池，
        # 可能与真实姓名巧合相同，故只扫描高熵字段：它们若出现必是真泄露。
        originals = set()
        for path in (BATCH1, BATCH2):
            for row in read_rows(path):
                for field in ("phone", "email", "bank_card", "id_card"):
                    originals.add(row[field].encode("utf-8"))
        self.assertTrue(originals)
        for value in originals:
            self.assertNotIn(value, blob, "还原清单中出现了原值 {!r}".format(value))


class TestStreaming(unittest.TestCase):
    def test_memory_does_not_grow_with_rows(self):
        tmp = tempfile.mkdtemp(prefix="masktool-stream-")
        self.addCleanup(shutil.rmtree, tmp, True)
        big = os.path.join(tmp, "big.csv")
        n_rows = 30000
        with open(big, "w", encoding="utf-8", newline="") as fh:
            fh.write(",".join(c["name"] for c in COLUMNS) + "\n")
            for i in range(n_rows):
                cust = i % 2000  # 客户重复出现，模拟真实导出
                fh.write("C{:05d},SO{:010d},罗娜,13466431365,"
                         "order{}@shop.example.org,6296912342978539,"
                         "32010619800801738X,2026-03-08,{}.11\n".format(
                             cust, i, cust, 100 + i % 500))
        manifest = Manifest(os.path.join(tmp, "m.db"))
        self.addCleanup(manifest.close)
        masker = Masker(KEY, manifest, COLUMNS)
        tracemalloc.start()
        with open(big, encoding="utf-8", newline="") as fin, \
                open(os.path.join(tmp, "out.csv"), "w",
                     encoding="utf-8", newline="") as fout:
            process_file(masker, fin, fout, "mask")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 64 * 1024 * 1024,
                        "处理 {} 行峰值内存 {} 过高".format(n_rows, peak))


class TestCli(unittest.TestCase):
    def test_cli_mask_and_restore_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="masktool-cli-")
        self.addCleanup(shutil.rmtree, tmp, True)
        key_path = os.path.join(tmp, "key.hex")
        manifest = os.path.join(tmp, "m.db")
        masked = os.path.join(tmp, "masked.csv")
        restored = os.path.join(tmp, "restored.csv")
        env = dict(os.environ, PYTHONPATH=REPO)
        subprocess.run([sys.executable, "-m", "masktool", "genkey",
                        "--out", key_path], check=True, env=env)
        self.assertEqual(oct(os.stat(key_path).st_mode & 0o777), "0o600")
        for direction, src, dst in (("mask", BATCH1, masked),
                                    ("restore", masked, restored)):
            subprocess.run(
                [sys.executable, "-m", "masktool", direction,
                 "--key", key_path, "--columns",
                 os.path.join(SAMPLES, "columns.json"),
                 "--manifest", manifest, src, dst],
                check=True, env=env)
        with open(BATCH1, "rb") as fh:
            self.assertEqual(fh.read(), open(restored, "rb").read())


if __name__ == "__main__":
    unittest.main()
