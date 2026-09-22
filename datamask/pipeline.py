"""流式脱敏 / 还原管线：逐行读写，内存占用与行数无关。"""

import csv
import hashlib
import json

from .manifest import Manifest, ManifestWriter, sha256_file
from .transforms import FallbackNeeded, Transformer


def load_columns(path):
    with open(path, encoding="utf-8") as fh:
        spec = json.load(fh)
    return spec.get("dataset", ""), spec["columns"]


def columns_sha256(path):
    return sha256_file(path)


def _plan(columns):
    """把列定义展开成 [(index, name, mask, type)]，keep 列不参与变换。"""
    plan = []
    for i, col in enumerate(columns):
        plan.append((i, col["name"], col["mask"], col["type"]))
    return plan


def mask_rows(rows, plan, transformer, on_fallback):
    """逐行产出脱敏后的行。on_fallback(ctype, masked, original) 处理值域外异常值。"""
    for row in rows:
        out = list(row)
        for i, _name, mask, ctype in plan:
            if mask == "keep":
                continue
            value = row[i]
            try:
                if mask == "valid-fake" or mask == "shift" or mask == "jitter":
                    out[i] = transformer.mask(ctype, value)
                else:
                    raise ValueError("unknown mask rule: %r" % mask)
            except FallbackNeeded:
                fake = transformer.fallback_mask(ctype, value)
                on_fallback(ctype, fake, value)
                out[i] = fake
        yield out


def mask_file(columns_path, key, in_path, out_path, manifest_path):
    dataset, columns = load_columns(columns_path)
    transformer = Transformer(key)
    plan = _plan(columns)
    rows = 0
    with ManifestWriter(manifest_path, key, dataset, columns_sha256(columns_path)) as manifest:
        with open(in_path, newline="", encoding="utf-8") as fin, \
             open(out_path, "w", newline="", encoding="utf-8") as fout:
            reader = csv.reader(fin)
            writer = csv.writer(fout, lineterminator="\n")
            header = next(reader)
            writer.writerow(header)
            _check_header(header, plan)
            for out_row in mask_rows(reader, plan, transformer, manifest.add_fallback):
                writer.writerow(out_row)
                rows += 1
        manifest.add_file(out_path, rows, sha256_file(in_path), sha256_file(out_path))
    return rows


def restore_rows(rows, plan, transformer, manifest, key):
    for row in rows:
        out = list(row)
        for i, _name, mask, ctype in plan:
            if mask == "keep":
                continue
            value = row[i]
            original = manifest.lookup(ctype, value, key)
            if original is not None:
                out[i] = original
            else:
                out[i] = transformer.unmask(ctype, value)
        yield out


def restore_file(columns_path, key, in_path, out_path, manifest_path):
    _dataset, columns = load_columns(columns_path)
    transformer = Transformer(key)
    plan = _plan(columns)
    manifest = Manifest(manifest_path, key)
    rows = 0
    with open(in_path, newline="", encoding="utf-8") as fin, \
         open(out_path, "w", newline="", encoding="utf-8") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout, lineterminator="\n")
        header = next(reader)
        writer.writerow(header)
        _check_header(header, plan)
        for out_row in restore_rows(reader, plan, transformer, manifest, key):
            writer.writerow(out_row)
            rows += 1
    # 与清单里记录的原始文件哈希比对，验证逐字节还原
    masked_hash = sha256_file(in_path)
    file_rec = manifest.find_file(masked_hash)
    verification = None
    if file_rec is not None:
        restored_hash = sha256_file(out_path)
        verification = {
            "rows_expected": file_rec["rows"],
            "rows_restored": rows,
            "original_sha256": file_rec["original_sha256"],
            "restored_sha256": restored_hash,
            "ok": restored_hash == file_rec["original_sha256"] and rows == file_rec["rows"],
        }
    return rows, verification


def _check_header(header, plan):
    for i, name, _mask, _type in plan:
        if i >= len(header) or header[i] != name:
            raise ValueError("CSV 表头与列定义不符：第 %d 列期望 %r，实际 %r"
                             % (i, name, header[i] if i < len(header) else None))
