"""命令行入口：

  python -m datamask init-key --out key.b64
  python -m datamask mask    --columns samples/columns.json --key-file key.b64 \
      --manifest out/manifest.jsonl --in samples/export-batch-1.csv --out out/masked-1.csv
  python -m datamask restore --columns samples/columns.json --key-file key.b64 \
      --manifest out/manifest.jsonl --in out/masked-1.csv --out out/restored-1.csv
"""

import argparse
import base64
import os
import sys

from .pipeline import mask_file, restore_file


def load_key(path) -> bytes:
    with open(path, "rb") as fh:
        raw = fh.read().strip()
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        key = bytes.fromhex(raw.decode("ascii"))
    if len(key) < 16:
        raise SystemExit("密钥太短：至少需要 16 字节（建议 32 字节随机数）")
    return key


def cmd_init_key(args):
    key = os.urandom(32)
    with open(args.out, "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(key).decode("ascii") + "\n")
    os.chmod(args.out, 0o600)
    print("已生成 32 字节随机密钥：%s（权限 600，请与数据分开保管）" % args.out)


def cmd_mask(args):
    key = load_key(args.key_file)
    rows = mask_file(args.columns, key, args.input, args.output, args.manifest)
    print("脱敏完成：%s -> %s（%d 行），清单追加到 %s"
          % (args.input, args.output, rows, args.manifest))


def cmd_restore(args):
    key = load_key(args.key_file)
    rows, verification = restore_file(args.columns, key, args.input, args.output, args.manifest)
    print("还原完成：%s -> %s（%d 行）" % (args.input, args.output, rows))
    if verification is None:
        print("提示：清单中找不到该脱敏文件的记录，跳过逐字节校验")
    elif verification["ok"]:
        print("逐字节校验通过：还原结果与原始文件 SHA-256 一致（%s）"
              % verification["original_sha256"][:16] + "...")
    else:
        print("校验失败：还原结果与清单记录的原始文件不一致！", file=sys.stderr)
        raise SystemExit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="datamask", description="可逆数据脱敏工具")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-key", help="生成随机密钥文件")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_init_key)

    for name, help_text in (("mask", "脱敏一个 CSV 导出"),
                            ("restore", "用密钥与清单还原一个脱敏后的 CSV")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--columns", required=True, help="列定义 JSON")
        p.add_argument("--key-file", required=True, help="密钥文件（base64 或 hex）")
        p.add_argument("--manifest", required=True, help="还原清单路径（JSONL）")
        p.add_argument("--in", dest="input", required=True)
        p.add_argument("--out", dest="output", required=True)
        p.set_defaults(func=cmd_mask if name == "mask" else cmd_restore)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
