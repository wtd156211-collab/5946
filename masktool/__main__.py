"""命令行入口：

  python -m masktool genkey  --out key.hex
  python -m masktool mask    --key key.hex --columns columns.json \
      --manifest manifest.sqlite3 in.csv out.csv
  python -m masktool restore --key key.hex --columns columns.json \
      --manifest manifest.sqlite3 out.csv restored.csv
"""
import argparse
import json
import os
import sys

from .core import Masker, Manifest, generate_key, load_key, process_file


def _load_columns(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["columns"]


def _run(direction, args):
    with open(args.key, encoding="ascii") as fh:
        key = load_key(fh.read())
    columns = _load_columns(args.columns)
    with Manifest(args.manifest) as manifest:
        masker = Masker(key, manifest, columns)
        with open(args.input, encoding="utf-8", newline="") as fin, \
                open(args.output, "w", encoding="utf-8", newline="") as fout:
            process_file(masker, fin, fout, direction)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="masktool", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_key = sub.add_parser("genkey", help="生成新密钥（hex）")
    p_key.add_argument("--out", help="密钥文件路径，缺省打印到标准输出")

    for name in ("mask", "restore"):
        p = sub.add_parser(name, help="脱敏" if name == "mask" else "还原")
        p.add_argument("--key", required=True, help="密钥文件（hex）")
        p.add_argument("--columns", required=True, help="列定义 JSON")
        p.add_argument("--manifest", required=True,
                       help="还原清单 SQLite 路径（mask 时累积，restore 时读取）")
        p.add_argument("input")
        p.add_argument("output")

    args = parser.parse_args(argv)
    if args.cmd == "genkey":
        key = generate_key()
        if args.out:
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(key + "\n")
        else:
            print(key)
    else:
        _run(args.cmd, args)


if __name__ == "__main__":
    main(sys.argv[1:])
