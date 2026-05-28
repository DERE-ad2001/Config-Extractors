#!/usr/bin/env python3
import argparse
import sys
from base64 import b64decode
from hashlib import md5

from Crypto.Cipher import AES

KEY = "8521"


def decrypt(blob: str, key: str = KEY) -> str:
    raw = b64decode(blob)
    iv, ct = raw[:16], raw[16:]
    pt = AES.new(md5(key.encode()).digest(), AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    return pt.decode()


def main():
    p = argparse.ArgumentParser(description="Decrypt AES-CBC blobs (MD5 key, IV prefix).")
    p.add_argument("blob", nargs="+")
    p.add_argument("-k", "--key", default=KEY)
    args = p.parse_args()
    for b in args.blob:
        try:
            print(decrypt(b, args.key))
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
