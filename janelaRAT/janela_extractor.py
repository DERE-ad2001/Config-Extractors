"""
  JanelaRAT static config extractor (dnfile + dncil).

  python extracto2.py <sample | directory>
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from base64 import b64decode
from hashlib import md5
from typing import Any, Iterator, Optional

import dnfile
from Crypto.Cipher import AES
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import StringToken
from dnfile import dnPE
from dnfile.mdtable import MethodDefRow

logging.getLogger("dnfile").setLevel(logging.CRITICAL)

CONFIG_PREFIX = ["nop", "nop", "nop", "nop", "ldstr", "stsfld"]
CONFIG_SUFFIX = ["ldstr", "ldsfld", "call", "stsfld", "ret"]
CONFIG_MARK = "volatile."
CONFIG_MIN_INSNS = 100

B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def decrypt(blob: str, key: str) -> str:
    """AES-CBC decrypt (MD5 key, IV prefix) — Class56.smethod_27."""
    raw = b64decode(blob)
    iv, ct = raw[:16], raw[16:]
    pt = AES.new(md5(key.encode()).digest(), AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    return pt.decode()


class _BodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe: dnPE, row: MethodDefRow) -> None:
        self.pe = pe
        self.offset = pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int) -> int:
        self.offset = offset
        return self.offset


def read_body(pe: dnPE, row: MethodDefRow) -> Optional[CilMethodBody]:
    try:
        return CilMethodBody(_BodyReader(pe, row))
    except MethodBodyFormatError:
        return None


def iter_bodies(pe: dnPE) -> Iterator[CilMethodBody]:
    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or row.Flags.mdAbstract or row.Flags.mdPinvokeImpl:
            continue
        body = read_body(pe, row)
        if body and body.instructions:
            yield body


def config_initializer_body(pe: dnPE) -> Optional[CilMethodBody]:
    for body in iter_bodies(pe):
        if is_config_initializer(body):
            return body
    return None


def is_config_initializer(body: CilMethodBody) -> bool:
    names = [ins.mnemonic for ins in body.instructions]
    if len(names) < CONFIG_MIN_INSNS:
        return False
    if names[: len(CONFIG_PREFIX)] != CONFIG_PREFIX:
        return False
    if names[-len(CONFIG_SUFFIX) :] != CONFIG_SUFFIX:
        return False
    if CONFIG_MARK not in names:
        return False
    return True


def ldstr_operand(pe: dnPE, ins) -> Optional[str]:
    if ins.mnemonic != "ldstr" or not isinstance(ins.operand, StringToken):
        return None
    try:
        entry = pe.net.user_strings.get(ins.operand.rid)
    except UnicodeDecodeError:
        return None
    if entry and entry.value is not None:
        return entry.value
    return None


def is_ciphertext(value: str) -> bool:
    if not value or len(value) < 16 or " " in value:
        return False
    if not B64_RE.match(value):
        return False
    try:
        return len(b64decode(value, validate=True)) > 16
    except Exception:
        return False


def find_aes_key(body: CilMethodBody) -> Optional[str]:
    for ins in body.instructions:
        if ins.mnemonic == "ldc.i4" and isinstance(ins.operand, int):
            if 1000 <= ins.operand <= 99999:
                return str(ins.operand)
    return None


def extract_ldstrs(pe: dnPE, body: CilMethodBody) -> list[str]:
    results: list[str] = []
    for ins in body.instructions:
        s = ldstr_operand(pe, ins)
        if s is not None:
            results.append(s)
    return results


def decrypt_strings(raw: list[str], key: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for idx, value in enumerate(raw):
        if is_ciphertext(value):
            try:
                out[str(idx)] = decrypt(value, key)
            except Exception:
                out[str(idx)] = value
        else:
            out[str(idx)] = value
    return out


def process_file(path: str) -> dict[str, Any]:
    pe = dnfile.dnPE(path)
    sample = os.path.abspath(path)
    if not pe.net:
        raise ValueError("not a .NET assembly")

    body = config_initializer_body(pe)
    if body is None:
        return {"sample": sample, "error": "config initializer not found"}

    key = find_aes_key(body)
    if not key:
        return {"sample": sample, "error": "AES key (ldc.i4) not found"}

    return {
        "sample": sample,
        "key": key,
        "strings": decrypt_strings(extract_ldstrs(pe, body), key),
    }


def list_samples(target: str) -> list[str]:
    if os.path.isfile(target):
        return [target]
    found: list[str] = []
    for root, _dirs, files in os.walk(target):
        for name in files:
            found.append(os.path.join(root, name))
    return sorted(found)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python extracto2.py <sample | directory>", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"error: not found: {target}", file=sys.stderr)
        sys.exit(1)

    samples = list_samples(target)
    if not samples:
        print(f"error: no files under {target}", file=sys.stderr)
        sys.exit(1)

    results: dict[str, dict[str, Any]] = {}
    for path in samples:
        try:
            entry = process_file(path)
        except Exception as exc:
            entry = {"sample": os.path.abspath(path), "error": str(exc)}
        results[entry["sample"]] = entry

    if len(results) == 1:
        print(json.dumps(next(iter(results.values())), indent=2, ensure_ascii=False))
    else:
        print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
