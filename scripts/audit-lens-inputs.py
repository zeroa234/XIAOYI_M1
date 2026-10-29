"""Inventory existing lens input wrappers; use hashlib/zlib/Capstone only.

No lens patching. The 42.5mm Thumb interpretation is explicitly a hypothesis;
the zoom lens CPU and trailing checksum remain unidentified.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    manifest = json.loads((ROOT / "reports/input-manifest.json").read_text(encoding="utf-8"))
    results = []
    for name in ("lens-12-40", "lens-42-5"):
        path = ROOT / "data/input" / name / "LENS_FW.lin"
        raw = path.read_bytes()
        expected = next(r for r in manifest if r["label"] == name and r["kind"] == "entry" and r["project_path"].endswith("LENS_FW.lin"))
        if digest(raw) != expected["sha256"] or len(raw) != expected["size"]:
            raise ValueError("Original lens input changed")
        header, payload, trailer = raw[:32], raw[32:-32], raw[-32:]
        declared = struct.unpack_from("<I", header, 12)[0]
        if header[:28] != trailer[:28] or len(payload) != declared:
            raise ValueError("Observed mirrored wrapper or payload size does not match")
        checksum = struct.unpack_from("<I", trailer, 28)[0]
        comparisons = []
        for label, data in (("payload", payload), ("header-plus-payload", raw[:-32]), ("except-last-four", raw[:-4])):
            values = dict(crc32IEEE=zlib.crc32(data), adler32=zlib.adler32(data), byteSum=sum(data) & 0xffffffff)
            comparisons.append(dict(range=label, values={k: hex(v) for k, v in values.items()},
                                    matches=[k for k, v in values.items() if v == checksum]))
        result = dict(name=name, path=path.relative_to(ROOT).as_posix(), bytes=len(raw), sha256=digest(raw),
                      headerHex=header.hex(), trailerHex=trailer.hex(), headerWordsLE=[hex(v) for v in struct.unpack("<8I", header)],
                      payloadBytes=len(payload), payloadSha256=digest(payload), first28BytesMirrored=True,
                      trailingWord=hex(checksum), trailingWordMeaning="unknown", finiteChecksumComparisons=comparisons)
        if name == "lens-42-5":
            sp, reset = struct.unpack_from("<II", payload)
            entry = reset & ~1
            if not 0 <= entry < len(payload) or not reset & 1:
                raise ValueError("Thumb architecture hypothesis has no in-payload entry")
            disassembly = [dict(address=hex(i.address), raw=i.bytes.hex(), assembly=f"{i.mnemonic} {i.op_str}")
                           for i in Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(payload[entry:entry + 48], entry)]
            if not disassembly:
                raise ValueError("Thumb architecture hypothesis yields no instructions")
            result["architectureHypothesis"] = dict(interpretation="ARM Thumb with zero-based payload; not externally established",
                initialWord0=hex(sp), initialWord1=hex(reset), inferredEntry=hex(entry),
                disassembly=disassembly)
        else:
            result["architectureHypothesis"] = None
        results.append(result)
    report = dict(passed=True, inputsUnchanged=True, results=results,
                  limits=["Wrapper field meanings beyond observed lengths/mirrors are not established.",
                          "Finite checksum comparisons do not prove that no checksum exists.",
                          "No CPU or lens performance claim; these inputs are not part of the body system candidate."])
    destination = ROOT / "reports/lens-input-audit-2026-10-29.json"
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS: two original lens inputs, mirrored wrappers, payload lengths and source hashes")


if __name__ == "__main__":
    main()
