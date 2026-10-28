"""Offline candidate decode using an unchanged, independent existing LZSS library.

No codec is implemented here. The original firmware and upstream outputs are read
only. Full reference outputs and table-bounded analysis views are kept separately.
Neither output is a flashable image or proof of the camera's decoding semantics.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "vendor/ff7tools-reference/lzss.py"
REFERENCE_HASH = "ee3b65e055231164d29ac53a67da1dd047c2e761b932c6a3efb27e6d7f102f84"
INPUTS = {
    "3.2-cn": ("body-3-2-cn", "92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4"),
    "3.1-cn": ("body-3-1-cn", "97dfa394efc91f8643c3b1a0673be2dd96590754b29080ce60d3498ebe3d15be"),
}
SECTIONS = ((".text", "00008192"), (".rodata", "03127296"), (".data", "07251968"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def section_record(table, name):
    needle = name.encode("ascii") + b"\0"
    positions = []
    cursor = 0
    while (position := table.find(needle, cursor)) >= 0:
        # An exact name starts after a zero field, not inside '.ROM.data'.
        if position >= 16 and table[position - 1] == 0:
            positions.append(position)
        cursor = position + 1
    if len(positions) != 1:
        raise ValueError(f"Ambiguous or missing exact section name {name}: {positions}")
    position = positions[0]
    address, size, flags, reserved = struct.unpack_from("<IIII", table, position - 16)
    return {"nameOffset": position, "address": hex(address), "bytes": size, "flags": flags, "reserved": reserved}


def main():
    if sha256(REFERENCE.read_bytes()) != REFERENCE_HASH:
        raise ValueError("Reference source hash changed; review before execution")
    spec = importlib.util.spec_from_file_location("ff7_lzss_reference", REFERENCE)
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    fixtures = [
        ("8 literals", b"\xffABCDEFGH", b"ABCDEFGH"),
        ("overlapping match", b"\xffWXYZABCD\xfe\xf2\xf5" + b"Q" * 7, b"WXYZABCDABCDABCD" + b"Q" * 7),
        ("upstream counterexample under sequential semantics", bytes.fromhex("7f5758595a414243f2f4"), b"WXYZABCABCABCA"),
    ]
    for name, encoded, expected in fixtures:
        if bytes(codec.decompress(encoded)) != expected:
            raise AssertionError(f"Reference fixture failed: {name}")
    for original in (b"A", b"ABCDEFG", b"ABCDEFGH", b"WXYZABCABCWXYZ", b"ABC" * 20):
        if bytes(codec.decompress(codec.compress(original))) != original:
            raise AssertionError("Reference small-vector roundtrip failed")

    results = []
    for version, (folder, expected_hash) in INPUTS.items():
        original_path = ROOT / "data/input" / folder / "firmware.bin"
        original_hash = sha256(original_path.read_bytes())
        if original_hash != expected_hash:
            raise ValueError(f"Unexpected original firmware: {version}")
        base = ROOT / "output" / folder
        table = (base / f"m1-{version}.analysis.bin.0.00004096").read_bytes()
        destination = ROOT / "output/reference-decoded" / folder
        destination.mkdir(parents=True, exist_ok=True)
        for name, offset in SECTIONS:
            mapped = section_record(table, name)
            packed = section_record(table, ".ROM" + name)
            compressed_path = base / f"m1-{version}.analysis.bin.0.{offset}"
            container = compressed_path.read_bytes()
            if not 0 < packed["bytes"] <= len(container):
                raise ValueError("Invalid packed length in load table")
            payload = container[:packed["bytes"]]
            decoded = bytes(codec.decompress(payload))
            if len(decoded) < mapped["bytes"]:
                raise ValueError(f"Candidate output shorter than declared section: {version} {name}")
            trailer = decoded[mapped["bytes"]:]
            full_path = destination / f"{name[1:]}.full.candidate.bin"
            mapped_path = destination / f"{name[1:]}.mapped.candidate.bin"
            full_path.write_bytes(decoded)
            mapped_path.write_bytes(decoded[:mapped["bytes"]])
            prior = (base / (compressed_path.name + ".decompressed")).read_bytes()
            row = {
                "version": version, "section": name, "loadRecord": mapped, "packedRecord": packed,
                "compressedFile": str(compressed_path.relative_to(ROOT)), "payloadSha256": sha256(payload),
                "decodedBytes": len(decoded), "decodedSha256": sha256(decoded),
                "mappedBytes": mapped["bytes"], "mappedSha256": sha256(decoded[:mapped["bytes"]]),
                "trailerBytes": len(trailer), "trailerHeadHex": trailer[:32].hex(), "trailerSha256": sha256(trailer),
                "differentFromUpstreamAtSameOffsets": sum(a != b for a, b in zip(decoded, prior)),
                "fullCandidate": str(full_path.relative_to(ROOT)), "mappedCandidate": str(mapped_path.relative_to(ROOT)),
            }
            results.append(row)
            print(f"{version} {name}: packed={len(payload)} declared={mapped['bytes']} decoded={len(decoded)} trailer={len(trailer)} head={trailer[:8].hex()}")
        if sha256(original_path.read_bytes()) != original_hash:
            raise AssertionError("Input changed during candidate decode")

    report = {
        "referenceSource": "reports/reference-codec-source.json", "referenceSha256": REFERENCE_HASH,
        "fixturesPassed": len(fixtures), "smallRoundtripsPassed": 5,
        "limitations": [
            "Independent existing codec; candidate sequential-copy interpretation, not proven camera compatibility.",
            "Encoded lengths and mapped lengths come from exact names in the raw load/section table, not zero-padding heuristics.",
            "Full outputs are preserved. Mapped views explicitly retain only the declared section range; trailer sizes and hashes are recorded, not silently ignored.",
            "No repack, firmware byte changes, device commands or camera access.",
        ], "results": results,
    }
    (ROOT / "reports/reference-decode-results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
