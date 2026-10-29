"""Experimental demo builder: existing token splicer + pinned ff7tools compressor.

Dense PCM changes cannot generally fit the conservative 140-byte ROM slack.
This separate builder explicitly recompresses .rodata with the existing library.
It proves sequential decode with two implementations, not native hardware decode
or snapshot-copy equivalence. Never replaces the conservative builder.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import re
import struct
import sys
import time

from firmware_tokens import (ROOT, OFFICIAL_SHA, require, sha, official_bytes,
    parse_container, layouts, parse_stream, decode)
import repack

REFERENCE = ROOT / "vendor/ff7tools-reference/lzss.py"
REFERENCE_SHA = "ee3b65e055231164d29ac53a67da1dd047c2e761b932c6a3efb27e6d7f102f84"


def reference():
    require(sha(REFERENCE.read_bytes()) == REFERENCE_SHA, "Pinned compressor source changed")
    spec = importlib.util.spec_from_file_location("demo_reference_lzss", REFERENCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def container_with_body(template, body):
    parts = parse_container(template)
    header = parts[0]["header"]
    match = re.search(rb"\bSUM=(\d+)\b", header)
    value = str(sum(body) & 0xffffffff).encode("ascii")
    require(match is not None and len(value) == len(match[1]), "SUM digit width changed")
    header = header[:match.start(1)] + value + header[match.end(1):]
    return header + bytes(body) + template[256 + len(body):]


def desired_rodata(original, patches):
    body = parse_container(original)[0]["body"]
    layout = layouts(body)[".rodata"]
    packed = body[layout["start"]:layout["start"] + layout["packedSize"]]
    desired = bytearray(decode(parse_stream(packed), "sequential"))
    changes = repack.section_changes(patches, ".rodata", layout, desired)
    for offset, (_, value) in changes.items():
        desired[offset] = value
    return bytes(desired), changes


def verify(raw, patches, codec):
    original = official_bytes()
    before, after = parse_container(original), parse_container(raw)
    require(len(raw) == len(original) and len(after) == len(before) == 4, "Container shape changed")
    require(after[0]["length"] == before[0]["length"], "Main body size changed")
    for i in range(1, 4):
        require(before[i]["header"] == after[i]["header"] and before[i]["body"] == after[i]["body"], "ND1/IPL/PTBL changed")
    oldbody, body = before[0]["body"], after[0]["body"]
    old_layout, new_layout = layouts(oldbody)[".rodata"], layouts(body)[".rodata"]
    for field in old_layout:
        if field not in ("packedSize", "slack"):
            require(old_layout[field] == new_layout[field], "ROM geometry changed")
    start, length = new_layout["start"], new_layout["packedSize"]
    require(length <= old_layout["capacity"], "Recompressed rodata exceeds ROM capacity")
    packed = body[start:start + length]
    desired, changes = desired_rodata(original, patches)
    sequential = decode(parse_stream(packed), "sequential")
    independent = bytes(codec.decompress(packed))
    require(sequential == independent == desired, "Two sequential decoders disagree with explicit patch set")
    require(body[start + length:old_layout["limit"]] == oldbody[start + length:old_layout["limit"]], "ROM unused tail changed")
    # Restore only the independently checked rodata stream/table field, then use
    # the existing full conservative verifier on every remaining byte/token.
    surrogate_body = bytearray(body)
    surrogate_body[start:old_layout["limit"]] = oldbody[start:old_layout["limit"]]
    field = old_layout["sizeField"]
    surrogate_body[field:field + 4] = oldbody[field:field + 4]
    surrogate = container_with_body(raw, surrogate_body)
    conservative = repack.verify_module().verify_build(surrogate, [p for p in patches if p["section"] != ".rodata"])
    snapshot = decode(parse_stream(packed), "snapshot")
    return dict(passed=True, outputSha256=sha(raw), outputBytes=len(raw), inputSha256=OFFICIAL_SHA,
        changedRoDataPlainBytes=len(changes), rodataFullSha256=sha(desired), rodataFullBytes=len(desired),
        oldRoDataPackedBytes=old_layout["packedSize"], newRoDataPackedBytes=length,
        remainingRoDataCapacity=old_layout["capacity"] - length,
        sequentialDecodeImplementations=["project firmware_tokens", "unchanged cebix/ff7tools"],
        sequentialDecodesAgree=True, snapshotEqualsSequential=snapshot == desired,
        snapshotDifferentBytes=sum(a != b for a, b in zip(snapshot, desired)) + abs(len(snapshot) - len(desired)),
        remainingSectionsConservativeVerification=conservative,
        nativeDecodeVerified=False, cameraTested=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--patches", nargs="+", required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if not args.verify_only:
        raise SystemExit("WITHDRAWN: user reported a black-screen/no-boot incident after flashing 3.2-d1. New demo builds are disabled. --verify-only remains available for forensic checks; see reports/firmware-incident-2026-10-29.md.")
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.name) is not None, "Invalid demo build name")
    target = ROOT / "output/firmware-builds" / args.name
    patches, sources = repack.read_patches(args.patches)
    codec = reference()
    if args.verify_only:
        manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
        require(manifest["patchSources"] == sources and manifest["patches"] == patches, "Patch inputs changed since build")
        result = verify((target / "firmware.bin").read_bytes(), patches, codec)
        require(result == manifest["verification"], "On-disk verification differs from build manifest")
        print(json.dumps({k: result[k] for k in ("passed", "outputSha256", "newRoDataPackedBytes", "snapshotEqualsSequential", "nativeDecodeVerified")}, indent=2))
        return
    require(not target.exists(), "Refusing to overwrite an existing demo")
    original = official_bytes()
    audit = repack.checksum_audit()
    base, rows = repack.build_firmware(original, [p for p in patches if p["section"] != ".rodata"])
    body = bytearray(parse_container(base)[0]["body"])
    layout = layouts(body)[".rodata"]
    desired, _ = desired_rodata(original, patches)
    began = time.monotonic()
    packed = bytes(codec.compress(desired))
    seconds = time.monotonic() - began
    require(len(packed) <= layout["capacity"], f"rodata does not fit: {len(packed)} > {layout['capacity']}")
    body[layout["start"]:layout["start"] + len(packed)] = packed
    struct.pack_into("<I", body, layout["sizeField"], len(packed))
    result = container_with_body(base, body)
    verification = verify(result, patches, codec)
    manifest = dict(schema=1, name=args.name, status="experimental-offline-demo-not-camera-validated",
        strategy="official token preservation for text/data; pinned ff7tools full sequential rodata recompression",
        inputSha256=OFFICIAL_SHA, outputSha256=sha(result), outputBytes=len(result), patchSources=sources, patches=patches,
        compressorSourceSha256=REFERENCE_SHA, compressionSeconds=seconds, verification=verification, secinfo=audit,
        nativeDecodeVerified=False, cameraTested=False,
        limits=["Native hardware decompression has not been proven. Full rodata recompression changes the original token stream.",
                "Snapshot-copy equivalence is measured and is not a required invariant of this experimental builder.",
                "Exposure implementation and custom sound remain experimental until measured on the camera.",
                "Unknown secinfo word is preserved; update/boot failure may not have automatic recovery."])
    target.mkdir(parents=True)
    (target / "firmware.bin").write_bytes(result)
    (target / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(sha(official_bytes()) == OFFICIAL_SHA, "Original firmware changed")
    print(json.dumps(dict(name=args.name, sha256=sha(result), rodataPackedBytes=len(packed), remaining=layout["capacity"] - len(packed), compressionSeconds=seconds), indent=2))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
