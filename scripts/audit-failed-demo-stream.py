"""Read-only incident audit using the existing parser and sequential decoder.

The dictionary-fill probes are sensitivity experiments, not a hardware model.
No compressor is called and no firmware or original manifest is written.
"""
from pathlib import Path
import builtins
import gc
import json
import struct
from unittest.mock import patch
import firmware_tokens as ft

ROOT = Path(__file__).resolve().parents[1]


def token_profile(stream):
    unwritten, overlap, zero_distance, wraps = [], 0, 0, 0
    for token in stream.tokens:
        if token.literal:
            continue
        distance = ((ft.START + token.out) - token.index) & (ft.WINDOW - 1)
        if token.out < ft.WINDOW and (distance > token.out or distance == 0):
            unwritten.append(dict(outputOffset=token.out, packedTokenOffset=token.source_offset,
                tokenHex=token.raw.hex(), index=token.index, length=token.size,
                distance=distance, sourceOutputOffset=token.out-distance))
        overlap += int(0 < distance < token.size)
        zero_distance += int(distance == 0)
        wraps += int(token.index + token.size > ft.WINDOW)
    return dict(tokens=len(stream.tokens), parsedOutputBytes=stream.output_size,
        unwrittenInitialReferences=unwritten, overlappingReferences=overlap,
        zeroDistanceReferences=zero_distance, ringBoundaryReferences=wraps,
        trailingOrphanFlag=stream.orphan_flag.hex(), unusedFlags=stream.unused_flags)


def decode_with_fill(stream, fill):
    def factory(*args, **kwargs):
        if args == (ft.WINDOW,) and not kwargs:
            return builtins.bytearray([fill]) * ft.WINDOW
        return builtins.bytearray(*args, **kwargs)
    # Reuse the exact project decoder; only its initial dictionary allocation
    # changes. No byte/token is edited and no new decoder is implemented.
    with patch.object(ft, "bytearray", factory, create=True):
        return ft.decode(stream, "sequential")


def differing_runs(left, right, base):
    rows, start = [], None
    count = 0
    for i, (a, b) in enumerate(zip(left, right)):
        if a != b:
            count += 1
            if start is None:
                start = i
        elif start is not None:
            rows.append(dict(offset=start, va=hex(base+start), bytes=i-start))
            start = None
    if start is not None:
        rows.append(dict(offset=start, va=hex(base+start), bytes=len(left)-start))
    return dict(changedBytes=count, changedRunCount=len(rows), firstRuns=rows[:24])


def main():
    sources = [
        ("official-3.1", "data/input/body-3-1-cn/firmware.bin"),
        ("official-3.2", "data/input/body-3-2-cn/firmware.bin"),
        ("failed-3.2-d1", "output/demo-packages/firmware.bin"),
        ("prior-user-reported-boot", "output/firmware-builds/experimental-exposure-bounds-3-2cn/firmware.bin"),
    ]
    expected_failed = "6c247d53e127d0a3b3442f38b438afb15d24a7bb16fe51e6bf060fc635bc2b35"
    official = ft.parse_container(ft.official_bytes())
    rows = []
    for label, name in sources:
        path = ROOT / name
        if not path.exists():
            rows.append(dict(label=label, path=name, available=False))
            continue
        raw = path.read_bytes()
        digest = ft.sha(raw)
        if label == "failed-3.2-d1":
            ft.require(digest == expected_failed, "Failed image changed")
        parts = ft.parse_container(raw)
        body = parts[0]["body"]
        row = dict(label=label, path=name, sha256=digest, bytes=len(raw),
            containerSumsPass=True, rawVectorEqualsOfficial=body[:0x1000] == official[0]["body"][:0x1000],
            secinfoWord=hex(struct.unpack_from("<I", body, 0x17a0)[0]),
            extraSectionsEqualOfficial=[parts[i]["header"] == official[i]["header"] and
                parts[i]["body"] == official[i]["body"] for i in range(1, 4)], sections={})
        for name, layout in ft.layouts(body).items():
            packed = body[layout["start"]:layout["start"]+layout["packedSize"]]
            stream = ft.parse_stream(packed)
            result = dict(layout=layout, prefixHex=packed[:32].hex(), tailHex=packed[-24:].hex(),
                packedSha256=ft.sha(packed), profile=token_profile(stream))
            if name == ".rodata" and label in ("official-3.2", "failed-3.2-d1"):
                zero = ft.decode(stream, "sequential")
                sensitivity = []
                for fill in (0x20, 0xa5):
                    filled = decode_with_fill(stream, fill)
                    sensitivity.append(dict(hypotheticalDictionaryFill=fill,
                        outputSha256=ft.sha(filled), first64Hex=filled[:64].hex(),
                        **differing_runs(zero, filled, layout["va"])))
                result["initialDictionarySensitivity"] = sensitivity
                result["zeroFillOutputSha256"] = ft.sha(zero)
                result["zeroFillFirst64Hex"] = zero[:64].hex()
            row["sections"][name] = result
            del stream
            gc.collect()
        rows.append(row)
        print(label, "initial unwritten references", {
            k: len(v["profile"]["unwrittenInitialReferences"]) for k,v in row["sections"].items()}, flush=True)
    report = dict(schema=1, date="2026-10-29", evidence="Existing token parser and decoder; file-only audit",
        firmwareModified=False, hardwareDecodeVerified=False, rootCauseConfirmed=False,
        qualification="Nonzero dictionary fills are hypothetical sensitivity probes. The hardware's actual dictionary initialization is unknown.",
        sources=rows)
    out = ROOT / "reports/failed-demo-stream-audit-2026-10-29.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    for row in rows:
        for sec in row.get("sections", {}).values():
            for probe in sec.get("initialDictionarySensitivity", []):
                print(row["label"], "fill", probe["hypotheticalDictionaryFill"],
                      "diff bytes", probe["changedBytes"], "runs", probe["changedRunCount"], flush=True)


if __name__ == "__main__":
    main()
