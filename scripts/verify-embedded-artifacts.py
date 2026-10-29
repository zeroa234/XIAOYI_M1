"""Independently verify embedded-image exports and extracted radio windows.

Uses csv/hashlib and raw source bytes. Successful artifact checks do not prove
correct CPU profiles, true firmware boundaries, function recovery or behavior.
"""
from pathlib import Path
import csv
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t", quoting=csv.QUOTE_NONE))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def escape(value):
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def main():
    source = (ROOT / "output/reference-decoded/body-3-2-cn/rodata.mapped.candidate.bin").read_bytes()
    expected = next(r["mappedSha256"] for r in json.loads((ROOT / "reports/reference-decode-results.json").read_text())[
        "results"] if r["version"] == "3.2-cn" and r["section"] == ".rodata")
    require(sha(source) == expected, "Original reference rodata hash")
    base = ROOT / "output/embedded-subcpu-2026-10-29"
    summary = json.loads((base / "summary.json").read_text())
    inputs = json.loads((base / "run-inputs.json").read_text(encoding="utf-8"))
    verification = json.loads((base / "run-verification.json").read_text(encoding="utf-8"))
    payload = source[0x440e00 - 0x43f800:0x527c00 - 0x43f800]
    require(len(payload) == summary["payload_size"] == 0xe6e00, "Embedded payload length")
    require(sha(payload) == inputs["extracted_payload"]["sha256"], "Embedded payload source hash")
    require(verification["inputs_unchanged"] and verification["payload_unchanged"], "Embedded run modified inputs")
    functions, strings = read(base / "functions.tsv"), read(base / "strings.tsv")
    timings, failures = read(base / "decompile-timings.tsv"), read(base / "failures.tsv")
    entries = {row["entry"] for row in functions}
    require(len(entries) == len(functions) == summary["functions"], "Embedded function catalog count/uniqueness")
    require({p.stem for p in (base / "decompiled").glob("*.c")} == entries, "Embedded C file coverage")
    require(len(timings) == len(entries) and {r["entry"] for r in timings} == entries, "Embedded timing coverage")
    require(len(failures) == summary["failed"] and summary["success"] + summary["failed"] == len(entries), "Embedded failure counts")
    total, warning_files, warning_count = 0, 0, 0
    for entry in entries:
        content = (base / "decompiled" / (entry + ".c")).read_bytes()
        total += len(content)
        count = content.count(b"WARNING:")
        warning_count += count
        warning_files += bool(count)
    require(total == summary["c_bytes"], "Embedded total C bytes")
    load = int(summary["payload_base"], 16)
    require(len(strings) == summary["strings"], "Embedded string count")
    for row in strings:
        offset, length = int(row["address"], 16) - load, int(row["length"])
        require(0 <= offset and offset + length < len(payload), "Embedded string bounds")
        content = payload[offset:offset + length]
        require(payload[offset + length] == 0 and all(32 <= c <= 126 or c in (9, 10, 13) for c in content), "Embedded string bytes")
        require(escape(content.decode("ascii")) == row["text"], "Embedded string text")
    radio = json.loads((ROOT / "reports/pi-offline-radio-2026-10-29.json").read_text(encoding="utf-8"))
    extraction_results = []
    for row in radio["extractions"]:
        start, end = int(row["start"], 16), int(row["end_exclusive"], 16)
        require(0x43f800 <= start <= end <= 0x43f800 + len(source), "Radio source interval")
        name = row["file"]
        require(Path(name).name == name, "Radio filename is not a plain basename")
        raw = (ROOT / "output/embedded-radio-2026-10-29" / name).read_bytes()
        require(len(raw) == row["length"] == end - start, "Radio extraction length")
        require(raw == source[start - 0x43f800:end - 0x43f800] and sha(raw) == row["sha256"], "Radio extraction source/hash")
        extraction_results.append(dict(file=name, bytes=len(raw), sha256=sha(raw)))
    main_start, clone_start, size = 0x91b798 - 0x43f800, 0x4904d4 - 0x43f800, 607872
    a, b = source[main_start:main_start + size], source[clone_start:clone_start + size]
    differences = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    require(differences == [size - 4, size - 3, size - 2, size - 1], "Radio clone comparison")
    report = dict(artifactChecksPassed=True, sourceRoDataSha256=expected,
        embeddedSubcpu=dict(payloadSha256=sha(payload), functions=len(entries), success=summary["success"], failed=summary["failed"],
            cBytes=total, strings=len(strings), filesWithDecompilerWarnings=warning_files, decompilerWarnings=warning_count,
            unrecognizedCallTargetsAfterThumbNormalization=summary["unrecognized_call_targets"],
            thumbBitCallTargets=summary.get("thumb_bit_call_targets")),
        radioExtractions=extraction_results,
        radioClone=dict(bytesCompared=size, differingBytes=len(differences), differingOffsets=[hex(i) for i in differences],
            actualFirmwareBoundaryVerified=False),
        semanticVerification=False,
        limits=["All recognized embedded functions have an output file, including failure fallbacks; this is not full semantic recovery.",
                "Mixed ARM/Thumb and nested WLAN content can produce false functions, invalid instructions and decompiler warnings.",
                "Matching or near-matching windows prove duplication, not firmware container boundaries, load addresses or entrypoints.",
                "No hardware, camera or wireless firmware is modified by this verification."])
    out = ROOT / "reports/embedded-artifact-verification-2026-10-29.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(entries)} embedded function outputs, {len(strings)} raw strings, {len(extraction_results)} radio windows; semantic verification remains false")


if __name__ == "__main__":
    main()
