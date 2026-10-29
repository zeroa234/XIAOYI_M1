"""Recheck the complete catalog using csv/hashlib and prior verification rules.

Project glue only: no new decoder, disassembler or firmware modifications.
Checks exported material, not complete recovery of firmware semantics.
"""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t", quoting=csv.QUOTE_NONE))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def addresses(value):
    return value.split(";") if value else []


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def escape(value):
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = (ROOT / args.output).resolve()
    require(out.is_relative_to(ROOT / "output"), "Output must be inside project output/")
    require(not out.exists(), "Refusing to overwrite previous audit")
    base = ROOT / "output/code-map"
    functions, strings = read(base / "functions.tsv"), read(base / "strings.tsv")
    summary = json.loads((base / "summary.json").read_text(encoding="utf-8"))
    fm = {row["entry"]: row for row in functions}
    sm = {row["address"]: row for row in strings}
    require(len(fm) == len(functions) == summary["functions"], "Function count/uniqueness")
    require(list(fm) == sorted(fm), "Function sort order")
    require(len(sm) == len(strings) == summary["strings"], "String count/uniqueness")
    require({p.stem for p in (base / "decompiled").glob("*.c")} == set(fm), "C file coverage")
    timings = read(base / "decompile-timings.tsv")
    failures = read(base / "failures.tsv")
    require(len(timings) == len(fm) and {t["entry"] for t in timings} == set(fm), "Timing coverage")
    require(len(failures) == summary["failed"] and summary["success"] + len(failures) == len(fm), "Failure counts")
    expected = {row["section"].lstrip("."): row["mappedSha256"] for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text(encoding="utf-8"))["results"] if row["version"] == "3.2-cn"}
    section_bytes = {}
    for section, address in (("text", 0x2000), ("rodata", 0x43f800), ("data", 0xc09b0000)):
        path = ROOT / f"output/reference-decoded/body-3-2-cn/{section}.mapped.candidate.bin"
        require(sha(path) == expected[section], "Candidate input hash: " + section)
        section_bytes[section] = (address, path.read_bytes())
    string_counts = {"rodata": 0, "data": 0}
    function_strings = {entry: set() for entry in fm}
    for s in strings:
        found = False
        for section in ("rodata", "data"):
            address, raw = section_bytes[section]
            offset, length = int(s["address"], 16) - address, int(s["length"])
            if 0 <= offset and offset + length < len(raw):
                content = raw[offset:offset + length]
                require(raw[offset + length] == 0 and all(32 <= c <= 126 or c in (9, 10, 13) for c in content), "String bytes")
                require(escape(content.decode("ascii")) == s["text"], "String text differs from raw bytes")
                string_counts[section] += 1
                found = True
                break
        require(found, "String outside mapped data")
        for entry in addresses(s["functions"]):
            require(entry in fm, "String reference to unknown function")
            function_strings[entry].add(s["address"])
    incoming = {entry: set() for entry in fm}
    unresolved_edges = []
    for f in functions:
        for target in addresses(f["callees"]):
            if target in fm:
                incoming[target].add(f["entry"])
            else:
                unresolved_edges.append((f["entry"], target))
    for f in functions:
        require(int(f["entry"], 16) <= int(f["end"], 16), "Function bounds")
        for field, count, limit in (("callers", "caller_count", 20), ("callees", "callee_count", 2**31),
                                   ("string_addresses", "string_count", 30), ("ram_globals", "ram_count", 100), ("mmio", "mmio_count", 100)):
            values = addresses(f[field])
            require(len(values) == min(int(f[count]), limit) and len(set(values)) == len(values), "Truncated count: " + f["entry"])
        require(set(addresses(f["string_addresses"])) <= function_strings[f["entry"]], "String reverse reference")
        for caller in addresses(f["callers"]):
            require(caller in fm and f["entry"] in addresses(fm[caller]["callees"]), "Call reverse reference")
        require(len(incoming[f["entry"]]) == int(f["caller_count"]), "Complete incoming call count: " + f["entry"])
        if int(f["caller_count"]) <= 20:
            require(incoming[f["entry"]] == set(addresses(f["callers"])), "Complete incoming call set: " + f["entry"])
    helpers = read(base / "inline-helpers.tsv")
    require(len(helpers) == 27 and all(h["status"] == "已核验大小，仅内存内联" for h in helpers), "Outline helper status")
    hashes, triage, total_bytes = [], [], 0
    for entry in fm:
        path = base / "decompiled" / (entry + ".c")
        raw = path.read_bytes()
        code = raw.decode("utf-8")
        total_bytes += len(raw)
        hashes.append((entry, len(raw), hashlib.sha256(raw).hexdigest()))
        # Textual index for further review; these are NOT verified defects.
        warnings = code.count("WARNING:")
        endless = len(re.findall(r"while\s*\(\s*true\s*\)", code))
        if warnings or endless:
            triage.append((entry, warnings, endless))
    require(total_bytes == summary["c_bytes"], "Total C bytes")
    slice_results = []
    for folder in ("slices", "slices-320k"):
        manifest = read(base / folder / "manifest.tsv")
        covered = []
        for m in manifest:
            group = base / folder / m["slice"]
            index = read(group / "index.tsv")
            code = (group / "code.c").read_text(encoding="utf-8")
            require(len(index) == int(m["function_count"]) and len(code.encode("utf-8")) == int(m["c_bytes"]), "Slice count/bytes")
            require(code.count("/* 函数 0x") == len(index), "Slice headers")
            expected_strings, cursor = set(), 0
            for f in index:
                entry = f["entry"]
                require(f == fm[entry], "Slice catalog mismatch")
                source = (base / "decompiled" / (entry + ".c")).read_text(encoding="utf-8")
                pos = code.find(source, cursor)
                require(pos >= 0, "Slice source missing: " + entry)
                cursor = pos + len(source)
                expected_strings.update(function_strings[entry])
                covered.append(entry)
            exported = {line.split("\t")[0] for line in (group / "strings.txt").read_text(encoding="utf-8").splitlines()[1:]}
            require(expected_strings == exported and len(exported) == int(m["string_count"]), "Slice string coverage")
        require(covered == list(fm), "Slice omissions/duplicates/order")
        slice_results.append(dict(folder=folder, slices=len(manifest), functions=len(covered)))
    verification = json.loads((base / "run-verification.json").read_text(encoding="utf-8"))
    require(verification["source_project_unchanged"], "Original export changed source project")
    for name, expected_sha in verification["source_project_sha256_after"].items():
        require(sha(ROOT / "output/ghidra-projects" / name) == expected_sha, "Current Ghidra source changed: " + name)
    out.mkdir(parents=True)
    for name, header, rows in (("function-hashes.tsv", ("entry", "bytes", "sha256"), hashes),
                               ("review-index.tsv", ("entry", "decompiler_warning_count", "textual_endless_loop_count"), triage)):
        with (out / name).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(header)
            writer.writerows(rows)
    report = dict(passed=True, functions=len(fm), decompiledBytes=total_bytes, strings=len(sm), stringsBySection=string_counts,
                  slices=slice_results, candidateHashes=expected, currentSourceProjectMatches=True,
                  functionHashIndexSha256=sha(out / "function-hashes.tsv"),
                  reviewIndexFunctions=len(triage), decompilerWarnings=sum(r[1] for r in triage),
                  textualEndlessLoops=sum(r[2] for r in triage),
                  completeIncomingCountsChecked=True, unresolvedCatalogEdges=len(unresolved_edges),
                  unresolvedCatalogTargets=sorted({target for _, target in unresolved_edges}),
                  unrecognizedCallTargets=read(base / "unrecognized-call-targets.tsv"),
                  limitations=["Checks all exported functions, not all possible executable code or semantics.",
                               "Unresolved callee targets are recorded, not assumed to be missing functions or rejected as invalid.",
                               "Textual loops and decompiler warnings are review candidates, not defects.",
                               "Candidate decode and hardware behavior remain unverified on this offline run."])
    (out / "verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
