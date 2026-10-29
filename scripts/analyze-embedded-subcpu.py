"""Analyze the @PDI embedded ARM sub-CPU image with an isolated Ghidra project.

Own glue only:
  * verify the existing reference-decoded .rodata/.data/.text hashes;
  * verify the @PDI header and the 0x42eb90 loader literals;
  * extract the payload to temp/ (original inputs remain read-only);
  * invoke the existing Ghidra 12.2/Java 25 headless launcher;
  * run the isolated PrepareEmbeddedSubcpu / ExportEmbeddedSubcpu scripts.

No network, camera, USB, remote-control, firmware patch or repack is used.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RODATA = ROOT / "output/reference-decoded/body-3-2-cn/rodata.mapped.candidate.bin"
DATA = ROOT / "output/reference-decoded/body-3-2-cn/data.mapped.candidate.bin"
TEXT = ROOT / "output/reference-decoded/body-3-2-cn/text.mapped.candidate.bin"
RODATA_BASE = 0x43F800
DATA_BASE = 0xC09B0000
TEXT_BASE = 0x2000
HEADER_VA = 0x440C00
HEADER_LEN = 0x200
PAYLOAD_VA = 0x440E00
PAYLOAD_LEN = 0xE6E00
PAYLOAD_END = 0x527C00
IMAGE_BASE = 0xDFC90000
OUT = ROOT / "output/embedded-subcpu-2026-10-29"
TEMP = ROOT / "temp/pi-embedded-subcpu"
EXPECTED_RODATA_SHA = "3b06a163647b6d986bbb5d20a44a1ef08de38517eb398a8517b2b59d51126438"
EXPECTED_PAYLOAD_SHA = "a48744ebf2e7f8c4fe895f8ddd7b4823dab82b7307acb19a185e31684579cc7a"
EXPECTED_LOADER_WORDS = {
    0x42EBD0: 0xE59F005C,  # ldr r0,[pc,#0x5c] -> 0x440c00
    0x42EBD4: 0xE59F1060,  # ldr r1,[pc,#0x60] -> 0x527c00
    0x42EBD8: 0xE0411000,  # sub r1,r1,r0
    0x42EBDC: 0xE2412C02,  # sub r2,r1,#0x200
    0x42EBE0: 0xE2801C02,  # add r1,r0,#0x200
    0x42EBE4: 0xE595000C,  # ldr r0,[r5,#0xc]
    0x42EBE8: 0xEBF57BE7,  # bl 0x18db8c
}
EXPECTED_LITERALS = {
    0x42EC34: 0x00440C00,
    0x42EC38: 0xC0A020F0,
    0x42EC3C: 0x00527C00,
}


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def read_expected_hashes() -> dict[str, str]:
    rows = json.loads((ROOT / "reports/reference-decode-results.json").read_text(encoding="utf-8"))["results"]
    return {row["section"]: row["mappedSha256"] for row in rows if row["version"] == "3.2-cn"}


def verify_inputs() -> tuple[bytes, bytes, bytes]:
    expected = read_expected_hashes()
    ro = RODATA.read_bytes()
    da = DATA.read_bytes()
    tx = TEXT.read_bytes()
    actual = {".rodata": sha_bytes(ro), ".data": sha_bytes(da), ".text": sha_bytes(tx)}
    for section, value in actual.items():
        if value != expected[section]:
            raise SystemExit(f"{section} candidate hash changed: {value} != {expected[section]}")
    if actual[".rodata"] != EXPECTED_RODATA_SHA:
        raise SystemExit("reference rodata SHA differs from the qualification constant")
    return ro, da, tx


def verify_container(ro: bytes, da: bytes, tx: bytes) -> dict:
    hoff = HEADER_VA - RODATA_BASE
    if ro[hoff:hoff + 4] != b"@PDI":
        raise SystemExit("missing @PDI magic")
    header_len = int.from_bytes(ro[hoff + 8:hoff + 12], "little")
    payload_len = int.from_bytes(ro[hoff + 12:hoff + 16], "little")
    if header_len != HEADER_LEN:
        raise SystemExit(f"unexpected @PDI header length {header_len:#x}")
    if payload_len != PAYLOAD_LEN:
        raise SystemExit(f"unexpected @PDI payload length {payload_len:#x}")
    version = ro[hoff + 16:hoff + 64].split(b"\0", 1)[0].decode("ascii", "replace")
    payload = ro[PAYLOAD_VA - RODATA_BASE:PAYLOAD_END - RODATA_BASE]
    if len(payload) != PAYLOAD_LEN:
        raise SystemExit("payload slice length mismatch")
    if sha_bytes(payload) != EXPECTED_PAYLOAD_SHA:
        raise SystemExit("payload SHA differs from the qualified extraction")
    last_nonzero = max((i for i, b in enumerate(payload) if b), default=-1)
    zero_tail = len(payload) - last_nonzero - 1
    if last_nonzero < 0:
        raise SystemExit("payload is empty")
    # The loader is in the main candidate .text. Check the actual words and literals,
    # not only the decompiled C.
    for va, expected_word in EXPECTED_LOADER_WORDS.items():
        word = struct.unpack_from("<I", tx, va - TEXT_BASE)[0]
        if word != expected_word:
            raise SystemExit(f"loader word mismatch at {va:#x}: {word:#x} != {expected_word:#x}")
    for va, expected_value in EXPECTED_LITERALS.items():
        value, = struct.unpack_from("<I", tx, va - TEXT_BASE)
        if value != expected_value:
            raise SystemExit(f"loader literal mismatch at {va:#x}: {value:#x} != {expected_value:#x}")
    # Descriptor .data@0xc0a020f0+0xc is the destination passed to memcpy.
    descriptor = {
        f"{va:08x}": struct.unpack_from("<I", da, va - DATA_BASE)[0]
        for va in (0xC0A020F0, 0xC0A020F4, 0xC0A020F8, 0xC0A020FC)
    }
    if descriptor["c0a020fc"] != IMAGE_BASE:
        raise SystemExit("descriptor destination is not 0xdfc90000")
    return {
        "magic": "@PDI",
        "header_va": f"{HEADER_VA:08x}",
        "header_bytes": HEADER_LEN,
        "header_version": version,
        "payload_va": f"{PAYLOAD_VA:08x}",
        "payload_end": f"{PAYLOAD_END:08x}",
        "payload_bytes": len(payload),
        "payload_sha256": sha_bytes(payload),
        "payload_last_nonzero_offset": f"{last_nonzero:08x}",
        "payload_zero_tail_bytes": zero_tail,
        "load_address": f"{IMAGE_BASE:08x}",
        "descriptor_words": descriptor,
        "loader_words": {f"{k:08x}": f"{v:08x}" for k, v in EXPECTED_LOADER_WORDS.items()},
        "loader_literals": {f"{k:08x}": f"{v:08x}" for k, v in EXPECTED_LITERALS.items()},
    }


def find_tool() -> tuple[Path, Path]:
    rows = json.loads((ROOT / "reports/toolchain-installed.json").read_text(encoding="utf-8"))
    tools = {row["kind"]: Path(row["directory"]) for row in rows}
    for path in tools.values():
        if not (path.parent / ".verified-source.json").exists():
            raise SystemExit("tool installation lacks verified-source marker")
    return tools["ghidra"], tools["java"]


def java_launch_options(ghidra: Path) -> list[str]:
    options = []
    for line in (ghidra / "support/launch.properties").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("VMARGS", "VMARGS_WINDOWS"):
            options.append(value)
    return options


def main() -> int:
    if OUT.exists() and any(OUT.iterdir()):
        raise SystemExit(f"output directory is not empty: {OUT}")
    TEMP.mkdir(parents=True, exist_ok=True)
    payload_path = TEMP / "payload.bin"
    ro, da, tx = verify_inputs()
    facts = verify_container(ro, da, tx)
    payload = ro[PAYLOAD_VA - RODATA_BASE:PAYLOAD_END - RODATA_BASE]
    payload_path.write_bytes(payload)
    if sha_file(payload_path) != EXPECTED_PAYLOAD_SHA:
        raise SystemExit("extracted payload hash changed")
    OUT.mkdir(parents=True, exist_ok=True)

    ghidra, java = find_tool()
    project = TEMP / f"ghidra-project-{time.time_ns()}"
    project.mkdir()
    paths = {name: TEMP / f"ghidra-{name}" for name in ("tmp", "user", "settings", "cache")}
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)

    command = [
        str(java / "bin/java.exe"), *java_launch_options(ghidra), "-Xmx2G",
        "-Djava.awt.headless=true",
        f"-Duser.home={paths['user']}",
        f"-Dapplication.settingsdir={paths['settings']}",
        f"-Dapplication.cachedir={paths['cache']}",
        f"-Dapplication.tempdir={paths['tmp']}",
        f"-Djava.io.tmpdir={paths['tmp']}",
        f"-Djava.util.prefs.userRoot={paths['settings'] / 'prefs'}",
        "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2",
        "-cp", str(ghidra / "Ghidra/Framework/Utility/lib/Utility.jar"),
        "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless",
        str(project), "embedded-subcpu",
        "-import", str(payload_path),
        "-processor", "ARM:LE:32:v5t",
        "-loader", "BinaryLoader",
        "-loader-baseAddr", f"{IMAGE_BASE:#x}",
        "-scriptPath", str(ROOT / "scripts/ghidra"),
        "-preScript", "PrepareEmbeddedSubcpu.java", f"{IMAGE_BASE:#x}", f"{PAYLOAD_LEN:#x}",
        "-postScript", "ExportEmbeddedSubcpu.java", str(OUT), f"{IMAGE_BASE:#x}", f"{PAYLOAD_LEN:#x}", "30", "0",
        "-analysisTimeoutPerFile", "180",
        "-max-cpu", "2",
        "-log", str(OUT / "ghidra.log"),
        "-scriptlog", str(OUT / "ghidra-script.log"),
    ]
    env = os.environ.copy()
    env.update(TEMP=str(paths["tmp"]), TMP=str(paths["tmp"]), TMPDIR=str(paths["tmp"]),
               PYTHONPYCACHEPREFIX=str(ROOT / "temp/python-cache"))
    run_inputs = {
        "qualification": "Candidate static analysis of the embedded @PDI ARM image; not a camera memory image, not a firmware patch.",
        "input_sha256": {
            ".rodata": sha_file(RODATA),
            ".data": sha_file(DATA),
            ".text": sha_file(TEXT),
        },
        "container": facts,
        "extracted_payload": {"path": str(payload_path.relative_to(ROOT)), "sha256": sha_file(payload_path)},
        "project": str(project.relative_to(ROOT)),
        "limits": {
            "analysis_timeout_per_file_seconds": 180,
            "decompile_timeout_per_function_seconds": 30,
            "max_cpu": 2,
            "java_xmx": "2G",
            "process_priority": "IDLE_PRIORITY_CLASS when supported by the host",
            "outline_helpers": "not applied; the 27 main-program helpers are irrelevant to this image",
        },
        "command": command,
    }
    (OUT / "run-inputs.json").write_text(json.dumps(run_inputs, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    started = time.time()
    creationflags = getattr(subprocess, "IDLE_PRIORITY_CLASS", 0x40)
    with (OUT / "console.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
                                creationflags=creationflags)
    elapsed = time.time() - started

    # Verify that the original and extracted inputs were not altered.
    input_hashes_after = {
        ".rodata": sha_file(RODATA),
        ".data": sha_file(DATA),
        ".text": sha_file(TEXT),
    }
    payload_sha_after = sha_file(payload_path)
    summary = None
    summary_path = OUT / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    decompiled_count = len(list((OUT / "decompiled").glob("*.c"))) if (OUT / "decompiled").exists() else 0
    functions_rows = 0
    functions_path = OUT / "functions.tsv"
    if functions_path.exists():
        with functions_path.open(encoding="utf-8") as stream:
            functions_rows = max(sum(1 for _ in stream) - 1, 0)
    strings_rows = 0
    strings_path = OUT / "strings.tsv"
    if strings_path.exists():
        with strings_path.open(encoding="utf-8") as stream:
            strings_rows = max(sum(1 for _ in stream) - 1, 0)
    console = (OUT / "console.log").read_text(encoding="utf-8", errors="replace") if (OUT / "console.log").exists() else ""
    script_log = (OUT / "ghidra-script.log").read_text(encoding="utf-8", errors="replace") if (OUT / "ghidra-script.log").exists() else ""
    combined = console + chr(10) + script_log
    lower = combined.lower()
    log_lines = console.splitlines()
    log_flags = {
        "analysis_timed_out": any(token in lower for token in ("analysis timed out", "timed out")),
        "script_error": "SCRIPT ERROR" in console or "unexpected image base" in console,
        "complete_marker": "COMPLETE functions=" in combined,
        "prepared_marker": "PREPARED vectors=" in combined,
        "ghidra_error_lines": sum(1 for line in log_lines if line.startswith("ERROR")),
        "arm_analyzer_errors": sum(1 for line in log_lines if "Unexpected Exception (ArmAnalyzer)" in line),
        "decompiler_warning_lines": sum(1 for line in log_lines if line.startswith("WARN  Decompiling")),
    }
    verification = {
        "qualification": "Isolated Ghidra headless run; partial analysis is reported, not silently treated as complete.",
        "exit_code": result.returncode,
        "wall_seconds": elapsed,
        "input_hashes_after": input_hashes_after,
        "inputs_unchanged": input_hashes_after == run_inputs["input_sha256"],
        "payload_sha256_after": payload_sha_after,
        "payload_unchanged": payload_sha_after == EXPECTED_PAYLOAD_SHA,
        "summary": summary,
        "functions_tsv_rows": functions_rows,
        "strings_tsv_rows": strings_rows,
        "decompiled_c_files": decompiled_count,
        "decompile_coverage_complete": summary is not None and decompiled_count == int(summary.get("success", 0)) + int(summary.get("failed", 0)),
        "log_flags": log_flags,
        "project": str(project.relative_to(ROOT)),
        "outputs": sorted(p.name for p in OUT.iterdir()),
    }
    (OUT / "run-verification.json").write_text(json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if result.returncode != 0:
        raise SystemExit(f"Ghidra headless failed with exit code {result.returncode}; see {OUT / 'console.log'}")
    if summary is None:
        raise SystemExit(f"Ghidra did not produce summary.json; see {OUT / 'console.log'}")
    if not verification["inputs_unchanged"] or not verification["payload_unchanged"]:
        raise SystemExit("input or extracted payload changed during analysis")
    if not verification["decompile_coverage_complete"]:
        raise SystemExit("decompiled C count does not match summary success+failed")
    if not log_flags["prepared_marker"]:
        raise SystemExit("PrepareEmbeddedSubcpu did not report PREPARED vectors")
    if log_flags["script_error"]:
        raise SystemExit("Ghidra reported a script error; see console.log")
    print(json.dumps({
        "summary": summary,
        "checks": {
            "inputs_unchanged": verification["inputs_unchanged"],
            "payload_unchanged": verification["payload_unchanged"],
            "decompile_coverage_complete": verification["decompile_coverage_complete"],
            "analysis_timed_out": log_flags["analysis_timed_out"],
            "script_error": log_flags["script_error"],
            "ghidra_error_lines": log_flags["ghidra_error_lines"],
            "arm_analyzer_errors": log_flags["arm_analyzer_errors"],
            "decompiler_warning_lines": log_flags["decompiler_warning_lines"],
        },
        "output": str(OUT),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
