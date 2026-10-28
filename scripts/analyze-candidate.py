"""Run official Ghidra locally on explicitly qualified candidate sections.

Own glue only: existing Ghidra performs disassembly/analysis/decompilation.
All caches, preferences, projects and logs stay inside this project.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-only", action="store_true")
    parser.add_argument("--targets", type=Path)
    parser.add_argument("--output-name", default="ghidra-focus-3-2")
    parser.add_argument("--roots-only", action="store_true")
    parser.add_argument("--existing-only", action="store_true",
                        help="Do not create new functions at target addresses")
    options = parser.parse_args()
    if Path(options.output_name).name != options.output_name or options.output_name in (".", ".."):
        raise ValueError("output-name must be a single directory name")
    os.chdir(ROOT)
    tools = {row["kind"]: Path(row["directory"]) for row in json.loads(
        (ROOT / "reports/toolchain-installed.json").read_text())}
    for tool in tools.values():
        if not (tool.parent / ".verified-source.json").exists():
            raise ValueError("Tool installation has no verified-source marker")
    paths = {name: ROOT / "temp" / ("ghidra-" + name) for name in ("user", "settings", "cache", "tmp")}
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    projects = ROOT / "output/ghidra-projects"
    projects.mkdir(exist_ok=True)
    output = ROOT / "output" / options.output_name
    table = (ROOT / "output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00004096").read_bytes()
    selected = (".bss", ".noinit", ".heap", ".rtosmem", ".log_save")
    records = []
    for name in selected:
        offset = table.index(name.encode() + b"\0")
        address, size, flags, reserved = struct.unpack_from("<IIII", table, offset - 16)
        if not size or not 0xc0000000 <= address < 0xd0000000:
            raise ValueError("Unexpected RAM section")
        records.append(f"{name}\t{address:#x}\t{size:#x}")
    mapfile = ROOT / "temp/ghidra-ram-map.tsv"
    mapfile.write_text("\n".join(records) + "\n")
    candidates = ROOT / "output/reference-decoded/body-3-2-cn"
    hashes = {section: hashlib.sha256((candidates / f"{section}.mapped.candidate.bin").read_bytes()).hexdigest()
              for section in ("text", "rodata", "data")}
    expected = {row["section"].lstrip("."): row["mappedSha256"] for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"] if row["version"] == "3.2-cn"}
    if hashes != expected:
        raise ValueError("Candidate input hash changed")
    # Keep official active launch properties; override only project paths/headless limits.
    launch_options = []
    for line in (tools["ghidra"] / "support/launch.properties").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("VMARGS", "VMARGS_WINDOWS"):
            launch_options.append(value)
    command = [str(tools["java"] / "bin/java.exe"), *launch_options, "-Xmx4G", "-Djava.awt.headless=true",
               f"-Duser.home={paths['user']}", f"-Dapplication.settingsdir={paths['settings']}",
               f"-Dapplication.cachedir={paths['cache']}", f"-Dapplication.tempdir={paths['tmp']}",
               f"-Djava.io.tmpdir={paths['tmp']}", "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2",
               "-cp", str(tools["ghidra"] / "Ghidra/Framework/Utility/lib/Utility.jar"),
               "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless", str(projects),
               "m1-3-2-candidate", "-import", str(candidates / "text.mapped.candidate.bin"),
               "-processor", "ARM:LE:32:v5t", "-loader", "BinaryLoader", "-loader-baseAddr", "0x2000",
               "-scriptPath", str(ROOT / "scripts/ghidra"),
               "-preScript", "LoadM1Focus.java", str(candidates / "rodata.mapped.candidate.bin"),
               str(candidates / "data.mapped.candidate.bin"), str(mapfile),
               "-postScript", "ExportM1Focus.java", str(output),
               "-analysisTimeoutPerFile", "300", "-max-cpu", "4",
               "-log", str(ROOT / "logs/ghidra-analysis.log"),
               "-scriptlog", str(ROOT / "logs/ghidra-scripts.log")]
    export_only = options.export_only
    if export_only:
        start = command.index("-import")
        end = command.index("-postScript")
        command[start:end] = ["-process", "text.mapped.candidate.bin", "-noanalysis",
                              "-scriptPath", str(ROOT / "scripts/ghidra")]
    if options.targets:
        targets = options.targets.resolve()
        if not targets.is_relative_to(ROOT):
            raise ValueError("Target list must be inside the project")
        insert = command.index("-analysisTimeoutPerFile")
        command[insert:insert] = [str(targets), *( ["roots-only"] if options.roots_only else []),
                                 *( ["existing-only"] if options.existing_only else [])]
    elif options.roots_only:
        raise ValueError("roots-only requires an explicit target list")
    elif options.existing_only:
        raise ValueError("existing-only requires an explicit target list")
    env = os.environ.copy()
    env.update(TEMP=str(paths["tmp"]), TMP=str(paths["tmp"]))
    custom_run = options.output_name != "ghidra-focus-3-2"
    report_path = (output / "run-inputs.json") if custom_run else ROOT / "reports" / ("ghidra-export-inputs.json" if export_only else "ghidra-run-inputs.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({
        "qualification": "Candidate standard-semantics decode, not camera verified; no firmware patch.",
        "inputSha256": hashes, "uninitializedRamBlocksFromTable": records, "command": command,
    }, indent=2) + "\n")
    logfile = (output / "console.log") if custom_run else ROOT / "logs" / ("ghidra-export-console.log" if export_only else "ghidra-console.log")
    with logfile.open("w", encoding="utf-8") as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    print("Ghidra exit:", result.returncode)
    print("Log:", logfile.relative_to(ROOT))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
