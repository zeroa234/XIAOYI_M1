"""Wrap unmodified candidate sections with GNU as/ld for static analysis only.

Own glue selects addresses from the existing load records, invokes existing GNU
tools, and independently checks their ELF with pyelftools. No ELF encoder,
instruction rewriter, firmware repacker or camera transport is implemented.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from elftools.elf.elffile import ELFFile
import elftools


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    original = ROOT / "data/input/body-3-2-cn/firmware.bin"
    if sha(original.read_bytes()) != "92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4":
        raise ValueError("Original firmware hash changed")
    spec = importlib.util.spec_from_file_location("reference_decode", ROOT / "scripts/reference-decode.py")
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    table = (ROOT / "output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00004096").read_bytes()
    records = [r for r in json.loads((ROOT / "reports/reference-decode-results.json").read_text())["results"]
               if r["version"] == "3.2-cn"]
    sources = {}
    sections = []
    for row in records:
        name = row["section"]
        record = decoder.section_record(table, name)
        if record != row["loadRecord"]:
            raise ValueError("Stored and raw section records differ: " + name)
        source = ROOT / "output/reference-decoded/body-3-2-cn" / (name[1:] + ".mapped.candidate.bin")
        data = source.read_bytes()
        if sha(data) != row["mappedSha256"] or len(data) != record["bytes"]:
            raise ValueError("Candidate section changed: " + name)
        sources[name] = data
        sections.append({"name": name, "address": int(record["address"], 16), "size": len(data),
                         "initialized": True, "sha256": sha(data)})
    for name in (".bss", ".noinit", ".heap", ".rtosmem", ".log_save"):
        r = decoder.section_record(table, name)
        sections.append({"name": name, "address": int(r["address"], 16), "size": r["bytes"], "initialized": False})
    sections.sort(key=lambda s: s["address"])
    if any(a["address"] + a["size"] > b["address"] for a, b in zip(sections, sections[1:])):
        raise ValueError("Overlapping load records")
    output = ROOT / "output/rea-analysis-image"
    output.mkdir(exist_ok=True)
    assembly = [".syntax unified", ".arch armv5te", ".arm"]
    linker = ["OUTPUT_FORMAT(elf32-littlearm)", "OUTPUT_ARCH(arm)",
              "ENTRY(m1_analysis_entry)", "m1_analysis_entry = 0x3d6f60;",
              "PHDRS { text PT_LOAD FLAGS(5); rodata PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6);",
              "ram PT_LOAD FLAGS(6); log PT_LOAD FLAGS(6); }", "SECTIONS {"]
    for s in sections:
        name = s["name"]
        if s["initialized"]:
            flags = "ax" if name == ".text" else "aw" if name == ".data" else "a"
            assembly.extend([f'.section {name},"{flags}",%progbits',
                f'.incbin "output/reference-decoded/body-3-2-cn/{name[1:]}.mapped.candidate.bin"'])
            segment = name[1:]
            linker.append(f'  {name} {s["address"]:#x} : {{ *({name}) }} :{segment}')
        else:
            assembly.extend([f'.section {name},"aw",%nobits', f'.space {s["size"]}'])
            segment = "log" if name == ".log_save" else "ram"
            linker.append(f'  {name} {s["address"]:#x} (NOLOAD) : {{ *({name}) }} :{segment}')
    linker.extend(["  .ARM.attributes 0 : { *(.ARM.attributes) }", "}"])
    (output / "candidate.s").write_text("\n".join(assembly) + "\n")
    (output / "candidate.ld").write_text("\n".join(linker) + "\n")
    tools = "vendor/arm-binutils/usr/bin/arm-none-eabi-"
    commands = [
        [tools + "as", "-march=armv5te", "-o", "output/rea-analysis-image/candidate.o", "output/rea-analysis-image/candidate.s"],
        [tools + "ld", "--build-id=none", "-T", "output/rea-analysis-image/candidate.ld", "-o",
         "output/rea-analysis-image/m1-3-2.analysis-only.elf", "output/rea-analysis-image/candidate.o"],
        [tools + "objcopy", "--strip-all", "output/rea-analysis-image/m1-3-2.analysis-only.elf"],
    ]
    wsl_root = subprocess.check_output(
        ["wsl.exe", "-d", "Ubuntu", "--exec", "wslpath", "-a", str(ROOT)], text=True).strip()
    for command in commands:
        subprocess.run(["wsl.exe", "-d", "Ubuntu", "--cd", wsl_root, "--exec", *command], check=True)
    result = output / "m1-3-2.analysis-only.elf"
    with result.open("rb") as stream:
        elf = ELFFile(stream)
        if not elf.little_endian or elf.elfclass != 32 or elf["e_machine"] != "EM_ARM" or elf["e_entry"] != 0x3d6f60:
            raise ValueError("Unexpected ELF identity")
        if result.stat().st_size > 12_000_000:
            raise ValueError("Unexpectedly large wrapper")
        for s in sections:
            actual = elf.get_section_by_name(s["name"])
            if actual is None or actual["sh_addr"] != s["address"] or actual["sh_size"] != s["size"]:
                raise ValueError("ELF layout differs: " + s["name"])
            if s["initialized"]:
                if actual.data() != sources[s["name"]]:
                    raise ValueError("GNU tools changed section bytes: " + s["name"])
            elif actual["sh_type"] != "SHT_NOBITS":
                raise ValueError("Uninitialized section became stored data")
        segments = [{k: p[k] for k in ("p_type", "p_offset", "p_vaddr", "p_filesz", "p_memsz", "p_flags")}
                    for p in elf.iter_segments()]
        for s in sections:
            containing = [p for p in segments if p["p_type"] == "PT_LOAD" and
                          p["p_vaddr"] <= s["address"] and s["address"] + s["size"] <= p["p_vaddr"] + p["p_memsz"]]
            if len(containing) != 1:
                raise ValueError("Section lacks a unique load segment: " + s["name"])
            if s["initialized"]:
                p = containing[0]
                offset = s["address"] - p["p_vaddr"]
                stream.seek(p["p_offset"] + offset)
                if offset + s["size"] > p["p_filesz"] or stream.read(s["size"]) != sources[s["name"]]:
                    raise ValueError("Load segment bytes differ: " + s["name"])
    # The source file is checked again after all subprocesses.
    if any(sha((ROOT / "output/reference-decoded/body-3-2-cn" /
                (s["name"][1:] + ".mapped.candidate.bin")).read_bytes()) != s["sha256"]
           for s in sections if s["initialized"]):
        raise ValueError("Source bytes changed during wrapping")
    report = {"qualification": "Analysis-only ELF container, not original firmware format or a flashable image.",
              "methods": "GNU as .incbin and ld explicit VMA; independent pyelftools section/segment-byte verification.",
              "pyelftoolsVersion": elftools.__version__, "entry": "0x3d6f60",
              "entryMeaning": "Known candidate function selected for analysis, not a recovered boot entry.",
              "cpuAttribute": "ARMv5TE selected by caller; not independently established by an ELF header from the camera.",
              "abiLimitation": "EABI metadata is generated by GNU tools for this analysis wrapper; original firmware ABI is not established.",
              "ramLimitation": "NOBITS ranges reserve addresses only; their runtime contents are unknown, not measured zero values.",
              "fileBytes": result.stat().st_size, "sha256": sha(result.read_bytes()), "sections": sections, "segments": segments}
    (ROOT / "reports/analysis-elf-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: analysis-only ARM ELF; all 3 initialized sections and 5 NOBITS ranges verified; input bytes unchanged")


if __name__ == "__main__":
    main()
