"""Compare real IPL table traversal for the official and withdrawn images.

NAND reads are supplied from files. Decoder setup/wait, timers, printing and
BSS DMA are explicitly stubbed. This traces loader arguments, not decoding.
"""
from pathlib import Path
import importlib.util
import json
import struct
import sys
from firmware_tokens import parse_container, layouts, load_records, official_bytes, sha, require

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("incident_ipl", ROOT / "scripts/check-native-ipl-load.py")
ipl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ipl)
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_PC


def trace(body, ipl_bytes, ptbl):
    m = ipl.Machine(ipl_bytes)
    m.uc.mem_write(ipl.PTBL, ptbl)
    device = bytearray(0x2c)
    struct.pack_into("<I", device, 0x20, ipl.BASE + 0x832c)
    m.uc.mem_write(ipl.DEVICE, bytes(device))
    m.uc.mem_write(ipl.BASE + 0x111a0, struct.pack("<I", ipl.BASE + 0x4bd8))
    reads, configs = [], []
    stubs = {0x832c: "File-backed NAND read", 0x702c: "Suppress print",
        0x6ab4: "Timer", 0x6b28: "Timer", 0x6e08: "Timer", 0x7b64: "Skip BSS DMA",
        0x107ac: "Record decoder configuration arguments; no decode",
        0x108d0: "Skip hardware wait; no completion or output claim"}

    def code(cpu, address, size, unused):
        off = address - ipl.BASE
        if off == 0x832c:
            sector, count, dest = (cpu.reg_read(r) for r in ipl.REGS[:3])
            start = (sector - 0x10200) * 512
            require(start >= 0 and start + count * 512 <= len(body), "NAND read exceeds supplied body")
            cpu.mem_write(dest, body[start:start + count * 512])
            reads.append(dict(sector=sector, count=count, bodyOffset=start, destination=dest))
            m.ret(0)
        elif off == 0x107ac:
            configs.append([cpu.reg_read(r) for r in ipl.REGS])
            m.ret(0)
        elif off in stubs:
            m.ret(0)

    m.uc.hook_add(UC_HOOK_CODE, code)
    result = m.call(0x7ff8, (ipl.PTBL, 0x10000012, ipl.DEVICE), count=2000000)
    require(m.uc.reg_read(UC_ARM_REG_PC) == ipl.RETURN and result == 0, "Loader trace did not return")
    require(len(configs) == 3, "Expected three decoder configuration calls")
    return dict(callStubs={hex(k): v for k,v in stubs.items()}, nandReads=reads,
        decoderArguments=configs, returned=result, actualHardwareDecoded=False)


def main():
    original_raw = official_bytes()
    path = ROOT / "output/demo-packages/firmware.bin"
    failed_raw = path.read_bytes()
    require(sha(failed_raw) == "6c247d53e127d0a3b3442f38b438afb15d24a7bb16fe51e6bf060fc635bc2b35", "Failed image changed")
    original, failed = parse_container(original_raw), parse_container(failed_raw)
    require(len(original) == len(failed) == 4, "Unexpected container count")
    for a,b in zip(original[1:], failed[1:]):
        require(a["header"] == b["header"] and a["body"] == b["body"], "ND1/IPL/PTBL changed")
    rows = []
    for label, parts in (("official", original), ("failed", failed)):
        body = parts[0]["body"]
        run = trace(body, parts[2]["body"], parts[3]["body"])
        checks = []
        for (name, layout), args in zip(layouts(body).items(), run["decoderArguments"]):
            related = [r for r in run["nandReads"] if
                r["bodyOffset"] >= layout["start"] and
                r["bodyOffset"] < layout["start"] + layout["packedSize"]]
            require(len(related) == 2, "Unexpected split NAND reads")
            read_start = related[0]["bodyOffset"]
            read_end = related[-1]["bodyOffset"] + related[-1]["count"] * 512
            require(read_start == layout["start"] and read_end >= read_start + layout["packedSize"], "Read truncates compressed stream")
            require(args[3] == layout["plainSize"], "Decoder length is not target plaintext size")
            require(all(v % 8 == 0 for v in args[1:]), "Decoder address/length alignment changed")
            checks.append(dict(section=name, packedBytes=layout["packedSize"],
                readBytes=read_end-read_start, readExcessBytes=read_end-read_start-layout["packedSize"],
                decoderArgs=[hex(x) for x in args], coversPackedStream=True))
        rows.append(dict(label=label, trace=run, segmentChecks=checks))
    require(rows[0]["trace"]["decoderArguments"] == rows[1]["trace"]["decoderArguments"], "Decoder arguments changed")
    before, after = load_records(original[0]["body"]), load_records(failed[0]["body"])
    changes = []
    for name, row in before.items():
        for key, value in row.items():
            if after[name][key] != value:
                require(name in (".ROM.text", ".ROM.rodata") and key == "size", "Unexpected table change")
                changes.append(dict(record=name, field=key, old=value, new=after[name][key]))
    report = dict(date="2026-10-29", failedSha256=sha(failed_raw), containerChecksPassed=True,
        vectorBlockUnchanged=original[0]["body"][:0x1000] == failed[0]["body"][:0x1000],
        tableChanges=changes, unchangedNd1IplPtbl=True, decoderArgumentsUnchanged=True,
        traces=rows, hardwareDecodeVerified=False, rootCauseConfirmed=False,
        qualification="Stubbed NAND source and decoder setup/wait; demonstrates table traversal, arguments and input coverage only, not NAND integrity or hardware decompression.")
    (ROOT / "reports/failed-demo-loader-audit-2026-10-29.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print("PASS: original IPL traversal uses unchanged decoder arguments; all three packed streams are fully covered by file-backed reads. Actual hardware decode remains unverified.")


if __name__ == "__main__":
    main()
