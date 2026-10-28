"""只读核对 3.2-cn 取景曝光施加链；不是运行期内存快照。"""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

RANGES = [
    (0x365634, 0x3656a8), (0x35b35c, 0x35b384),
    (0x391fdc, 0x392040), (0x3b9254, 0x3b9260),
    (0x3b8ef8, 0x3b8fa8), (0x3b90c0, 0x3b90f8),
    (0x3ba548, 0x3ba5b0), (0x2445e8, 0x2446a8),
    (0x3655dc, 0x365634), (0x3b9158, 0x3b924c),
    (0x3bc684, 0x3bc7d4), (0x429704, 0x429770),
    (0x364434, 0x3645a8), (0x363c14, 0x363cf8),
    (0x363a88, 0x363b84), (0x361ad4, 0x361bc8),
    (0x36be00, 0x36bea0), (0x399b58, 0x399b94),
    (0x394264, 0x3942ac), (0x36e2d8, 0x36e368),
    (0x369d50, 0x369e9c), (0xf880, 0xf888),
    (0x35d254, 0x35d280), (0x85d30, 0x85d40),
    (0x87f14, 0x87f3c), (0x354c04, 0x354c30),
    (0xad85c, 0xad934), (0x362010, 0x362088),
]


def main():
    base = ROOT / "output/reference-decoded/body-3-2-cn"
    segments = [(name, va, (base / f"{name}.mapped.candidate.bin").read_bytes())
                for name, va in (("text", 0x2000), ("rodata", 0x43f800), ("data", 0xc09b0000))]
    expected = {r["section"].lstrip("."): r["mappedSha256"] for r in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"] if r["version"] == "3.2-cn"}
    hashes = {name: hashlib.sha256(buf).hexdigest() for name, _, buf in segments}
    assert hashes == expected, "输入哈希改变"
    text = segments[0][2]
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    def word(va):
        for _, start, buf in segments:
            if start <= va <= start + len(buf) - 4:
                return struct.unpack_from("<I", buf, va - start)[0]

    rows = []
    for lo, hi in RANGES:
        instructions = []
        for address in range(lo, hi, 4):
            ins = list(cs.disasm(text[address-0x2000:address-0x2000+4], address))
            if not ins:
                continue
            i = ins[0]
            row = {"va": hex(address), "bytes": i.bytes.hex(), "asm": i.mnemonic + " " + i.op_str}
            w = word(address)
            if w & 0x0f7f0000 == 0x051f0000:
                pool = address + 8 + ((w & 0xfff) if w & (1 << 23) else -(w & 0xfff))
                value = word(pool)
                row["literalPool"] = hex(pool)
                row["literalValue"] = hex(value) if value is not None else None
            instructions.append(row)
        rows.append({"start": hex(lo), "endExclusive": hex(hi), "instructions": instructions})

    lo, hi = 0x369d68, 0x369e18
    branches, pointers, adr = [], [], []
    for off in range(0, len(text)-3, 4):
        w = struct.unpack_from("<I", text, off)[0]
        address = off + 0x2000
        if w & 0x0e000000 == 0x0a000000:
            imm = w & 0xffffff
            if imm & 0x800000:
                imm -= 0x1000000
            target = address + 8 + imm * 4
            if lo <= target < hi:
                branches.append({"from": hex(address), "to": hex(target), "inside": lo <= address < hi})
        op = w & 0x0fff0000
        if op in (0x028f0000, 0x024f0000):
            rot = 2 * ((w >> 8) & 15)
            imm = w & 255
            if rot:
                imm = ((imm >> rot) | (imm << (32-rot))) & 0xffffffff
            target = address + 8 + (imm if op == 0x028f0000 else -imm)
            if lo <= target < hi:
                adr.append({"from": hex(address), "to": hex(target)})
    for name, start, buf in segments:
        for off in range(0, len(buf)-3, 4):
            w = struct.unpack_from("<I", buf, off)[0]
            if lo <= w < hi:
                pointers.append({"segment": name, "at": hex(start+off), "value": hex(w)})
    report = {"说明": "候选解码的指令核对；不证明运行期取景状态或可安全刷写。",
              "inputSha256": hashes, "ranges": rows,
              "deadCodeCandidate": {"start": hex(lo), "endExclusive": hex(hi), "bytes": hi-lo,
                                    "directBranches": branches, "alignedPointers": pointers, "adr": adr,
                                    "限制": "扫描包括内联数据，可能有伪命中；不涵盖计算跳转/未装载段。未占用此区。"}}
    (ROOT / "reports/exposure-apply-evidence-2026-10-27.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    scratch = ROOT / "temp/codex-exposure"
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "apply-chain.asm.txt").write_text("\n".join(
        f"{i['va']}: {i['bytes']} {i['asm']}" + (" ; =" + str(i["literalValue"]) if "literalValue" in i else "")
        for r in rows for i in r["instructions"]) + "\n", encoding="utf-8")
    print("已保存指令证据；代码空洞候选", hi-lo, "字节；外部直接分支",
          sum(not b["inside"] for b in branches), "；对齐指针", len(pointers), "；ADR", len(adr))


if __name__ == "__main__":
    main()
