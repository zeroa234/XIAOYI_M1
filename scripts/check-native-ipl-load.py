"""执行官方 IPL 的装载、硬件解码配置和错误传播路径。

不模拟解码硬件，不向模拟 RAM 注入软件解码结果。NAND 桩仅在明确列出
的用例中提供官方段体；计时器/打印桩不决定解码结果。输出均为离线证据。
"""
from __future__ import annotations

import hashlib
import argparse
import json
import os
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
TMP = ROOT / "temp/codex-tmp"
TMP.mkdir(parents=True, exist_ok=True)
os.environ["TMP"] = os.environ["TEMP"] = str(TMP)
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_CPU_ARM_926, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_CPSR)

INPUT = ROOT / "data/input/body-3-2-cn/firmware.bin"
INPUT_HASH = "92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4"
IPL_HASH = "3513946d8068f6a03706bc5ec142fe45122773b2163ef688806afa7e03012dc4"
BASE = 0x22ffc000
RAM = 0x24000000
STACK = RAM + 0x1f000
RETURN = RAM + 0x1ff00
PTBL = RAM + 0x1000
DEVICE = RAM + 0x3000
SOURCE = 0x43000000
DEST = 0x45000000
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inputs():
    raw = INPUT.read_bytes()
    assert sha(raw) == INPUT_HASH, "官方输入哈希不符"
    sections, offset = [], 0
    while offset < len(raw):
        header = raw[offset:offset + 256]
        length = int(re.search(rb"LENGTH=(\d+)", header)[1])
        payload = raw[offset + 256:offset + 256 + length]
        assert len(payload) == length
        assert sum(payload) == int(re.search(rb"SUM=(\d+)", header)[1])
        sections.append(payload)
        offset += 256 + length
    assert offset == len(raw) and len(sections) == 4
    assert sha(sections[2]) == IPL_HASH
    return sections


def records(body):
    """只读官方 .secinfo 链：next/name/address/size/flags/关联记录。"""
    result, seen, at = {}, set(), 0x1000
    while at:
        assert at not in seen and 0x1000 <= at < 0x17a0
        seen.add(at)
        nxt, name, address, size, flags, associated = struct.unpack_from("<6I", body, at)
        end = body.index(0, name)
        label = body[name:end].decode("ascii")
        result[label] = dict(recordOffset=at, next=nxt, nameOffset=name,
                             address=address, size=size, flags=flags, associated=associated)
        at = nxt
    return result


class Machine:
    def __init__(self, ipl):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_926)
        self.uc.mem_map(BASE, 0x20000)
        self.uc.mem_write(BASE, ipl)
        self.uc.mem_map(RAM, 0x20000)
        self.uc.mem_map(0x30000000, 0x200000)
        self.uc.mem_map(0x40000000, 0xb00000)
        self.uc.mem_map(SOURCE, 0x800000)
        self.uc.mem_map(DEST, 0x800000)
        self.uc.mem_map(0xc09b0000, 0x60000)
        self.uc.mem_map(0xc1400000, 0x200000)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x13)
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)

    def call(self, entry, args=(), count=100000):
        for reg, value in zip(REGS, args):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        self.uc.emu_start(BASE + entry, RETURN, count=count)
        return self.uc.reg_read(UC_ARM_REG_R0)

    def ret(self, result=0):
        self.uc.reg_write(UC_ARM_REG_R0, result & 0xffffffff)
        self.uc.reg_write(UC_ARM_REG_PC, self.uc.reg_read(UC_ARM_REG_LR))

    def word(self, address):
        return struct.unpack("<I", self.uc.mem_read(address, 4))[0]


def descriptor_case(ipl, ptbl):
    m = Machine(ipl)
    m.uc.mem_write(PTBL, ptbl)
    result = m.call(0x6740, (RAM, PTBL, 0x10000012))
    assert result == 0 and m.uc.reg_read(UC_ARM_REG_PC) == RETURN
    values = struct.unpack("<6I", m.uc.mem_read(RAM, 24))
    assert values == (0x10000012, 0, 1, 0, 0x10200, 0x23600)
    return dict(entry="0x6740", result=result, descriptor=[hex(v) for v in values],
                evidence="Unicorn 原指令；官方 PTBL，无调用桩")


def hardware_case(ipl, packed, expected):
    m = Machine(ipl)
    m.uc.mem_write(SOURCE, packed)
    guard = bytes([0xa5]) * len(expected)
    m.uc.mem_write(DEST, guard)
    writes = []

    def write(uc, access, address, size, value, unused):
        writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC) - BASE),
                           address=hex(address), bytes=size, value=hex(value)))
    m.uc.hook_add(UC_HOOK_MEM_WRITE, write, begin=0x30000000, end=0x301fffff)
    m.call(0x10714)
    assert m.uc.reg_read(UC_ARM_REG_PC) == RETURN
    m.call(0x107ac, (8, SOURCE, DEST, len(expected)))
    assert m.uc.reg_read(UC_ARM_REG_PC) == RETURN
    assert m.uc.mem_read(SOURCE, len(packed)) == packed
    assert m.uc.mem_read(DEST, len(expected)) == guard
    assert m.word(0x3014031c) & 0xffff == 0xfee
    polls = []

    def read(uc, access, address, size, value, unused):
        if len(polls) < 3:
            polls.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC) - BASE),
                              address=hex(address), bytes=size))
    m.uc.hook_add(UC_HOOK_MEM_READ, read, begin=0x30140280, end=0x30140283)
    m.call(0x108d0, count=1000)
    pc = m.uc.reg_read(UC_ARM_REG_PC) - BASE
    assert pc in (0x108d8, 0x108dc, 0x108e0)
    after = bytes(m.uc.mem_read(DEST, len(expected)))
    assert after == guard
    return dict(entry="0x10714 → 0x107ac → 0x108d0", callStubs=[],
                packedBytes=len(packed), packedSha256=sha(packed),
                expectedBytes=len(expected), expectedSha256=sha(expected),
                destinationUnchanged=True, decodedBytesProduced=0,
                nativeDecodeVerified=False, stopPc=hex(pc), instructionLimit=1000,
                waitReads=polls, mmioWrites=writes,
                qualification="仅执行硬件配置/等待；未实现 SoC 解码器，未伪造完成位/解码输出")


def load_until_wait(ipl, body, ptbl):
    """真实 LoadData/链表解析，只替代 NAND 输入、打印和计时外设。"""
    m = Machine(ipl)
    m.uc.mem_write(PTBL, ptbl)
    device = bytearray(0x2c)
    struct.pack_into("<I", device, 0x20, BASE + 0x832c)
    m.uc.mem_write(DEVICE, bytes(device))
    m.uc.mem_write(BASE + 0x111a0, struct.pack("<I", BASE + 0x4bd8))
    reads, configs, prints = [], [], []
    stubs = [0x702c, 0x6ab4, 0x6b28, 0x6e08, 0x7b64, 0x832c]
    # 0x6e08 只写用于速度打印的计数器，本例停在解码等待，不读取速度。
    def code(uc, address, size, unused):
        off = address - BASE
        if off == 0x832c:
            sector, count, dest = (uc.reg_read(r) for r in REGS[:3])
            start = (sector - 0x10200) * 512
            assert 0 <= start < len(body)
            buf = body[start:start + count * 512]
            assert len(buf) == count * 512
            uc.mem_write(dest, buf)
            reads.append(dict(sector=hex(sector), count=count, destination=hex(dest), bodyOffset=hex(start)))
            m.ret()
        elif off == 0x702c:
            p = uc.reg_read(UC_ARM_REG_R0)
            prints.append(bytes(uc.mem_read(p, 128)).split(b"\0")[0].decode("ascii"))
            m.ret()
        elif off in (0x6ab4, 0x6b28, 0x6e08, 0x7b64):
            m.ret()
        elif off == 0x107ac:
            configs.append([hex(uc.reg_read(r)) for r in REGS])
        elif off == 0x108d8:
            uc.emu_stop()
    m.uc.hook_add(UC_HOOK_CODE, code)
    m.call(0x7ff8, (PTBL, 0x10000012, DEVICE), count=100000)
    assert m.uc.reg_read(UC_ARM_REG_PC) == BASE + 0x108d8
    assert configs == [["0x8", "0x43000000", "0x40002000", "0x43d438"]]
    assert reads[0] == dict(sector="0x10200", count=10, destination="0x40000000", bodyOffset="0x0")
    return dict(entry="0x7ff8", callStubs=[hex(x) for x in stubs],
                nandReads=reads, decoderArguments=configs, prints=prints,
                stopPc="0x108d8", nativeTableParsingVerified=True,
                qualification="NAND 以 PTBL FIRM 起始为基准提供官方段体；跳过独立 BSS 清零 DMA 0x7b64；不证明 NAND 物理映射/实际解码")


def decode_error_case(ipl, ptbl, injected_error=False):
    """核实错误分支是否向 0x415c 传播失败，不伪称该用例进行了解码。"""
    m = Machine(ipl)
    m.uc.mem_write(PTBL, ptbl)
    device = bytearray(0x2c)
    struct.pack_into("<I", device, 0x20, BASE + 0x832c)
    m.uc.mem_write(DEVICE, bytes(device))
    m.uc.mem_write(BASE + 0x111a0, struct.pack("<I", BASE + 0x4bd8))
    prints, stubs = [], [0x702c, 0x6ab4, 0x6b28, 0x6e08, 0x6c7c, 0x832c]
    if injected_error:
        stubs.append(0x7c48)
    def code(uc, address, size, unused):
        off = address - BASE
        if off == 0x702c:
            p = uc.reg_read(UC_ARM_REG_R0)
            prints.append(bytes(uc.mem_read(p, 128)).split(b"\0")[0].decode("ascii"))
            m.ret()
        elif off in (0x6ab4, 0x6b28, 0x6e08, 0x6c7c):
            m.ret()
        elif off == 0x832c:
            # 合成无效首块：缺少 .picbase，首项 next 指针不在可映射区间。
            # 完全全零链表会形成自环，不能把它误报为受控错误返回。
            uc.mem_write(uc.reg_read(UC_ARM_REG_R2), b"\xff" * 4 + bytes(uc.reg_read(UC_ARM_REG_R1) * 512 - 4))
            m.ret()
        elif off == 0x7c48 and injected_error:
            m.ret(0xffffffff)
    m.uc.hook_add(UC_HOOK_CODE, code)
    result = m.call(0x7ff8, (PTBL, 0x10000012, DEVICE), count=100000)
    assert m.uc.reg_read(UC_ARM_REG_PC) == RETURN
    assert result == 0 and "Decode Error!\n" in prints
    return dict(entry="0x7ff8", inputCase="注入内部 -1" if injected_error else "NAND 返回缺少 .picbase 的无效装载表",
                callStubs=[hex(x) for x in stubs], prints=prints, result=result,
                evidence="Unicorn 原指令：错误打印后 0x8184 无条件将返回值置 0")


def version_copy_case(ipl):
    m = Machine(ipl)
    before = bytes(m.uc.mem_read(BASE + 0x4000, 65))
    result = m.call(0x4b84, (DEST,))
    assert result == 65 and m.uc.reg_read(UC_ARM_REG_PC) == RETURN
    assert bytes(m.uc.mem_read(DEST, 65)) == before
    return dict(entry="0x4b84", result=result, copiedBytes=65,
                copiedSha256=sha(before), callStubs=[],
                evidence="Unicorn 原指令：IPL 的 65 字节版本表复制到传入地址，无版本比较")


def fallback_case(ipl, ptbl, outer_failure):
    """区分向上传播的 LoadData 错误和被吞掉的内部错误。"""
    m = Machine(ipl)
    m.uc.mem_write(PTBL, ptbl)
    m.uc.mem_write(BASE + 0x111a0, struct.pack("<I", BASE + 0x4bd8))
    loaded, prints = [], []
    stubs = [0x8194, 0x7834, 0x702c]
    if outer_failure:
        stubs.append(0x7ff8)
    else:
        stubs += [0x6ab4, 0x6b28, 0x6e08, 0x6c7c, 0x7c48]
    def code(uc, address, size, unused):
        off = address - BASE
        if off == 0x8194:
            m.ret()
        elif off == 0x7834:
            m.ret(0x10000012)
        elif off == 0x7ff8:
            part = uc.reg_read(UC_ARM_REG_R1)
            loaded.append(hex(part))
            if outer_failure:
                m.ret(1 if part == 0x10000012 else 0)
        elif off == 0x702c:
            p = uc.reg_read(UC_ARM_REG_R0)
            prints.append(bytes(uc.mem_read(p, 128)).split(b"\0")[0].decode("ascii"))
            m.ret()
        elif off in (0x6ab4, 0x6b28, 0x6e08, 0x6c7c):
            m.ret()
        elif off == 0x7c48:
            m.ret(0xffffffff)
        elif off == 0x41c4:
            uc.emu_stop()
    m.uc.hook_add(UC_HOOK_CODE, code)
    m.call(0x40cc, (PTBL, RAM + 0x4000, DEVICE, RAM + 0x5000))
    assert m.uc.reg_read(UC_ARM_REG_PC) == BASE + 0x41c4
    expected = ["0x10000012", "0x10000010"] if outer_failure else ["0x10000012"]
    assert loaded == expected
    return dict(entry="0x40cc", inputCase="LoadData 返回 1" if outer_failure else "内部 0x7c48 返回 -1",
                callStubs=[hex(x) for x in stubs], loadedPartitions=loaded, prints=prints,
                bootFallback=outer_failure, stopPc="0x41c4")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-native-decode", action="store_true",
                        help="原生解码未获验证时退出码为 2，供构建门禁使用")
    args = parser.parse_args()
    body, nd1, ipl, ptbl = inputs()
    table = records(body)
    native = {}
    for name in ("text", "rodata", "data"):
        packed = table[".ROM." + name]
        start = packed["address"] - 0x10000000
        expected = (ROOT / f"output/reference-decoded/body-3-2-cn/{name}.mapped.candidate.bin").read_bytes()
        assert len(expected) == table["." + name]["size"]
        native[name] = hardware_case(ipl, body[start:start + packed["size"]], expected)
    report = dict(inputSha256=INPUT_HASH, iplSha256=IPL_HASH,
                  evidenceType="官方 ARM 指令在 Unicorn ARM926 执行；无相机访问",
                  nativeDecodeVerified=False, nativeDecodeFailure="解码由 MMIO 硬件执行，Unicorn 不提供此 SoC 外设",
                  descriptor=descriptor_case(ipl, ptbl), sections=table,
                  hardwareAttempts=native, loadPath=load_until_wait(ipl, body, ptbl),
                  errorCases=[decode_error_case(ipl, ptbl), decode_error_case(ipl, ptbl, True)],
                  fallbackCases=[fallback_case(ipl, ptbl, True), fallback_case(ipl, ptbl, False)],
                  versionCopy=version_copy_case(ipl),
                  firmwareProduced=False)
    assert sha(INPUT.read_bytes()) == INPUT_HASH
    path = ROOT / "reports/native-ipl-load-results.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS：10 个受限原指令用例（含两个 BOOT 回退分支）；所有调用桩均列入结果")
    print("未通过原生解码验证：硬件无仿真实现，三个输出缓冲均未改变；未生成固件")
    if args.require_native_decode:
        raise SystemExit(2)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
