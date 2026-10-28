"""Execute the extracted ARM command-search loop with existing Unicorn.

Only emulator RAM is changed. No patched firmware/image is written. This tests
one isolated loop, not camera compatibility, the HTTP server or a freeze fix.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (UC_CPU_ARM_926, UC_ARM_REG_SP, UC_ARM_REG_PC,
    UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R9, UC_ARM_REG_R12)

TEXT_ADDRESS = 0x2000
RODATA_ADDRESS = 0x43f800
LOOP_START = 0x1568b4
LOOP_READ = 0x1568bc
LOOP_END = 0x15691c
COMPARE = 0x156910
TABLE_ADDRESS = 0x6b86a8
TABLE_BYTES = 0x168


def run_case(text, rodata, command, changed, stack, replacement_bytes):
    emu = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    emu.ctl_set_cpu_model(UC_CPU_ARM_926)
    emu.mem_map(0, 0x9b0000)
    emu.mem_write(TEXT_ADDRESS, text)
    emu.mem_write(RODATA_ADDRESS, rodata)
    if changed:
        # ARM A32 CMP r6,#45, independently checked below by Capstone.
        emu.mem_write(COMPARE, replacement_bytes)
    emu.mem_map(0x20000000, 0x40000)
    tokens = 0x20000000
    input_address = 0x20001000
    emu.mem_write(input_address, command + b"\0")
    # Fields used by the extracted loop: string type, begin and end offsets.
    emu.mem_write(tokens + 0x10, struct.pack("<III", 3, 0, len(command)))
    table_start = stack + 0x34
    table = rodata[TABLE_ADDRESS - RODATA_ADDRESS:TABLE_ADDRESS - RODATA_ADDRESS + TABLE_BYTES]
    emu.mem_write(table_start, table)
    for register, value in ((UC_ARM_REG_SP, stack), (UC_ARM_REG_R4, tokens),
                            (UC_ARM_REG_R7, input_address), (UC_ARM_REG_R9, 0)):
        emu.reg_write(register, value)
    events = {"command": command.decode("ascii"), "emulatorChange": changed,
              "stack": hex(stack), "reads": 0, "firstOutsideTable": None, "finished": False}

    def read_hook(cpu, access, address, size, value, user):
        if cpu.reg_read(UC_ARM_REG_PC) == LOOP_READ:
            events["reads"] += 1
            if not (table_start <= address and address + size <= table_start + TABLE_BYTES):
                events["firstOutsideTable"] = {"index": cpu.reg_read(UC_ARM_REG_R6),
                    "address": hex(address), "size": size}
                cpu.emu_stop()

    def code_hook(cpu, address, size, user):
        if address == LOOP_END:
            events["finished"] = True
            cpu.emu_stop()

    emu.hook_add(UC_HOOK_MEM_READ, read_hook)
    emu.hook_add(UC_HOOK_CODE, code_hook)
    emu.emu_start(LOOP_START, 0, timeout=2000000, count=100000)
    events["resultHandler"] = hex(emu.reg_read(UC_ARM_REG_R12))
    events["lastIndex"] = emu.reg_read(UC_ARM_REG_R6)
    if not events["finished"] and events["firstOutsideTable"] is None:
        raise AssertionError("Emulation did not reach a checked boundary")
    return events


def main():
    base = ROOT / "output/reference-decoded/body-3-2-cn"
    text = (base / "text.mapped.candidate.bin").read_bytes()
    rodata = (base / "rodata.mapped.candidate.bin").read_bytes()
    expected = {row["section"]: row["mappedSha256"] for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"] if row["version"] == "3.2-cn"}
    for section, data in ((".text", text), (".rodata", rodata)):
        if hashlib.sha256(data).hexdigest() != expected[section]:
            raise ValueError("Candidate input hash changed")
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    original_bytes = text[COMPARE-TEXT_ADDRESS:COMPARE-TEXT_ADDRESS+4]
    original_instruction = next(cs.disasm(original_bytes, COMPARE))
    manifest_path = ROOT / "config/patches/command-bounds.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if len(manifest["patches"]) != 1:
        raise AssertionError("Unexpected manifest patch count")
    patch = manifest["patches"][0]
    if patch["section"] != ".text" or int(patch["va"], 16) != COMPARE:
        raise AssertionError("Unexpected manifest segment/address")
    if bytes.fromhex(patch["orig_hex"]) != original_bytes:
        raise AssertionError("Manifest original bytes do not match pinned input")
    replacement_bytes = bytes.fromhex(patch["new_hex"])
    if len(replacement_bytes) != 4:
        raise AssertionError("Replacement must be one ARM instruction")
    replacement_instruction = next(cs.disasm(replacement_bytes, COMPARE))
    if (original_instruction.mnemonic, original_instruction.op_str) != ("cmp", "r6, #0x168"):
        raise AssertionError("Unexpected original comparison")
    if (replacement_instruction.mnemonic, replacement_instruction.op_str) != ("cmp", "r6, #0x2d"):
        raise AssertionError("Unexpected emulator-only comparison")
    table = rodata[TABLE_ADDRESS-RODATA_ADDRESS:TABLE_ADDRESS-RODATA_ADDRESS+TABLE_BYTES]
    commands = []
    handlers = []
    for offset in range(0, TABLE_BYTES, 8):
        pointer, handler = struct.unpack_from("<II", table, offset)
        start = pointer - RODATA_ADDRESS
        end = rodata.index(b"\0", start)
        command = rodata[start:end]
        if not all(0x20 <= b < 0x7f for b in command):
            raise AssertionError("Non-ASCII command needs separate inspection")
        commands.append(command)
        handlers.append(handler)
    if len(set(commands)) != 45:
        raise AssertionError("Unexpected duplicate command")
    results = []
    for changed in (False, True):
        for command, handler in zip(commands, handlers):
            event = run_case(text, rodata, command, changed, 0x20010000, replacement_bytes)
            if not event["finished"] or event["firstOutsideTable"] or int(event["resultHandler"], 16) != handler:
                raise AssertionError(f"Known command changed or escaped table: {event}")
            results.append(event)
        for stack in (0x20010000, 0x20020000):
            for command in (b"NoSuchCommand", b"RCISOSet-unknown", b"GetCameraStatus-unknown", b""):
                event = run_case(text, rodata, command, changed, stack, replacement_bytes)
                if changed:
                    if not event["finished"] or event["firstOutsideTable"] or int(event["resultHandler"], 16) != 0:
                        raise AssertionError(f"Changed loop did not reject unknown command: {event}")
                elif event["firstOutsideTable"] is None or event["firstOutsideTable"]["index"] != 45:
                    raise AssertionError(f"Original loop did not reproduce first excess read: {event}")
                results.append(event)
    report = {
        "qualification": "固定候选 ARM 搜索循环隔离验证；不是整机挂死诊断或真机刷写验证。补丁直接读取清单。",
        "patchManifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
        "patchManifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "existingEngines": {"disassembly": "Capstone", "execution": "Unicorn 2.1.4 ARM926"},
        "loop": {"start": hex(LOOP_START), "read": hex(LOOP_READ), "end": hex(LOOP_END)},
        "tableAddress": hex(TABLE_ADDRESS), "tableBytes": TABLE_BYTES, "records": len(commands),
        "originalCompare": {"address": hex(COMPARE), "bytes": original_bytes.hex(), "assembly": original_instruction.op_str},
        "emulatorOnlyCompare": {"bytes": replacement_bytes.hex(), "assembly": replacement_instruction.op_str},
        "passedCases": len(results), "results": results,
        "limits": ["入口寄存器、token字段及表副本由测试装置提供，不是完整HTTP解析器。",
                   "实际执行原strlen/比较指令；没有模拟外设、调度器或HTTP完整生命周期。",
                   "原指令在第一笔表外读取时停止；不等于证明相机崩溃。",
                   "全部机器码更改仅作用于模拟器RAM，不改输入或输出固件包。"]}
    (ROOT / "reports/command-bounds-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("通过：", len(results), "项 ARM 隔离用例；两版本均保留45条合法命令。")
    print("原指令：8项未知命令均尝试表索引45；清单补丁：8项均返回空处理函数。")


if __name__ == "__main__":
    main()
