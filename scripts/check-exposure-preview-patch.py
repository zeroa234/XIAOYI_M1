"""执行原取景配置函数及 JSON 补丁；严格区分局部通过与整机曝光精度。"""
from pathlib import Path
import hashlib
import itertools
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_EXEC)
from unicorn.arm_const import *

BASE = ROOT / "output/reference-decoded/body-3-2-cn"
TEXT = (BASE / "text.mapped.candidate.bin").read_bytes()
RODATA = (BASE / "rodata.mapped.candidate.bin").read_bytes()
DATA = (BASE / "data.mapped.candidate.bin").read_bytes()
MANIFEST_PATH = ROOT / "config/patches/exposure-preview.json"
MANIFEST_BYTES = MANIFEST_PATH.read_bytes()
MANIFEST = json.loads(MANIFEST_BYTES)
STOP = 0x1000
SNAP = 0x20010000
CFG = 0x20020000
STATE = 0x20024000
SP = 0x20038000
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
        UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_CPSR]


def put(cpu, address, value):
    cpu.mem_write(address, struct.pack("<I", value & 0xffffffff))


def word(cpu, address):
    return struct.unpack("<I", cpu.mem_read(address, 4))[0]


def signed(value):
    return value-0x100000000 if value & 0x80000000 else value


def machine(patched, write_ranges):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, 0x9b0000)
    cpu.mem_write(0x2000, TEXT)
    cpu.mem_write(0x43f800, RODATA)
    if patched:
        for p in MANIFEST["patches"]:
            assert p["section"] == ".text"
            va = int(p["va"], 16)
            before, after = bytes.fromhex(p["orig_hex"]), bytes.fromhex(p["new_hex"])
            assert len(before) == len(after)
            assert bytes(cpu.mem_read(va, len(before))) == before
            assert not (va < 0x111000 and va+len(after) > 0x10f000)
            cpu.mem_write(va, after)
    cpu.mem_protect(0, 0x9b0000, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(0xc09b0000, 0x60000)
    cpu.mem_write(0xc09b0000, DATA)
    cpu.mem_map(0xc1400000, 0x200000)
    cpu.mem_map(0x20000000, 0x40000)
    for va, size in ((0x30100000, 0x1000), (0x30000000, 0x3000),
                     (0x300f0000, 0x1000), (0x21c00000, 0x1000)):
        cpu.mem_map(va, size)
    cpu.reg_write(UC_ARM_REG_CPSR, 0xa0000013)
    for index, register in enumerate(REGS[:13]):
        cpu.reg_write(register, 0x12000000+index*0x101)
    cpu.reg_write(UC_ARM_REG_SP, SP)
    cpu.reg_write(UC_ARM_REG_LR, STOP)
    state = {"invalid": [], "outsideWrites": [], "patchOutsideReads": [], "finished": False, "writes": 0}

    def invalid_hook(c, access, address, size, value, user):
        state["invalid"].append([access, hex(address), size, hex(c.reg_read(UC_ARM_REG_PC))])
        return False

    def write_hook(c, access, address, size, value, user):
        state["writes"] += 1
        if not any(lo <= address and address+size <= hi for lo, hi in write_ranges):
            state["outsideWrites"].append([hex(address), size, hex(c.reg_read(UC_ARM_REG_PC))])
            c.emu_stop()

    def read_hook(c, access, address, size, value, user):
        pc = c.reg_read(UC_ARM_REG_PC)
        if 0x369d68 <= pc < 0x369dbc:
            # 新代码只能读其字面量、栈、调用方输出对象或已定位缓存。
            allowed = [(0x369d68, 0x369dc0), (0xc150f9f4, 0xc150f9f8), *write_ranges]
            if not any(lo <= address and address+size <= hi for lo, hi in allowed):
                state["patchOutsideReads"].append([hex(address),size,hex(pc)])
                c.emu_stop()

    cpu.hook_add(UC_HOOK_MEM_INVALID, invalid_hook)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    cpu.hook_add(UC_HOOK_MEM_READ, read_hook)
    return cpu, state


def execute(cpu, state, start, end=STOP, ack=False, count=100000):
    def boundary(c, address, size, user):
        if ack and address == 0x244694:
            # 外设模型：传输完成位；不替换任何 ARM 调用或数学函数。
            put(c, 0x21c00020, 1)
        if address == end:
            state["finished"] = True
            c.emu_stop()
    hook = cpu.hook_add(UC_HOOK_CODE, boundary)
    cpu.emu_start(start, 0, timeout=3000000, count=count)
    cpu.hook_del(hook)
    assert state["finished"] and not state["invalid"] and not state["outsideWrites"] and not state["patchOutsideReads"], state


def config_case(patched, mode, kind, delta, setting, cfg=CFG, base_comp=0):
    cpu, state = machine(patched, [(cfg, cfg+0x80), (SP-0x1000, SP)])
    cpu.mem_write(SNAP, bytes([0x19])*0x2a8)
    cpu.mem_write(cfg, bytes([0xcc])*0x80)
    # 原填充器读入的配置；设置与种类皆为测试输入，不声称是真机 RAM。
    for off, value in {0x1c:mode, 0x20:0, 0x30:base_comp, 0x40:setting[0],
                       0x44:setting[2], 0x58:setting[1], 0x19c:123}.items():
        put(cpu, SNAP+off, value)
    put(cpu, cfg+4, kind)
    put(cpu, 0xc150f9f4, delta)
    put(cpu, 0xc09d9804, 1)
    # 原函数读取的帧时序：36000、1200*1000 clocks，约33.3ms。
    put(cpu, 0x30100004, 1199 << 16)
    put(cpu, 0x30100020, 1000 << 16)
    cpu.reg_write(UC_ARM_REG_R0, cfg)
    cpu.reg_write(UC_ARM_REG_R1, SNAP)
    execute(cpu, state, 0x362084, 0x362088)
    assert cpu.reg_read(UC_ARM_REG_SP) == SP
    return bytes(cpu.mem_read(cfg, 0x80)), [cpu.reg_read(r) for r in REGS], state


def target_case(compensation):
    cpu, state = machine(False, [(STATE, STATE+0x100), (SP-0x1000, SP)])
    put(cpu, CFG+0x10, 3869)
    put(cpu, CFG+0x30, compensation)
    cpu.reg_write(UC_ARM_REG_R0, 1)
    cpu.reg_write(UC_ARM_REG_R1, CFG)
    cpu.reg_write(UC_ARM_REG_R2, 0x20025000)
    cpu.reg_write(UC_ARM_REG_R3, STATE)
    # 运行原 0x362bbc 到首次 0x35d254 返回，停止在后续平滑处理之前。
    execute(cpu, state, 0x362bbc, 0x362be4)
    factor = struct.unpack_from("<I", RODATA, 0x860d08-0x43f800+(compensation+90)*4)[0]
    result = cpu.reg_read(UC_ARM_REG_R0)
    assert result == 3869*factor//10000, (compensation, result, factor)
    return {"十分之一EV": compensation, "原AE目标": result, "表倍率x10000": factor}


def isp_case(value):
    allowed = [(STATE, STATE+16), (SP-0x1000, SP), (0x300f0310, 0x300f0318)]
    cpu, state = machine(False, allowed)
    for i in range(4):
        put(cpu, STATE+i*4, value)
    cpu.reg_write(UC_ARM_REG_R0, STATE)
    execute(cpu, state, 0x429704)
    expected = min(65535, (value*1024+50)//100)
    packed = expected | (expected << 16)
    assert [word(cpu, 0x300f0310), word(cpu, 0x300f0314)] == [packed, packed]
    assert cpu.reg_read(UC_ARM_REG_SP) == SP
    return {"百分之一倍": value, "四通道Q10": expected}


def shutter_case(first, second):
    allowed = [(SP-0x1000, SP), (0x30000800, 0x30000804),
               (0x300021b0, 0x300021bc), (0x21c00000, 0x21c00030)]
    cpu, state = machine(False, allowed)
    events = []

    def record(c, access, address, size, value, user):
        if address == 0x21c00018:
            events.append([word(c, 0x21c00014), value & 255])
    cpu.hook_add(UC_HOOK_MEM_WRITE, record)
    cpu.reg_write(UC_ARM_REG_R0, first)
    cpu.reg_write(UC_ARM_REG_R1, second)
    execute(cpu, state, 0x3ba548, ack=True)
    a, b = min(first, 4095), min(second, 4095)
    expected = [[0x702, a & 255], [0x802, a >> 8], [0x302, b & 255], [0x402, b >> 8]]
    assert events == expected, (events, expected)
    assert cpu.reg_read(UC_ARM_REG_SP) == SP
    return {"行计数输入": [first, second], "原传输命令": events}


def time_to_rows_case(value, height, line_clocks):
    cpu, state = machine(False, [(SP-0x1000,SP)])
    put(cpu,0xc09d9804,1)
    # 原0x241a94对寄存器字段先加1，测试参数height表示实际返回行数。
    put(cpu,0x30100020,(height-1) << 16)
    put(cpu,0x30100004,(line_clocks-1) << 16)
    cpu.reg_write(UC_ARM_REG_R0,0)
    cpu.reg_write(UC_ARM_REG_R2,value)
    execute(cpu,state,0x3b8ef8)
    off = 0x8715cc-0x43f800  # 已初始化为模式0；原函数从实际 rodata 取转换参数。
    correction = struct.unpack_from("<H",RODATA,off)[0]
    margins = RODATA[off+6]
    numerator = (36*max(10,value)+correction) & 0xffffffff
    integration = numerator//line_clocks
    integration = max(margins >> 4,min(integration,height-(margins & 15)))
    expected = height-integration
    actual = cpu.reg_read(UC_ARM_REG_R0)
    assert actual == expected, (value,height,line_clocks,actual,expected)
    assert cpu.reg_read(UC_ARM_REG_SP) == SP
    return {"时间输入":value,"帧行数":height,"行时钟":line_clocks,"原转换结果":actual}


def owner_and_timeout_cases():
    cpu, state = machine(True, [(SP-0x1000, SP)])
    entered = []
    def trace(c, address, size, user):
        if 0x369d68 <= address < 0x369e18:
            entered.append(hex(address))
    cpu.hook_add(UC_HOOK_CODE, trace)
    execute(cpu, state, 0x369d50, 0x369e18)
    assert not entered
    allowed = [(0x30000800,0x30000804), (0x300021b0,0x300021bc), (0x21c00000,0x21c00030)]
    cpu, state = machine(False, allowed)
    polls = []
    def poll(c, address, size, user):
        if address == 0x244684:
            polls.append(1)
    cpu.hook_add(UC_HOOK_CODE, poll)
    cpu.mem_write(STATE, b"\x02\x07\x12")
    cpu.reg_write(UC_ARM_REG_R0, STATE)
    execute(cpu, state, 0x2445e8, count=120000)
    assert len(polls) == 10001 and cpu.reg_read(UC_ARM_REG_R0) == 0
    return {"原死区所属函数仍跳过新增代码": True,
            "SPI不返回完成位时": {"轮询入口次数": len(polls), "返回": 0,
                               "说明": "有界但静默返回成功；未据此提出超时补丁"}}


def mode_switch_cases():
    rows = []
    for dial in range(1,6):
        cpu, state = machine(False, [(0xc1401074,0xc1401174), (SP-0x1000,SP+16)])
        cpu.mem_write(0xc1401074+0xa9,bytes([dial]))
        cpu.reg_write(UC_ARM_REG_R4,0xc1401074)
        cpu.reg_write(UC_ARM_REG_R5,0xc14c7d5d)
        # 从已选中普通档位重配分支进入；补足调用方保存帧，不模拟该分支之前的门控。
        for i,v in enumerate((0,0,0,STOP)):
            put(cpu,SP+4*i,v)
        execute(cpu,state,0xad85c)
        rows.append({"机身档位编码":dial,
                     "AE模式":cpu.mem_read(0xc1401074+0xb7,1)[0],
                     "设置af":cpu.mem_read(0xc1401074+0xaf,1)[0]})
    assert rows[-1]["AE模式"] == 1 and rows[-1]["设置af"] == 0
    return rows


def main():
    expected = {r["section"].lstrip("."): r["mappedSha256"] for r in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"] if r["version"] == "3.2-cn"}
    hashes = {n:hashlib.sha256(b).hexdigest() for n,b in (("text",TEXT),("rodata",RODATA),("data",DATA))}
    assert hashes == expected
    evidence = json.loads((ROOT / "reports/exposure-apply-evidence-2026-10-27.json").read_text(encoding="utf-8"))
    dead = evidence["deadCodeCandidate"]
    assert not dead["alignedPointers"] and not dead["adr"]
    assert all(b["inside"] for b in dead["directBranches"])
    assert TEXT[0xf880-0x2000:0xf888-0x2000].hex() == "0000a0e31eff2fe1"
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    hook = MANIFEST["patches"][0]
    ins = next(cs.disasm(bytes.fromhex(hook["new_hex"]), 0x362084))
    assert (ins.mnemonic, ins.op_str) == ("bl", "#0x369d68")
    cave = MANIFEST["patches"][1]
    assert int(cave["va"],16) == 0x369d68 and len(bytes.fromhex(cave["new_hex"])) == 88
    disassembly = [f"{i.address:#x}: {i.mnemonic} {i.op_str}" for i in cs.disasm(bytes.fromhex(cave["new_hex"])[:84],0x369d68)]
    assert len(disassembly) == 21
    settings = [(250,35,3), (33333,71,6), (1300000,35,3), (60000000,220,11)]
    deltas = [-0x80000000, -51, -50, -33, -1, 0, 1, 20, 50, 51, 0x7fffffff]
    config_count, m_count, unchanged_count = 0, 0, 0
    for mode, kind, delta, setting in itertools.product(range(6), range(3), deltas, settings):
        before, before_regs, _ = config_case(False, mode, kind, delta, setting)
        after, after_regs, _ = config_case(True, mode, kind, delta, setting)
        wanted = bytearray(before)
        if mode == 1 and kind == 0:
            struct.pack_into("<i", wanted, 0x30, max(-50,min(50,delta)))
            m_count += 1
        else:
            unchanged_count += 1
        assert after == wanted, (mode, kind, delta, setting)
        assert before_regs == after_regs, ("返回寄存器/CPSR变化",mode,kind,delta)
        config_count += 2
    for mode, comp in itertools.product(range(6), (-50,-20,20,50)):
        before, regs, _ = config_case(False,mode,0,20,settings[0],base_comp=comp)
        after, after_regs, _ = config_case(True,mode,0,20,settings[0],base_comp=comp)
        wanted = bytearray(before)
        if mode == 1:
            struct.pack_into("<i",wanted,0x30,20)
            m_count += 1
        else:
            unchanged_count += 1
        assert after == wanted and regs == after_regs
        config_count += 2
    # 配置紧贴映射页边沿，验证88字节包装器未越过128字节输出对象。
    for cfg in (0x20020000, 0x20020f80, 0x20021000, 0x2003ff80):
        config_case(True, 1, 0, 20, settings[0], cfg=cfg)
        config_count += 1
    targets = [target_case(x) for x in (-50,-33,-20,-10,0,10,20,33,50)]
    assert all(a["原AE目标"] < b["原AE目标"] for a,b in zip(targets,targets[1:]))
    isp = [isp_case(x) for x in (0,1,50,100,125,200,3200,6399,6400,25600,64000,100000)]
    shutter = [shutter_case(a,b) for a,b in ((0,0),(1,2),(255,256),(1000,2000),(4095,4095),(4096,5000),(0xffffffff,0xffffffff))]
    time_rows = [time_to_rows_case(t,h,l) for (h,l),t in itertools.product(
        ((1000,1200),(1125,533),(2250,266)),(0,1,10,250,1000,16667,33333,1300000,60000000,0xffffffff))]
    additional = owner_and_timeout_cases()
    mode_rows = mode_switch_cases()
    report = {
        "状态": "局部隔离验证通过；候选尚未真机验证，不证明最终曝光精度",
        "inputSha256": hashes, "patchManifestSha256": hashlib.sha256(MANIFEST_BYTES).hexdigest(),
        "配置函数原指令与补丁执行次数": config_count,
        "M_kind0成对用例": m_count, "保持原配置的成对用例": unchanged_count,
        "非法访存及允许范围外写入": 0, "返回寄存器与CPSR": "所有成对用例一致",
        "补丁代码超出对象范围读取": 0,
        "补丁反汇编": disassembly,
        "原取景AE目标换算": targets, "原ISP数字增益写入": isp, "原传感器行计数传输": shutter,
        "原积分时间转行计数": time_rows,
        "入口及原传输超时验证": additional,
        "普通档位重配分支原指令": mode_rows,
        "硬件模型": "合成帧时序与RAM；SPI完成位由模拟外设提供。没有任何函数调用桩。",
        "证明范围": ["全程执行原0x361ad4、原取景调用指令或JSON替换指令；非M及非零kind的128字节配置完全一致。",
                       "M/kind0仅改变原补偿字段；缓存钳到±50；原0x362bbc→0x35d254按表生成单调目标。",
                       "原0x429704执行四通道Q10写入与上限钳位；原0x3ba548→0x2445e8执行命令打包和MMIO传输。"],
        "未证明": ["没有执行完整0x365344闭环、调度器、AF、镜头与真实传感器。",
                   "多组快门/光圈/ISO是合成配置；M缓存由装置提供，没有伪称其由这三项完整原生链计算。",
                   "目标变化不等于最终积分时间/增益随设置正确变化；原帧周期钳位与数字增益组合尚未闭环核验。",
                   "kind=0业务范围、缓存实时性和曝光偏差的物理标定尚未完全核实；不建议自动并入刷机包。"]}
    (ROOT / "reports/exposure-preview-patch-results-2026-10-27.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2)+"\n",encoding="utf-8")
    print("配置函数执行",config_count,"次；M/kind0",m_count,"对，原样保持",unchanged_count,"对。")
    print("原AE目标",len(targets),"项；ISP",len(isp),"项；传感器传输",len(shutter),"项；均通过。")
    print("原积分时间转行计数",len(time_rows),"项；均通过。")
    print("没有证明完整曝光闭环；实验候选不能自动作为已完成的曝光预览修复。")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        (ROOT / "temp/codex-exposure/validation-failure.txt").write_text(
            type(error).__name__+": "+str(error),encoding="utf-8")
        raise
