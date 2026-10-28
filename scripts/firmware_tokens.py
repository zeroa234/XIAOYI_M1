"""官方 token 保留、局部字面量替换；格式仅获统计/结构证据。

自写的解析/序列化与局部替换，不是通用 LZSS 编码器，不生成新匹配。
所有长度都取容器/装载表，不使用零串猜测压缩流终点。
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL = ROOT / "data/input/body-3-2-cn/firmware.bin"
OFFICIAL_SHA = "92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4"
SECTIONS = (".text", ".rodata", ".data")
WINDOW, START = 4096, 0xfee


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class Token:
    literal: bool
    raw: bytes
    out: int
    size: int
    source_offset: int = -1

    @property
    def index(self):
        return self.raw[0] | ((self.raw[1] & 0xf0) << 4)


@dataclass(slots=True)
class Stream:
    tokens: list[Token]
    unused_flags: int
    orphan_flag: bytes
    output_size: int


def parse_stream(data):
    tokens, cursor, out, unused, orphan = [], 0, 0, 0, b""
    while cursor < len(data):
        flag = data[cursor]
        cursor += 1
        if cursor == len(data):
            orphan = bytes([flag])
            break
        for bit in range(8):
            if cursor == len(data):
                unused = flag & ~((1 << bit) - 1)
                break
            literal = bool(flag & (1 << bit))
            size = 1 if literal else 2
            require(cursor + size <= len(data), "截断的匹配 token")
            raw = data[cursor:cursor + size]
            n = 1 if literal else (raw[1] & 15) + 3
            tokens.append(Token(literal, raw, out, n, cursor))
            cursor += size
            out += n
    return Stream(tokens, unused, orphan, out)


def serialize_stream(stream):
    output = bytearray()
    tokens = stream.tokens
    for pos in range(0, len(tokens), 8):
        group = tokens[pos:pos + 8]
        flag = sum(int(token.literal) << bit for bit, token in enumerate(group))
        if len(group) < 8:
            flag |= stream.unused_flags & ~((1 << len(group)) - 1)
        output.append(flag)
        for token in group:
            require(len(token.raw) == (1 if token.literal else 2), "非法 token 字节数")
            output.extend(token.raw)
    require(not stream.orphan_flag or len(tokens) % 8 == 0,
            "不能在不完整 flag 组后保留独立尾 flag")
    output.extend(stream.orphan_flag)
    return bytes(output)


def decode(stream, semantics):
    require(semantics in ("sequential", "snapshot", "snapshot_zero"), "未知复制语义")
    ring, write, output = bytearray(WINDOW), START, bytearray()
    for token in stream.tokens:
        if token.literal:
            values = token.raw
        elif semantics.startswith("snapshot"):
            if semantics == "snapshot" and len(output) < WINDOW:
                level = len(output)
                shift = write - level
                def warm_slot(index):
                    if level == 0:
                        return index & 4095
                    value = index - shift
                    # JavaScript remainder 保留被除数符号；复现现有工具的 warm-up。
                    value = value % WINDOW if value >= 0 else -((-value) % WINDOW)
                    value = value % level if value >= 0 else -((-value) % level)
                    return (value + shift + WINDOW) & 4095
                values = bytes(ring[warm_slot(token.index + n)] for n in range(token.size))
            else:
                values = bytes(ring[(token.index + n) & 4095] for n in range(token.size))
        else:
            for n in range(token.size):
                value = ring[(token.index + n) & 4095]
                output.append(value)
                ring[write] = value
                write = (write + 1) & 4095
            continue
        output.extend(values)
        for value in values:
            ring[write] = value
            write = (write + 1) & 4095
    return bytes(output)


def literal_tokens(data):
    return Stream([Token(True, bytes([value]), i, 1) for i, value in enumerate(data)], 0, b"", len(data))


def splice(stream, sequential, snapshot, changes):
    """changes: 明文偏移 -> (原字节, 新字节)。维护只有补丁环槽不同的归纳条件。"""
    require(len(sequential) == len(snapshot) == stream.output_size, "候选明文长度不一致")
    for pos, (old, new) in changes.items():
        require(0 <= pos < len(sequential), "补丁超出子段")
        require(sequential[pos] == old, f"原字节不符：{pos:#x}")
        require(sequential[pos] == snapshot[pos], f"补丁不在语义无关掩码内：{pos:#x}")
        require(old != new, "changes 只接受实际变化字节")
    if not changes:
        return stream, dict(replacedTokens=0, dependentTokens=0, newLiterals=0, changedByteCount=0)
    dirty, result, replaced, dependent, inserted = set(), [], 0, 0, 0
    patch_positions = sorted(changes)
    p = 0
    for token in stream.tokens:
        end = token.out + token.size
        while p < len(patch_positions) and patch_positions[p] < token.out:
            p += 1
        covers = p < len(patch_positions) and patch_positions[p] < end
        reads_dirty = bool(dirty) and not token.literal and any(((token.index + n) & 4095) in dirty for n in range(token.size))
        replace = covers or reads_dirty
        if replace:
            require(sequential[token.out:end] == snapshot[token.out:end],
                    f"需字面量化的整个 token 不在语义无关掩码内：{token.out:#x}..{end:#x}")
            for pos in range(token.out, end):
                value = changes[pos][1] if pos in changes else sequential[pos]
                result.append(Token(True, bytes([value]), pos, 1))
            replaced += 1
            dependent += int(reads_dirty and not covers)
            inserted += token.size
        else:
            result.append(token)  # 官方 token 对象及 raw 保留。
        # 只有真正补丁字节与对应语义的官方环状态不同，其余写入均恢复原值。
        for pos in range(token.out, end):
            slot = (START + pos) & 4095
            dirty.discard(slot)
            if pos in changes:
                dirty.add(slot)
    return Stream(result, stream.unused_flags, stream.orphan_flag, stream.output_size), dict(
        replacedTokens=replaced, dependentTokens=dependent, newLiterals=inserted,
        changedByteCount=len(changes), retainedTokens=len(stream.tokens) - replaced)


def parse_container(raw):
    result, at = [], 0
    while at < len(raw):
        header = raw[at:at + 256]
        require(len(header) == 256, "段头不足 0x100 字节")
        require(header.startswith(b"LENGTH=") if not result else
                re.match(rb"(?:ND1|IPL|PTBL)\s+LENGTH=", header) is not None,
                "首头须以 LENGTH= 开始，命名头须以其段名和 LENGTH= 开始")
        require(b"C59Y1" in header[:64], "前 0x40 字节缺少 C59Y1")
        length_matches = re.findall(rb"\bLENGTH=(\d+)\b", header)
        sums = re.findall(rb"\bSUM=(\d+)\b", header)
        version = re.search(rb"\bVER=([^\s\x00]+)", header)
        require(len(length_matches) == len(sums) == 1, "LENGTH/SUM 缺失或重复")
        require(version is not None and len(version[1]) <= 10, "VER 字段非法")
        length = int(length_matches[0])
        require(length > 0 and at + 256 + length <= len(raw), "段体长度越界")
        body = raw[at + 256:at + 256 + length]
        require(sum(body) & 0xffffffff == int(sums[0]), "SUM 不符")
        result.append(dict(offset=at, header=header, body=body, length=length, sum=int(sums[0])))
        at += 256 + length
    require(at == len(raw) and bool(result), "容器长度非法")
    return result


def load_records(body):
    records, seen, at = {}, set(), 0x1000
    while at:
        require(0x1000 <= at < 0x17a0 and at not in seen, "装载表越界/自环")
        seen.add(at)
        nxt, name, va, size, flags, associated = struct.unpack_from("<6I", body, at)
        require(0x1000 <= name < 0x17a0, "名字指针越界")
        end = body.find(b"\0", name, 0x17a0)
        require(end >= 0, "名字未终止")
        label = body[name:end].decode("ascii")
        require(label not in records, "重复段名")
        records[label] = dict(record=at, next=nxt, nameOffset=name, va=va, size=size, flags=flags, associated=associated)
        at = nxt
    return records


def layouts(body):
    table, result = load_records(body), {}
    for i, name in enumerate(SECTIONS):
        packed, plain = table[".ROM" + name], table[name]
        start = packed["va"] - 0x10000000
        limit = table[".ROM" + SECTIONS[i + 1]]["va"] - 0x10000000 if i < 2 else len(body)
        require(0 <= start < start + packed["size"] <= limit <= len(body), "ROM 区间不一致")
        require(packed["associated"] == plain["record"], "ROM 目标记录关联不符")
        result[name] = dict(start=start, limit=limit, capacity=limit - start,
                            packedSize=packed["size"], plainSize=plain["size"], va=plain["va"],
                            sizeField=packed["record"] + 12,
                            slack=limit - start - packed["size"])
    return result


def official_bytes():
    raw = OFFICIAL.read_bytes()
    require(sha(raw) == OFFICIAL_SHA, "官方输入 SHA-256 不符")
    return raw
