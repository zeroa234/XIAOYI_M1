"""基于官方 token 和局部字面量替换构建 YI M1 3.2-cn 测试包。

示例：python -B scripts/repack.py --name canary-3.2cn --patches config/canary-3.2cn.json
无 --patches 时构建零改动自检。可显式传入 config/patches/*.json；不会自动
把另一代理目录中的所有补丁混入构建。验证失败不发布 firmware.bin。
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys

from firmware_tokens import (ROOT, SECTIONS, OFFICIAL_SHA, require, sha, official_bytes,
    parse_container, layouts, parse_stream, serialize_stream, decode, splice)

TMP = ROOT / "temp/codex-tmp"
TMP.mkdir(parents=True, exist_ok=True)
os.environ["TMP"] = os.environ["TEMP"] = str(TMP)


def read_patches(patterns):
    patches, sources = [], []
    for pattern in patterns:
        paths = sorted(glob.glob(pattern))
        require(bool(paths), f"找不到补丁文件：{pattern}")
        for path in paths:
            raw = Path(path).read_bytes()
            obj = json.loads(raw.decode("utf-8-sig"))
            values = obj.get("patches") if isinstance(obj, dict) else obj
            require(isinstance(values, list), "补丁文件须为数组或含 patches 数组")
            patches.extend(values)
            sources.append(dict(path=Path(path).resolve().relative_to(ROOT).as_posix(), sha256=sha(raw)))
    return normalize_patches(patches), sources


def normalize_patches(patches):
    result = []
    for p in patches:
        require(isinstance(p, dict) and set(("section", "va", "orig_hex", "new_hex", "note")) <= p.keys(), "补丁字段缺失")
        section = p["section"]
        require(section in SECTIONS, f"不支持的补丁段：{section}")
        va = int(p["va"], 0) if isinstance(p["va"], str) else p["va"]
        require(isinstance(va, int) and not isinstance(va, bool), "补丁 VA 非整数")
        old, new = bytes.fromhex(p["orig_hex"]), bytes.fromhex(p["new_hex"])
        require(bool(old) and len(old) == len(new), "补丁须为非空等长替换")
        require(old != new, "补丁不得完全无变化")
        require(isinstance(p["note"], str) and bool(p["note"]), "补丁须说明用途")
        result.append(dict(section=section, va=hex(va), orig_hex=old.hex(), new_hex=new.hex(), note=p["note"]))
    return sorted(result, key=lambda p: (p["section"], int(p["va"], 0)))


def section_changes(patches, name, layout, baseline):
    changes, occupied = {}, set()
    for p in patches:
        if p["section"] != name:
            continue
        start = int(p["va"], 0) - layout["va"]
        old, new = bytes.fromhex(p["orig_hex"]), bytes.fromhex(p["new_hex"])
        require(0 <= start and start + len(old) <= layout["plainSize"], "补丁跨越明文段边界")
        span = set(range(start, start + len(old)))
        require(not occupied.intersection(span), "补丁范围重叠")
        occupied.update(span)
        require(baseline[start:start + len(old)] == old, f"补丁原字节不符：{name} {p['va']}")
        for i, (a, b) in enumerate(zip(old, new), start):
            if a != b:
                changes[i] = (a, b)
    return changes


def checksum_audit():
    path = ROOT / "reports/secinfo-checksum-results-2026-10-27.json"
    raw = path.read_bytes()
    report = json.loads(raw)
    current = next(v for v in report["versions"] if v["version"] == "3.2-cn")
    require(current["inputSha256"] == OFFICIAL_SHA and current["target"] == "0x4e34f129", "校验扫描来源不符")
    require(not report["identified"] and not current["matches"], "发现潜在校验算法，须先实现同步更新")
    return dict(value="0x4e34f129", status="未识别；已核 IPL 装载路径不检查；原样保留",
                changed=False, auditSha256=sha(raw), audit=path.relative_to(ROOT).as_posix())


def build_firmware(original, patches):
    parts = parse_container(original)
    require(len(parts) == 4 and len(parts[0]["body"]) == 0x707800, "官方容器结构不符")
    oldbody = parts[0]["body"]
    body, rows = bytearray(oldbody), []
    for name, r in layouts(oldbody).items():
        packed = oldbody[r["start"]:r["start"] + r["packedSize"]]
        stream = parse_stream(packed)
        require(serialize_stream(stream) == packed, f"官方 token 序列化自检失败：{name}")
        seq, snap = decode(stream, "sequential"), decode(stream, "snapshot")
        require(len(seq) == len(snap) == stream.output_size and len(seq) >= r["plainSize"], "官方流明文长度非法")
        changes = section_changes(patches, name, r, seq)
        new, stats = splice(stream, seq, snap, changes)
        result = serialize_stream(new)
        require(len(result) <= r["capacity"], f"{name} 增长超出原 ROM 空余：{len(result)-len(packed)} > {r['slack']}")
        # 不移动任何起点，也不重写负载结束以后的官方填充。
        body[r["start"]:r["start"] + len(result)] = result
        if len(result) != len(packed):
            struct.pack_into("<I", body, r["sizeField"], len(result))
        rows.append(dict(section=name, va=hex(r["va"]), romOffset=hex(r["start"]),
                         oldPackedBytes=len(packed), newPackedBytes=len(result), growth=len(result)-len(packed),
                         availableSlack=r["slack"], mappedBytes=r["plainSize"], fullDecodedBytes=len(seq),
                         trailerHex=seq[r["plainSize"]:].hex(), serializationIdentical=True, **stats))
        del stream, new, seq, snap
    header = parts[0]["header"]
    new_sum = sum(body) & 0xffffffff
    old_match = re.search(rb"\bSUM=(\d+)\b", header)
    digits = str(new_sum).encode("ascii")
    require(len(digits) == len(old_match[1]), "SUM 字符宽度改变，停止而不移动头字段")
    header = header[:old_match.start(1)] + digits + header[old_match.end(1):]
    result = header + bytes(body) + original[256 + len(oldbody):]
    require(len(result) == len(original), "容器总长改变")
    return result, rows


def verify_module():
    spec = importlib.util.spec_from_file_location("verify_build", ROOT / "scripts/verify-build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="output/firmware-builds 下的构建名")
    parser.add_argument("--patches", nargs="*", default=[], help="显式补丁 JSON 路径或 glob")
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.name) is not None, "构建名非法")
    patches, sources = read_patches(args.patches)
    audit = checksum_audit()
    original = official_bytes()
    result, rows = build_firmware(original, patches)
    verification = verify_module().verify_build(result, patches)
    require(verification["passed"], "构建未通过验证")
    if not patches:
        require(result == original, "零补丁构建与官方不一致")
    manifest = dict(schema=1, name=args.name, strategy="官方 token 保留＋局部字面量",
        formatEvidence="统计/结构证据，非硬件原生解码证明", inputSha256=OFFICIAL_SHA,
        outputSha256=sha(result), outputBytes=len(result), patchSources=sources, patches=patches,
        buildSections=rows, secinfo=audit, verification=verification,
        nativeDecodeVerified=False, cameraTested=False,
        risk="硬件解码/刷写未实测；内层错误可能被吞掉，等待无超时，BOOT 行为未知；能进升级 UI 才有条件刷回官方包")
    target = ROOT / "output/firmware-builds" / args.name
    require(not (target / "firmware.bin").exists() and not (target / "manifest.json").exists(), "构建已存在；拒绝覆盖")
    target.mkdir(parents=True, exist_ok=True)
    # 只有全部验证完成后发布；原包始终只读。
    (target / "firmware.bin").write_bytes(result)
    (target / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    require(sha(official_bytes()) == OFFICIAL_SHA, "原包改变")
    print(f"通过：{target.relative_to(ROOT)}；SHA-256={sha(result)}")
    print(f"明文差异 {verification['changedPlainBytes']} 字节；容器/段表/保留 token/两种语义均通过")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
