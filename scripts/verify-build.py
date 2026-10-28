"""重新解析候选包，核查容器、官方 token 来源和两种复制语义的全部差异。"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import struct
import sys

from firmware_tokens import (ROOT, SECTIONS, OFFICIAL_SHA, START, require, sha,
    official_bytes, parse_container, load_records, layouts, parse_stream, serialize_stream, decode)
from repack import normalize_patches, section_changes

os.environ["TMP"] = os.environ["TEMP"] = str(ROOT / "temp/codex-tmp")


def provenance(old, new, seq, snap, changes):
    """独立检查新 token：逐原 token 对齐，不接受新匹配或任意重压缩。"""
    index, dirty, retained, expanded = 0, set(), 0, 0
    for token in old.tokens:
        end = token.out + token.size
        patch_here = any(p in changes for p in range(token.out, end))
        reads_dirty = bool(dirty) and not token.literal and any(((token.index + n) & 4095) in dirty for n in range(token.size))
        require(index < len(new.tokens), "新 token 提前结束")
        if patch_here or reads_dirty:
            require(seq[token.out:end] == snap[token.out:end], "字面量化覆盖语义不一致区")
            for p in range(token.out, end):
                require(index < len(new.tokens), "字面量组提前结束")
                actual = new.tokens[index]
                expected = changes[p][1] if p in changes else seq[p]
                require(actual.literal and actual.out == p and actual.raw == bytes([expected]), "字面量替换不符")
                index += 1
            expanded += 1
        else:
            actual = new.tokens[index]
            require((actual.literal, actual.out, actual.size, actual.raw) ==
                    (token.literal, token.out, token.size, token.raw), "未受影响的官方 token 被改变")
            index += 1
            retained += 1
        for p in range(token.out, end):
            slot = (START + p) & 4095
            dirty.discard(slot)
            if p in changes:
                dirty.add(slot)
    require(index == len(new.tokens), "出现额外 token")
    require(old.orphan_flag == new.orphan_flag, "独立尾 flag 改变")
    tail_count = len(new.tokens) % 8
    expected_unused = old.unused_flags & ~((1 << tail_count) - 1) if tail_count else 0
    require(new.unused_flags == expected_unused, "最后 flag 未使用位改变")
    return dict(retainedTokens=retained, literalizedTokens=expanded, newMatches=0)


def verify_build(raw, patches):
    patches = normalize_patches(patches)
    original = official_bytes()
    oldparts, newparts = parse_container(original), parse_container(raw)
    require(len(raw) == len(original) and len(newparts) == len(oldparts) == 4, "容器结构/总长改变")
    require(newparts[0]["length"] == oldparts[0]["length"] == 0x707800, "首段长度改变")
    # 首头除 SUM 数字外，连空白及顺序也必须相同。
    scrub = lambda h: re.sub(rb"\bSUM=\d+\b", b"SUM=<sum>", h)
    require(scrub(oldparts[0]["header"]) == scrub(newparts[0]["header"]), "首头除 SUM 外有变化")
    for i in range(1, 4):
        require(oldparts[i]["header"] == newparts[i]["header"] and oldparts[i]["body"] == newparts[i]["body"], "ND1/IPL/PTBL 改变")
    oldbody, body = oldparts[0]["body"], newparts[0]["body"]
    reference_evidence = {row["section"]: row for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text(encoding="utf-8"))["results"]
        if row["version"] == "3.2-cn"}
    snapshot_evidence = json.loads((ROOT / "reports/container-and-decode-check.json").read_text(encoding="utf-8"))["decodeSemantics3_2"]
    oldtable, newtable = load_records(oldbody), load_records(body)
    oldlayout, newlayout = layouts(oldbody), layouts(body)
    require(oldtable.keys() == newtable.keys(), "段表名字改变")
    allowed_table = set()
    for name in oldtable:
        for key in oldtable[name]:
            if name in tuple(".ROM" + s for s in SECTIONS) and key == "size":
                continue
            require(oldtable[name][key] == newtable[name][key], f"段表字段改变：{name} {key}")
    permitted = bytearray(len(body))
    rows, all_diffs = [], []
    for name, before in oldlayout.items():
        after = newlayout[name]
        for key in before:
            if key not in ("packedSize", "slack"):
                require(before[key] == after[key], "ROM 起点/容量/明文长度改变")
        start, a, b = before["start"], before["packedSize"], after["packedSize"]
        old_packed, new_packed = oldbody[start:start + a], body[start:start + b]
        oldstream = parse_stream(old_packed)
        require(serialize_stream(oldstream) == old_packed, "官方 token 序列化自检失败")
        newstream = oldstream if old_packed == new_packed else parse_stream(new_packed)
        require(serialize_stream(newstream) == new_packed, "新流序列化自检失败")
        require(newstream.output_size == oldstream.output_size, "完整流输出长度/尾部改变")
        seq, snap = decode(oldstream, "sequential"), decode(oldstream, "snapshot")
        # 与已有独立库及原工具的映射明文逐字节交叉核对。
        reference = (ROOT / f"output/reference-decoded/body-3-2-cn/{name[1:]}.mapped.candidate.bin").read_bytes()
        full_reference = (ROOT / f"output/reference-decoded/body-3-2-cn/{name[1:]}.full.candidate.bin").read_bytes()
        upstream = (ROOT / f"output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.{start:08d}.decompressed").read_bytes()
        require(sha(reference) == reference_evidence[name]["mappedSha256"] and
                sha(full_reference) == reference_evidence[name]["decodedSha256"] and
                sha(upstream) == snapshot_evidence[name]["snapshotSha256"], "已有候选产物哈希改变")
        require(seq[:before["plainSize"]] == reference, "顺序明文与独立参考不一致")
        require(seq == full_reference, "完整顺序明文或尾部与独立参考不一致")
        require(snap == upstream[:len(snap)], "完整快照明文与原工具不一致")
        changes = section_changes(patches, name, before, seq)
        for p in changes:
            require(seq[p] == snap[p], "补丁字节不在语义无关掩码内")
        provenance_result = provenance(oldstream, newstream, seq, snap, changes)
        semantics = {}
        for sem, baseline in (("sequential", seq), ("snapshot", snap)):
            actual = baseline if newstream is oldstream else decode(newstream, sem)
            require(len(actual) == len(baseline), "解码长度改变")
            differences = [(i, x, y) for i, (x, y) in enumerate(zip(baseline, actual)) if x != y]
            require(differences == [(p, *changes[p]) for p in sorted(changes)], f"{sem} 明文差异超出补丁")
            semantics[sem] = dict(passed=True, decodedBytes=len(actual), mappedBytes=before["plainSize"],
                officialSha256=sha(baseline), newSha256=sha(actual), differingBytes=len(differences))
        for pos, (old, new) in sorted(changes.items()):
            all_diffs.append(dict(section=name, va=hex(before["va"] + pos), offset=hex(pos), orig_hex=f"{old:02x}", new_hex=f"{new:02x}"))
        if changes:
            permitted[start:start + b] = b"\x01" * b
        else:
            require(old_packed == new_packed, "无补丁子段压缩正文改变")
        if a != b:
            field = before["sizeField"]
            allowed_table.update(range(field, field + 4))
            permitted[field:field + 4] = b"\x01" * 4
        require(body[start + b:before["limit"]] == oldbody[start + b:before["limit"]], "ROM 尾部/未用填充改变")
        mask = bytes(x == y for x, y in zip(seq, snap))
        rows.append(dict(section=name, packedBytes=b, growth=b-a, availableSlack=before["slack"],
            serializationIdentical=True, semanticInvariantBytes=mask.count(1), semanticMaskBytes=len(mask),
            semanticMaskSha256=sha(mask),
            provenance=provenance_result, semantics=semantics))
        del oldstream, newstream, seq, snap
    raw_diff_count = 0
    for i, (old, new) in enumerate(zip(oldbody, body)):
        if old != new:
            raw_diff_count += 1
            require(permitted[i], f"允许区间外的正文变化：{i:#x}")
    require(body[0x17a0:0x17a4] == oldbody[0x17a0:0x17a4], "未识别 secinfo 末尾字改变")
    if not patches:
        require(raw == original, "零补丁包未逐字节等于官方")
    return dict(passed=True, inputSha256=OFFICIAL_SHA, outputSha256=sha(raw), outputBytes=len(raw),
        containerSections=[dict(index=i, bytes=p["length"], sum=p["sum"], sha256=sha(p["body"]),
            unchanged=i > 0 or p["body"] == oldbody) for i, p in enumerate(newparts)],
        headerOnlySumChanged=True, bodyLengthUnchanged=True, namedSectionsUnchanged=True,
        sectionTableOnlyPackedLengthsChanged=True, secinfoWordUnchanged=True,
        bodyDifferentBytes=raw_diff_count, changedPlainBytes=len(all_diffs), plainDifferences=all_diffs,
        sections=rows, zeroPatchIdentical=raw == original, nativeDecodeVerified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    path = args.manifest or args.firmware.with_name("manifest.json")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    raw = args.firmware.read_bytes()
    require(manifest["inputSha256"] == OFFICIAL_SHA and manifest["outputSha256"] == sha(raw), "manifest 哈希不符")
    from repack import checksum_audit
    require(manifest["secinfo"] == checksum_audit(), "manifest 校验字审计来源不符")
    result = verify_build(raw, manifest["patches"])
    require(manifest["verification"] == result, "manifest 验证结果不符")
    print(json.dumps(dict(passed=True, outputSha256=sha(raw), changedPlainBytes=result["changedPlainBytes"],
        namedSectionsUnchanged=result["namedSectionsUnchanged"], sections=[
            dict(section=r["section"], growth=r["growth"], semanticsPassed=list(r["semantics"])) for r in result["sections"]]), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
