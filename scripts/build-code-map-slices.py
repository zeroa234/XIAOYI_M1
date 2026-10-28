"""按函数边界与地址顺序拼接反编译文本，生成供分批阅读的中文索引。"""
from pathlib import Path
import argparse
import csv
import json
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parents[1]


def read_tsv(path):
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t", quoting=csv.QUOTE_NONE)
        return reader.fieldnames, list(reader)


def write_tsv(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fields, delimiter="\t", quoting=csv.QUOTE_NONE,
                                quotechar=None, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def safe_comment(text):
    return text.replace("*/", "* /")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "output/code-map")
    parser.add_argument("--output", type=Path, help="默认 INPUT/slices；目录必须为空")
    parser.add_argument("--target-kb", type=float, default=320, help="每片期望 UTF-8 字节数，1 KB=1024 B")
    parser.add_argument("--min-slices", type=int, default=40)
    parser.add_argument("--max-slices", type=int, default=60)
    parser.add_argument("--allow-partial", action="store_true", help="仅用于小范围试跑，跳过未反编译的目录行")
    args = parser.parse_args()
    source = args.input.resolve()
    out = (args.output or source / "slices").resolve()
    if not source.is_relative_to(ROOT) or not out.is_relative_to(ROOT / "output"):
        raise ValueError("输入必须在项目内；输出必须在项目 output/ 内")
    if not 1 <= args.min_slices <= args.max_slices or args.target_kb <= 0:
        raise ValueError("分片数量/大小参数错误")
    if out.exists() and any(out.iterdir()):
        raise ValueError("输出目录必须为空，避免旧分片混入")
    fields, functions = read_tsv(source / "functions.tsv")
    _, strings = read_tsv(source / "strings.tsv")
    print(f"已读取目录：{len(functions)} 个函数，{len(strings)} 条字符串", flush=True)
    by_function = defaultdict(list)
    for string in strings:
        for function in filter(None, string["functions"].split(";")):
            by_function[function].append(string)
    functions.sort(key=lambda f: int(f["entry"], 16))
    entries = [f["entry"] for f in functions]
    if len(set(entries)) != len(entries):
        raise ValueError("函数目录有重复入口")
    available = {p.stem for p in (source / "decompiled").glob("*.c")}
    missing, extra = set(entries) - available, available - set(entries)
    if extra or (missing and not args.allow_partial):
        raise ValueError(f"反编译覆盖不完整：缺少 {len(missing)} 个，多余 {len(extra)} 个")
    items = []
    for ordinal, f in enumerate(functions, 1):
        if f["entry"] not in available:
            continue
        code = (source / "decompiled" / (f["entry"] + ".c")).read_text(encoding="utf-8")
        brief = " | ".join(s["address"] + ":" + s["text"][:160] for s in by_function[f["entry"]][:6])
        header = (f"\n/* 函数 0x{f['entry']}；末地址 0x{f['end']}；函数体 {f['body_bytes']} 字节；"
                  f"调用者 {f['caller_count']} 个；名称 {safe_comment(f['name'])}。\n"
                  f" * 引用字符串摘要：{safe_comment(brief) or '无静态可解析字符串'}\n */\n")
        content = header + code + ("\n" if not code.endswith("\n") else "")
        items.append((f, content, len(content.encode("utf-8"))))
        if ordinal % 5000 == 0:
            print(f"已读取 C 文件：{ordinal}/{len(functions)}", flush=True)
    if not items:
        raise ValueError("没有可分片函数")
    total_bytes = sum(item[2] for item in items)
    count = min(len(items), max(args.min_slices, min(args.max_slices, round(total_bytes / (args.target_kb * 1024)))))
    # 逐片以剩余总量/剩余片数为目标，选择最近的函数边界；大函数始终完整。
    groups = []
    cursor, remaining_bytes = 0, total_bytes
    for number in range(count):
        remaining_groups = count - number
        target = remaining_bytes / remaining_groups
        group, size = [], 0
        while cursor < len(items):
            item = items[cursor]
            if group and remaining_groups > 1:
                if len(items) - cursor == remaining_groups - 1 or abs(size - target) <= abs(size + item[2] - target):
                    break
            group.append(item)
            size += item[2]
            cursor += 1
        groups.append(group)
        remaining_bytes -= size
    assert cursor == len(items) and all(groups)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for number, group in enumerate(groups, 1):
        folder = out / f"slice-{number:02d}"
        folder.mkdir()
        write_tsv(folder / "index.tsv", fields, [item[0] for item in group])
        content = "".join(item[1] for item in group)
        (folder / "code.c").write_text(content, encoding="utf-8", newline="\n")
        used, frequency = {}, Counter()
        for f, _, _ in group:
            for string in by_function[f["entry"]]:
                used[string["address"]] = string
                frequency[string["address"]] += 1
        ordered = sorted(used.values(), key=lambda s: int(s["address"], 16))
        (folder / "strings.txt").write_text("地址\t长度\t文本（反斜杠转义）\n" +
            "".join(f"{s['address']}\t{s['length']}\t{s['text']}\n" for s in ordered), encoding="utf-8", newline="\n")
        top = sorted(frequency, key=lambda a: (-frequency[a], int(a, 16)))[:10]
        keywords = " | ".join(f"{frequency[a]}× {a}:{used[a]['text'][:160]}" for a in top)
        manifest.append({"slice": f"slice-{number:02d}", "start": group[0][0]["entry"],
                         "end": f"{max(int(item[0]['end'], 16) for item in group):08x}",
                         "function_count": len(group), "c_bytes": len(content.encode("utf-8")),
                         "string_count": len(used), "keywords": keywords})
    write_tsv(out / "manifest.tsv", list(manifest[0]), manifest)
    summary = {"slices": len(manifest), "functions": len(items), "missing_functions": len(missing),
               "c_bytes": total_bytes, "min_slice_bytes": min(m["c_bytes"] for m in manifest),
               "max_slice_bytes": max(m["c_bytes"] for m in manifest), "target_kb": args.target_kb,
               "requested_slice_range": [args.min_slices, args.max_slices],
               "over_400kb": [m["slice"] for m in manifest if m["c_bytes"] > 400 * 1024],
               "under_250kb": [m["slice"] for m in manifest if m["c_bytes"] < 250 * 1024]}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
