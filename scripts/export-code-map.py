"""从已分析工程的临时副本只读导出；全部运行状态留在项目内。"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "m1-3-2-candidate"


def snapshot(folder):
    hashes = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            with path.open("rb") as stream:
                hashes[path.relative_to(folder).as_posix()] = hashlib.file_digest(stream, "sha256").hexdigest()
    return hashes


def inside(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("路径必须在项目内")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/code-map")
    parser.add_argument("--limit", type=int, default=0, help="0 表示全量；试跑用 200")
    parser.add_argument("--timeout", type=int, choices=range(30, 61), default=45)
    parser.add_argument("--start", default="0x2000", help="反编译起始地址；目录始终全量")
    parser.add_argument("--coverage-only", action="store_true", help="只读导出精确地址集合覆盖，不反编译")
    parser.add_argument("--max-cpu", type=int, choices=range(1, 5), default=4)
    args = parser.parse_args()
    out = inside(args.output)
    if not out.is_relative_to(ROOT / "output"):
        raise ValueError("导出必须在 output/ 下")
    if out.exists() and any(out.iterdir()):
        raise ValueError("输出目录必须为空，避免旧结果混入")
    if args.limit < 0:
        raise ValueError("limit 必须非负")
    int(args.start, 0)
    if args.coverage_only and (args.limit != 0 or args.timeout != 45 or int(args.start, 0) != 0x2000):
        raise ValueError("coverage-only 覆盖完整 .text，不接受 limit/timeout/start 的非默认值")
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()
    paths = {n: ROOT / "temp" / ("ghidra-" + n) for n in ("user", "settings", "cache", "tmp")}
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    tools = {row["kind"]: Path(row["directory"]) for row in json.loads(
        (ROOT / "reports/toolchain-installed.json").read_text(encoding="utf-8"))}
    for path in tools.values():
        if not (path.parent / ".verified-source.json").exists():
            raise ValueError("工具缺少来源核验标记")
    source = ROOT / "output/ghidra-projects"
    # 源工程只读访问；临时副本承接 Ghidra 工程元数据、锁和日志。
    def source_snapshot():
        return {**{PROJECT + ".rep/" + k: v for k, v in snapshot(source / (PROJECT + ".rep")).items()},
                PROJECT + ".gpr": hashlib.sha256((source / (PROJECT + ".gpr")).read_bytes()).hexdigest()}
    before = source_snapshot()
    work = ROOT / "temp" / ("ghidra-catalog-project-" + str(time.time_ns()))
    work.mkdir()
    shutil.copy2(source / (PROJECT + ".gpr"), work)
    shutil.copytree(source / (PROJECT + ".rep"), work / (PROJECT + ".rep"))
    work_before = snapshot(work)
    launch = []
    for line in (tools["ghidra"] / "support/launch.properties").read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("VMARGS", "VMARGS_WINDOWS"):
            launch.append(value)
    command = [str(tools["java"] / "bin/java.exe"), *launch, "-Xmx4G", "-Djava.awt.headless=true",
               f"-Duser.home={paths['user']}", f"-Dapplication.settingsdir={paths['settings']}",
               f"-Dapplication.cachedir={paths['cache']}", f"-Dapplication.tempdir={paths['tmp']}",
               f"-Djava.io.tmpdir={paths['tmp']}", f"-Djava.util.prefs.userRoot={paths['settings'] / 'prefs'}",
               "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2", "-cp",
               str(tools["ghidra"] / "Ghidra/Framework/Utility/lib/Utility.jar"), "ghidra.Ghidra",
               "ghidra.app.util.headless.AnalyzeHeadless", str(work), PROJECT,
               "-process", "text.mapped.candidate.bin", "-readOnly", "-noanalysis",
               "-scriptPath", str(ROOT / "scripts/ghidra"), "-postScript",
               "AuditM1Coverage.java" if args.coverage_only else "ExportM1Catalog.java",
               str(out), str(args.limit), str(args.timeout), args.start, "-max-cpu", str(args.max_cpu),
               "-log", str(out / "ghidra.log"), "-scriptlog", str(out / "ghidra-script.log")]
    env = os.environ.copy()
    env.update(TEMP=str(paths["tmp"]), TMP=str(paths["tmp"]), TMPDIR=str(paths["tmp"]),
               PYTHONPYCACHEPREFIX=str(ROOT / "temp/python-cache"))
    (out / "run-inputs.json").write_text(json.dumps({"command": command, "source_project_sha256": before,
        "qualification": "候选解码的静态分析，非相机验证；不修改或打包固件；工程临时副本只读运行。"},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (out / "console.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    after = source_snapshot()
    work_after = snapshot(work)
    changed = [k for k in sorted(work_before.keys() | work_after.keys()) if work_before.get(k) != work_after.get(k)]
    report = {"exit_code": result.returncode, "wall_seconds": time.time() - started,
              "source_project_unchanged": before == after, "source_project_sha256_before": before,
              "source_project_sha256_after": after, "temporary_project": str(work),
              "temporary_project_changed_files": changed}
    (out / "run-verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if before != after:
        raise RuntimeError("源工程哈希发生变化")
    if result.returncode or not (out / "summary.json").exists():
        raise RuntimeError("导出未完成，请检查 console.log（headless 脚本出错时也可能返回 0）")


if __name__ == "__main__":
    main()
