# 主程序全量代码目录与分片导出

本流水线只读取已经分析的 `text.mapped.candidate.bin` Ghidra 工程，生成供只读代理通读的目录、反编译 C 和地址连续分片。不修改、打包固件，不连接相机。输入依然是候选解码语义，不代表已由相机实测验证。

## 重跑

在仓库根目录使用 Python 3、`reports/toolchain-installed.json` 指定的 Ghidra 12.2 / Java 25。输出目录必须为空；重跑可改用新的 `--output` 目录，避免混入旧文件。

```powershell
$env:TEMP = "$PWD/temp/ghidra-tmp"
$env:TMP = $env:TEMP
$env:PYTHONPYCACHEPREFIX = "$PWD/temp/python-cache"
$env:PYTHONIOENCODING = 'utf-8'
New-Item -ItemType Directory -Force $env:TEMP | Out-Null

# 先验证 200 个函数；函数目录和字符串目录仍覆盖全量。
python scripts/export-code-map.py --output output/code-map-trial-new --limit 200 --timeout 45
python scripts/build-code-map-slices.py --input output/code-map-trial-new --allow-partial --min-slices 2 --max-slices 3

# 后台导出全量；可根据 PID、console.log 的 PROGRESS 和逐函数 timings 确认进展。
Start-Process -FilePath python -ArgumentList 'scripts/export-code-map.py','--output','output/code-map' -WorkingDirectory $PWD -WindowStyle Hidden -RedirectStandardOutput 'temp/code-map-launch.log' -RedirectStandardError 'temp/code-map-launch.err' -PassThru
Get-Content output/code-map/console.log -Tail 15

# 必须等 summary.json 和 run-verification.json 都生成且验证通过，再做全量分片。
python scripts/build-code-map-slices.py
```

`--limit 0` 表示全量；`--timeout` 可选 30–60 秒，默认每函数 45 秒。`--start 0x地址` 只限制反编译起点，目录仍然覆盖全部函数。局部试跑不能当作全量结果；分片器默认拒绝缺失或多余的 `.c` 文件，只有显式 `--allow-partial` 才跳过缺失文件。

## 工程与临时文件保护

`scripts/export-code-map.py` 先对源工程 `.gpr` 与 `.rep` 所有文件做 SHA-256 快照，将工程复制到唯一的 `temp/ghidra-catalog-project-*` 目录，再用 `-process text.mapped.candidate.bin -readOnly -noanalysis` 打开副本。所有运行时缓存、Java 用户目录、偏好、临时文件及 TMP/TEMP/TMPDIR 均指向项目内 `temp/ghidra-*`；日志放入本次输出目录。不会调用现有 focus 导出器中的清理或函数创建逻辑。

Java 导出器只在内存事务内设置已核验大小的 outline helper 的 `inline` 属性，结束时回滚事务；headless 的 `-readOnly` 再提供一层不保存保护。源工程从未被 Ghidra 打开，运行结束后逐文件哈希复核。`run-verification.json` 记录源工程前后哈希、是否完全一致，以及临时副本中变化的文件列表（若 Ghidra 产生锁、索引或日志，也只会落在临时副本）。临时副本保留供审计，不自动删除。

运行器同时检查退出码和 `summary.json`；Ghidra 某些脚本异常仍会返回 0，不能单凭进程退出码宣告完成。

## 输出格式

所有文本 UTF-8；地址均为无 `0x` 的 8 位小写十六进制，长度和计数为十进制。TSV 不使用引号转义，文本中的反斜杠、制表符、CR、LF 分别写成 `\\`、`\t`、`\r`、`\n`。用 Python `csv` 读取时指定 `delimiter='\t', quoting=csv.QUOTE_NONE`，不要自动反转义反斜杠。列表地址以 `;` 分隔。

| 路径 | 内容 |
| --- | --- |
| `output/code-map/functions.tsv` | `.text` 中所有现有函数，按入口排序。`entry/end` 是入口与函数体最大地址（末端包含）；`body_bytes` 是地址集合大小，不等同于两端之差；`instruction_count` 是 Ghidra 已识别指令数。 |
| 同上调用图列 | `caller_count/callee_count` 按唯一入口/目标地址计数，不是调用点次数；`callers` 最多 20 个；`callees` 不截断。直接流中的调用目标可以不是已识别函数。 |
| 同上数据列 | `strings` 最多 30 条 `地址:文本`，`string_addresses` 为对应地址；`ram_globals` 为 `c0000000 ≤ 地址 < d0000000`，`mmio` 为 `20000000 ≤ 地址 < 40000000`，两者最多 100 个；`string_count/ram_count/mmio_count` 为截断前数量。`name` 保留当前工程函数名。 |
| `decompiled/<entry>.c` | 每个目录函数一个文件；失败时写中文说明、错误消息及函数体完整的已识别指令反汇编注释，仍保持 `.c` 容器可拼接。 |
| `failures.tsv` | 入口、耗时秒、失败或超时原因、替代文本路径。无失败时只有表头。 |
| `strings.tsv` | `.rodata/.data` 中所有非空、NUL 结尾的可打印 ASCII 连续串（包括 TAB/CR/LF），最短 1 字节；地址、字节长度、文本、引用函数完整列表。独立扫描原始块，不要求 Ghidra 已定义字符串。 |
| `unrecognized-call-targets.tsv` | `.text` 已识别 BL/BLX 指令的直接目标中，没有精确函数入口的地址；记录所有调用点、目标所在函数（若有）及“未创建函数”标记。 |
| `inline-helpers.tsv` | 与 `ExportM1Focus.java` 同源的 27 个 helper 地址、核验体积、实际内存标注状态。缺失或体积不符不会新建函数或盲目内联。 |
| `decompile-timings.tsv` | 每函数耗时、成功/失败、文件 UTF-8 字节数；逐函数刷新，可观察进度。 |
| `summary.json` | 全量目录数量、本次反编译成功/失败、字符串与未识别调用目标数、文本体积、目录和总导出耗时。 |
| `run-inputs.json` / `run-verification.json` | 完整命令、源工程哈希及只读复核，后者 wall_seconds 包括工程复制、JVM 启动及复核。 |
| `catalog-original/`、`catalog-refresh/`、`catalog-refresh.json` | 本次目录修正的原始目录备份、刷新运行证据、最终目录哈希与变化入口清单；正常重跑最终版本脚本无需刷新步骤。 |
| `validation.json` | 本次全量覆盖、原始字符串字节、调用图、截断计数、分片 C 完整性和工程哈希验证结果。验证用一次性脚本在 `temp/verify-code-map.py`，不纳入 git。 |

函数字符串引用来源：Ghidra 指令数据引用；`.text` 字面量池、`.rodata/.data` 对齐 32 位指针最多两级追踪；单条指令 p-code 内常量传播、LOAD 和 PC 相对加减（包括 ADR / `add rX,pc`）。指向字符串内部的引用归并至扫描得到的字符串起点。`strings.tsv` 的函数列表在截断之前建立，因此分片字符串文件可以保留每个函数的全部已解析字符串，而不局限于目录显示的前 30 条。

## 分片规则

`scripts/build-code-map-slices.py` 默认以每片 320 KiB 为期望，先按总文本量计算片数并限制在 40–60，再按地址、函数完整边界将剩余文本量均衡分配。`--target-kb`、`--min-slices`、`--max-slices` 可调。每个函数前写入地址、函数体字节数、调用者数、函数名及最多 6 条字符串摘要；注释中的 `*/` 会转义为 `* /`。默认尽量落在每片约 250–400 KiB，完整大函数或总量与片数约束冲突时不会截断函数；`slices/summary.json` 如实列出超出区间的分片。

若实际总文本超过 60 × 400 KiB，两项约束无法同时满足。主目录优先保留 40–60 片；可另生成更小的阅读副本（放宽片数），不会删减函数内容：

```powershell
python scripts/build-code-map-slices.py --output output/code-map/slices-320k --target-kb 320 --min-slices 1 --max-slices 200
```

每片 `slice-NN/index.tsv` 保留完整原目录列，`code.c` 按地址拼接全部函数 C/失败替代文本，`strings.txt` 按字符串地址去重。`manifest.tsv` 包含片号、起止地址、函数数、带注释的 C 字节数、字符串数、被本片不同函数引用最多的 10 条字符串及引用次数（各提示文本最多 160 字符）。地址跨度不意味着不存在未识别代码或间隙；非连续函数体也可能令片的起止跨度重叠。

## 已知限制与阅读建议

- 候选解码使用 `ARM:LE:32:v5t` 标准语义。自动分析可能将数据误判为代码、漏认函数、切错边界或漏掉间接调用。此目录覆盖工程内已有 `.text` 函数，不承诺恢复所有实际机器代码；未识别 BL 目标单独保留，没有擅自补建函数。
- outline helper 会修改调用者寄存器、SP 或标志。忽略它们会令 C 丢失重要语义；本次保留与 focus 脚本一致的清单并临时内联，反编译仍不可替代指令核对。必须查看 `inline-helpers.tsv` 是否有异常状态。
- 数据地址与字符串关联是静态启发式。单条指令之外不做寄存器数据流传播，动态字符串、UTF-8 中文、UTF-16、运行时组装、间接指针表或跨指令构造地址可能漏掉。只按数值范围识别 RAM/MMIO，掩码和普通常数可能误报；短串也可能是二进制偶然形成的可打印片段。
- 调用图主要依据 Ghidra 已识别指令的静态调用流，不含无法解析的函数指针调用、尾跳转、异常流和未反汇编代码；调用者数低不表示函数没有被使用。
- `.c` 是阅读材料，类型、参数、结构体及变量名大多未经人工核验，不能直接当作可编译的原项目源码。超时/失败有反汇编替代，成功也可能含反编译警告。按分片进行子系统标注时，应记录证据地址与不确定性，并查阅 `reports/*.md` 的既有结论。

## 本次运行记录（2026-10-27）

全量启动前的试跑：`output/code-map-trial-200-v2/`，200 个入口函数全部成功，0 失败；工程内共有 27,107 个函数。Java 导出 11.57 秒，其中目录扫描 9.39 秒、反编译约 2.18 秒；连同工程复制、JVM 启动和复核，墙钟 21.07 秒。按反编译阶段线性外推，预计全量约 5 分钟；首段函数复杂度不代表后续，启动前预留范围为 5–20 分钟。每函数 45 秒硬性超时仍可能使实际耗时超出估算。

试跑验证覆盖：目录地址唯一与排序、每个字符串在原候选块中的实际 NUL 结尾及可打印字节、30/20 条截断、字符串反向引用、200 个函数的分片无遗漏无重复、27 个 helper 全部体积匹配、源工程与临时工程逐文件哈希不变。初版试跑发现 Java 条件表达式对空值自动拆箱导致异常，已修复；失败记录留在 `output/code-map-trial-200/`，未参与最终输出。

全量 C 生成期间又修正了目录提取中的短串/指针歧义：32 位指针可能恰好表现成 NUL 结尾的 1–3 字节 ASCII 短串，现在保留短串候选并继续追踪该指针。重新只读导出全量目录并验证 200 个函数，最终目录来自 `output/code-map-catalog-final/`；这项修正仅影响目录引用，不影响反编译，保留首次全量 C，另记录目录刷新来源与哈希。原始全量目录在输出目录内留存以供比较。

全量结果：

| 项目 | 结果 |
| --- | --- |
| `.text` 现有函数 | 27,107 |
| 反编译成功 / 失败 / 超时 | 27,107 / 0 / 0 |
| 未识别直接 BL 目标 | 5：`000417b8`、`00044bbc`、`00046b48`、`00046bbc`、`00168fc8`；均未创建函数 |
| ASCII 字符串 | 107,849：`.rodata` 99,444，`.data` 8,405；包括短串及二进制误候选 |
| 原始逐函数 C 总量 | 28,959,543 字节 |
| 分片 C 总量（含阅读注释头） | 32,512,932 字节 |
| 全量 Java 导出耗时 | 432.44 秒（7 分 12 秒），其中目录 10.32 秒 |
| 全量命令墙钟耗时 | 439.66 秒（7 分 20 秒），含复制、启动和工程哈希复核；在启动前 5–20 分钟预估内 |
| 最慢单函数 | `00268360`，31.46 秒；未达到 45 秒超时上限 |
| 目录修正复核 | 与全量 C 并行，墙钟 23.09 秒；更新 30 个函数目录行，额外解析 12 条函数到字符串关联；200 个试跑 C 文件逐字节相同 |
| 主分片 | 60 片，534,563–573,674 字节/片（约 522–560 KiB） |
| 小分片阅读副本 | 99 片，295,286–355,365 字节/片（约 288–347 KiB），全部落在 250–400 KiB 范围 |
| 成功重跑分片耗时 | 两套并行，各约 6.5 秒（文件缓存已热）；首次分片读文件更慢且触发下述 TSV 问题，不计入全量 Ghidra 墙钟 |
| 源工程 / 临时工程副本 | 全部运行前后逐文件哈希一致；临时工程变化列表为空，无残留锁文件 |

主 manifest 为 `output/code-map/slices/manifest.tsv`；细分阅读版为 `output/code-map/slices-320k/manifest.tsv`。完整文本总量大于 60 × 400 KiB，无法同时满足 40–60 片与 250–400 KiB；两套目录分别满足片数和阅读体积约束，均保留每个函数且不截断函数。多代理阅读建议选用 99 片版本。

首次全量分片遇到含双引号字符串的 TSV 写出异常，已将无引号 TSV 写出器的 `quotechar` 设为 `None`，并通过双引号、反斜杠及中文的往返读取验证后重跑；失败的部分分片移至项目 `temp/code-map-failed-slices*`，不混入最终输出。两套最终分片均需通过 `validation*.json` 的覆盖核验；导出失败的反汇编替代分支本次没有实际触发，不能据此宣称已在真实超时案例中验证。
