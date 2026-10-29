# 离线覆盖与系统候选验证

> **事故后状态：3.2-d1 已撤回，请勿刷写。** 本文保留离线研究阶段的证据与命令；参见[事前声明](../docs/pre-use-disclaimer.md)及[事故记录](firmware-incident-2026-10-29.md)。软件检查通过不代表硬件可启动。

日期：2026-10-29。没有连接或控制相机，没有刷写，没有向外部发送现场资料。

## 全量现有分析材料

`scripts/verify-offline-catalog.py` 复用了既有 `temp/verify-code-map.py` 的核对规则，新增原始字符串文本逐字节匹配、当前源工程重新哈希、逐函数 SHA-256 索引及反编译警告/循环文本索引。它使用 Python 标准库；不实现反编译器、压缩算法或缺陷判断器。

- 27,107 个函数文件，28,959,543 字节 C，目录、timings、文件集合相符。
- 107,849 条字符串的地址、长度、NUL、可打印字节及转义文本与参考解码输入一致。
- 60 片及 99 片两套材料均覆盖全部目录函数，函数内容、顺序、字符串集合相符。
- 三个候选段哈希与既有独立参考报告一致；当前 Ghidra 源工程全部已记录文件的哈希与导出后记录一致。
- 27 个已标注 outline helper 的记录状态相符。
- 全量文本扫描索引到 2,722 个含警告或无限循环文本的函数，共 4,925 条 `WARNING:`、1,509 处 `while (true)`。这是待审查索引，不是缺陷或实际死循环数量。

机器结果：`reports/offline-catalog-verification-2026-10-29.json`。逐函数哈希和待审查索引在 `output/offline-audit-2026-10-29/`。新增扫描覆盖现有目录全部函数，不能证明不存在未识别代码、间接调用、错误函数边界或反编译失真。

独立审查后增加调用图反向完整性核对并重跑：每个目录函数的入边总数都与完整 callee 集合重建结果一致，未截断 caller 集合完全一致；41 条指向非目录入口的边保留并报告。复核版输出为 `output/offline-audit-2026-10-29-reviewed/`，逐函数哈希索引摘要与初次完全相同；机器结果报告已更新为该次更严格结果。

`scripts/audit-unrecognized-targets.py` 另外用 Capstone 核对目录遗漏的全部 5 个直接调用入口与 7 个调用点，保存各入口 64 字节原指令及两种解码窗口的一致性。结果为 `reports/unrecognized-target-audit-2026-10-29.json`。没有擅自创建函数或按普通 ABI 推断这些片段；尤其不得遗漏共享助手对寄存器和标志的影响。

## 回归执行

| 命令 | 本次结果 |
| --- | --- |
| `python -B tests/test-repack.py` | 17 项通过，包含零补丁与官方逐字节相同 |
| `python -B tests/test-liveview-metadata.py` | 9 项通过 |
| `python -B tests/test-liveview-capture.py` | 3 项通过，仅 127.0.0.1 本地 HTTP/UDP 夹具 |
| `python -B tests/test-exposure-probe.py` | 11 项通过，人工夹具 |
| `python -B scripts/check-command-bounds.py` | 106 个原 ARM / 补丁隔离用例通过 |
| `python -B scripts/audit-unrecognized-targets.py` | 5 个目标、7 个原始直接调用点相符 |
| `python -B scripts/verify-offline-catalog.py --output output/offline-audit-2026-10-29` | 全量材料核对通过 |

测试文件名含连字符，`unittest discover` 初次未发现用例（0 项），不计为通过；已按上述文件分别运行。回环采集测试第一次被沙箱禁止套接字而失败，已核对只连接 127.0.0.1 后在允许本机套接字的执行环境重跑，3 项全部通过。没有相机网络请求。

## 可识别的系统保守候选

`output/firmware-builds/offline-system-3-2cn-v1/firmware.bin`：

- 基于原官方 3.2-cn；版本文本为 `3.2-s1`，包头 VER、M1CN 型号、IPL、ND1、PTBL 保持原值。
- 仅加入已验证的远程命令搜索上限修补和三处等长版本文本；明文共改变 8 字节。
- 原包文件实际共 11 字节不同：上述 8 字节，加上随段体内容重新计算的 SUM 的 3 位数字；没有遗漏包头变化。
- `.text/.rodata/.data` 三条压缩流均无增长，起点、容量、总包长不变。
- 构建内验证及独立从磁盘重新解析验证均通过；保留原 token 来源，并在顺序/快照两种复制语义下检查全部明文差异。
- SHA-256：`f7cf40d43dd0cdbc502b54db92562fbef71cebef2a699f4a82bac1b1320f7019`。

构建命令：

```powershell
python -B scripts/repack.py --name offline-system-3-2cn-v1 --patches config/patches/command-bounds.json config/patches/offline-system-identity.json
python -B scripts/verify-build.py output/firmware-builds/offline-system-3-2cn-v1/firmware.bin
```

构建器拒绝覆盖已存在的构建；复现时改用新的 `--name`。完整字节差异、来源和段统计见 `reports/offline-system-build-2026-10-29.json`，构建 manifest 与二进制同目录。

这是理论系统修补候选，不是已证实的提速、AF 或随机挂死修复。未知 secinfo 字仍原样保留，原生硬件解码、安装、启动、菜单版本显示及整机效果尚未验证；已有恢复路径限制仍适用。此包没有混入上次用户报告无曝光预览效果的实验补丁。
