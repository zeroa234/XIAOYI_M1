# M1 专用 REA 处理器配置

2026-10-26。用户要求将 M1 的处理器选择固定到专用配置，并继续保留通用 REA。

## 架构证据的范围

原始 3.2-cn `firmware.bin` 文件偏移 `0xb19868`、`0xb19874` 分别含 `ARM926_1`、`ARM926_2`；同一区域还有 `ARM9`。这些是固件载入/分区标识，不是从真机读取的 CPU ID，也不能证明整个相机只有一种核心。

[ARM926EJ-S 官方手册](https://documentation-service.arm.com/static/5e8e3d1088295d1e18d3a9b2) 将该处理器的架构列为 ARMv5TEJ。结合现有 ARM/Thumb 代码解析与隔离执行结果，本项目明确选择 `ARM:LE:32:v5t` 作为候选固件的分析模型。不能把“能用此模型分析/仿真”反过来当作芯片身份的独立证明。先前把 M1 实际架构直接说成已确认 ARMv5 的表达过于确定。

## 固定方式

工作区共享安装 `extensions/mcp/rea` 新增 `scripts/rea-m1-wsl.sh`。只使用 REA 已有的环境变量覆盖：

```bash
REA_GHIDRA_LANGUAGE_ID=ARM:LE:32:v5t
REA_GHIDRA_COMPILER_SPEC_ID=default
```

Ghidra 安装的 ARM 语言定义为该语言提供通用 ARM/Thumb v5 little endian 模型及 `default` compiler spec，并列有 `armv5tej` 外部别名。这里的 compiler spec 仍是分析约定，未声称恢复原固件编译 ABI。

服务划分：

| 服务 | 用途 | 处理器选择 |
| --- | --- | --- |
| `rea` | 其他程序/固件的通用分析 | 继续自动识别 |
| `rea-m1` | 本项目 M1 候选固件分析 | 固定 `ARM:LE:32:v5t` |

两者共用同一套 REA/Node/JDK/Ghidra，各自运行独立 MCP 会话。Codex、Pi 和 `extensions/.mcp.json` 已登记专用入口；未修改 Claude。

## 实际验证

用 GNU 工具把此前已核实的 5036 字节曲线代码片段，以及原常量节中 8 字节 bank 偏移表，包装为只供分析的 ELF。经专用入口调用原版 REA/Ghidra，返回的分析 profile 实际记录：

- `language_id=ARM:LE:32:v5t`。
- `compiler_spec_id=default`。
- `0x41ef2c` 函数 232 字节、58 条指令，与既有检查一致。

Windows→WSL 的专用 MCP initialize、229 个工具清单与 `binary_session` 查询通过。选定 Ghidra 范围的 doctor 通过；Pi 的连接结果另保存在安装目录的 `output/pi-mcp-list-m1.json`。结构化验证见 `reports/m1-analysis-profile-verification.json`，原始 dossier 在忽略的 `output/rea-arm-smoke/profile-function.json`。

此前完整 ELF 自动导入的日志实际显示 ARMv8。该导入在客户端中断后成为孤立进程，已核对目标路径、PID/PGID/会话及父进程后停止。没有把它的分析当作 ARMv5 结果。随后完整候选 ELF 已通过 `rea-m1` 以 ARMv5 模型完成分析，整块字节映射也已核对；见 `reports/rea-full-m1-stage.md`、`reports/rea-full-m1-verification.json`。这里的小样本验证与后续完整候选分析均不证明真实硬件身份或实际固件解码/刷机兼容。

这项配置针对 ELF 分析包装。REA raw ARM 导入仍使用其内置固定语言；不将外部覆盖宣称为已经改变 raw 导入行为。没有更改固件机器码或进行相机操作。
