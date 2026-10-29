# 2026-10-29 研究更新

先阅读[事前声明](pre-use-disclaimer.md)。**3.2-d1 已撤回，不能刷写；本仓库不提供固件下载。**

| 方向 | 本轮结果 | 阅读入口 |
|---|---|---|
| 事故披露 | 集成候选刷写后无法开机，尚未恢复 | [事故记录](../reports/firmware-incident-2026-10-29.md) |
| 原因候选 | 初始字典依赖与软件零初值盲区，根因未确认 | [原因审计](../reports/failed-demo-cause-audit-2026-10-29.md) |
| 保守候选 | 3.2-s1 仅 8 字节明文修改，仍未上机 | [复核](../reports/conservative-package-review-2026-10-29.md) |
| 主程序材料 | 核对 27,107 个函数及 107,849 条字符串 | [材料验证](../reports/offline-validation-2026-10-29.md) |
| 实际覆盖 | 996,542 条已定义指令、222,538 个未定义字节、860 个间接调用点 | [覆盖与错误路径](../reports/main-coverage-and-error-review-2026-10-29.md) |
| 嵌套载荷 | ARM 子 CPU、蓝牙 HCD、WLAN 候选窗口 | [复核](../reports/embedded-offline-review-2026-10-29.md) |
| 曝光链 | AE 下游、调用者与输出路径，仍缺整机验证 | [曝光复核](../reports/exposure-offline-review-2026-10-29.md) |
| 证据勘误 | 调用者、覆盖及子代理结论的修正 | [复核发现](../reports/offline-review-findings-2026-10-29.md) |

新增 `audit-failed-demo-stream.py`、`audit-failed-demo-loader.py`、`audit-failed-demo-patch-gate.py` 仅审计本地文件及 Unicorn 模型，不提供恢复功能。失败镜像不分发，也不要求通过再次刷写来复现事故。

报告中的 40 项测试、106 个命令隔离用例、58 个 AE 下游用例、32 个错误尾部用例及 22 个新曝光局部用例，是既有私人工作区的历史结果。本次公开更新仅重跑无需固件的合成测试、源码解析及发布检查，不重跑完整 Ghidra 或设备实验。具体结果见[发布检查](../reports/publication-checks-2026-10-29.json)。

原始子代理笔记、私人会话、音效、现场资料及二进制输出不公开。主代理复核后的结论优先；报告提及的未分发工程、反编译输出和临时文件，需要独立准备或仅作为证据身份记录理解。
