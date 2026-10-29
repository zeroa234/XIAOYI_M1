# 嵌入映像的主代理复核

本轮补齐了原 `.text` 目录之外的离线分析对象。`scripts/verify-embedded-artifacts.py` 独立核对提取范围、源哈希、函数文件集合、失败计数、完整字符串原字节与音无线资料窗口，不执行或修改这些固件。

## 子 CPU

`@PDI` 头和主程序 loader 相符：945,664 字节 payload 复制到 `0xdfc90000`，SHA-256 `a48744ebf2e7f8c4fe895f8ddd7b4823dab82b7307acb19a185e31684579cc7a`。新建隔离 Ghidra 工程，没有修改主工程。

自动识别 12,940 个函数候选，成功反编译 12,869 个，失败 71 个均保留反汇编替代；20,647 条字符串的地址、字节、NUL 和转义文本与原 payload 相符。导出文件完整性通过。

这仍是启发式分析：payload 混有 ARM、Thumb 形态和嵌入 WLAN 内容，存在大量错误指令、函数边界、未解析调用及反编译警告。主代理逐 C 文件统计有 8,266 个文件含 `WARNING:`，共 20,175 条；与 Ghidra 控制台 7,345 条反编译警告是不同统计口径。不能把导出完整说成全部语义恢复或全部函数真实存在。

## 蓝牙与 WLAN

Pi 初稿将 `0x8411c8` 附近的 `BCM4343A1_...`、`BRCMcfgS/D` 归为 WLAN；主代理由原字节发现其后实际为 `4c fc ...` HCI 命令，并查现成 Linux/研究资料，要求更正。

更正后的结果：`0x8411e8..0x849e7d` 为 35,989 字节 HCD 风格 HCI 命令流，使用现成 Scapy `HCI_Command_Hdr` 核验 166 条 Write_RAM（0xFC4C）和 1 条 Launch_RAM（0xFC4E）。原字节提取 SHA-256 为 `17954ada9a88b21a51f4f82896779407862a11079e974127729dc29f7e928f85`。它是蓝牙 patchram 线索，不应再由远处 WLAN 字符串反向归属。Linux 的 Broadcom patchram 加载器也按 HCI 命令头及参数长度遍历固件；本项目未实际加载到设备。[Linux btbcm.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/bluetooth/btbcm.c)、[Broadcom 蓝牙 patchram 研究](https://arxiv.org/abs/2205.06114)

主 `.rodata` 的 `0x91b798..0x9afe18` 与 PDI 中 `0x4904d4..0x524b54` 两段候选窗口长 607,872 字节，仅末 4 字节不同。重复窗口证明资料重用，不能证明真实 WLAN 容器边界、装载地址或入口。初稿的 `boundary_proven=true` 和“逐字节相同”已经更正。AAC 仍只有标识/描述符，没有证明独立负载边界。

## 验证产物

- `reports/embedded-artifact-verification-2026-10-29.json`：12,940 个函数输出、20,647 条原始字符串、9 个无线研究提取窗口，全部与各自来源一致；`semanticVerification=false`。
- `reports/embedded-subcpu-analysis-2026-10-29.md`：完整运行与失败清单。
- `reports/pi-offline-radio-2026-10-29.md`：更正后的无线分类、HCI 边界与限制。
- 提取的二进制和 C 文件保留在 `output/`，不公开推送。
