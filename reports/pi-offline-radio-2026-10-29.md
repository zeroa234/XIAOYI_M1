# Broadcom BT HCD 与 WLAN/AAC 嵌入负载边界审计（2026-10-29，修正版）

> 本版修正上一版的两处关键错误：
> 1. **0x8411c8 不是可肯定的 WLAN 头**。其 NUL 后 0x8411e8 起是严格的 Broadcom HCI vendor `Write_RAM`（opcode 0xFC4C）流，首条命令写地址 0x00211810、数据以 `BRCMcfgS` 开头；第二条写 0x00211852、数据以 `BRCMcfgD` 开头，流终止于 `Launch_RAM`（0xFC4E）。上一版把同一 `.rodata` 内远处的 WLAN 字符串归到这个局部块，属错误归属。
> 2. **607,872 字节窗口不是“逐字节相同”**：主 `.rodata` 与 PDI 窗口有 607,868 字节相同，末尾 4 字节不同；重复窗口也不能当作真实 payload 起点。`boundary_proven` 已改为 **false**，仅称 near-identical candidate range。
>
> 只读、离线；未连接相机、未访问网络、未遥控、未刷写、未改代码/输入、未 git 提交。机器可读结果：`reports/pi-offline-radio-2026-10-29.json`；提取：`output/embedded-radio-2026-10-29/`；脚本：`temp/pi-offline-radio/build_radio.py`。

## 0. 结论摘要

1. **0x8411c8 是 BT HCD/patchram 的版本元数据，不是 WLAN 头。**
   - 版本串 `BCM4343A1_001.002.009.0043.0178` 位于 0x8411c8–0x8411e7（32 字节含 NUL）。
   - 0x8411e8 起是 HCI 命令流：`4c fc 46` = opcode 0xFC4C、长度 0x46；随后 4 字节地址 `10 18 21 00` = 0x00211810，数据以 `BRCMcfgS` 开头。
   - 第二条在 0x841231：`4c fc ff` = 0xFC4C、长度 0xFF；地址 `52 18 21 00` = 0x00211852，数据以 `BRCMcfgD` 开头。
   - 0x84124b 的 `BCM4343WA1 37.4MHz Murata Type-1FJ BT4.1 OTP-BD-0043` 位于第二条 Write_RAM 的 payload 内，不是独立 WLAN 模块头。
2. **HCD 流已用 scapy 2.8.0 `HCI_Command_Hdr` 严格解析。**
   - 起止：0x8411e8–0x849e7d（35,989 字节，SHA-256 `17954ada9a88b21a51f4f82896779407862a11079e974127729dc29f7e928f85`）。
   - 167 条命令 = **166 条 0xFC4C Write_RAM + 1 条 0xFC4E Launch_RAM**。
   - 所有命令头 opcode/length 与 scapy 解析一致；最后一条在 0x849e76，`4e fc 04 ff ff ff ff`，长度 4、payload `ffffffff`；流止于 0x849e7d。
   - 总 `len` 字段和 = 35,488 字节；Write_RAM 的 4 字节地址之后的数据合计 **34,820 字节**。
   - 地址：166 个 Write_RAM 地址，min 0x000d6220、max 0x002194d7，全部唯一；156 个在 0x0021xxxx，10 个在 0x000dxxxx；地址不单调，116 个非 4 字节对齐（按原始字段记录，不强制对齐）。
3. **HCD 原字节可提取，但只称 “HCD-style raw HCI stream”。**
   - 已提取 `bt_hcd_patchram_0x8411e8_0x849e7d.bin`（35,989 字节）。
   - 该流直接从 vendor 0xFC4C 开始，没有初始 Reset；**Linux `.hcd` 兼容性未证明**，但命令顺序/长度/终点严格符合 HCI 流格式。
   - `BRCMcfgS`/`BRCMcfgD` 不是两个独立配置块，而是前两条 Write_RAM 的 payload；`BRCMcfgD` 内的 0x7ca4 长度由后续多条 Write_RAM 继续写入，不能按单条命令截断。
4. **WLAN 窗口修正为 near-identical candidate。**
   - 主 `.rodata` 0x91b798–0x9afe18 与 PDI 0x4904d4–0x524b54 长度均为 607,872；**607,868 字节相同，末尾 4 字节不同**（主 `83 6b 5f 8c`，PDI `00 00 00 00`）。
   - 因此不能说“逐字节相同”；重复窗口边界不能证明真实 payload 起点。`boundary_proven=false`，`loader` 仍未定位。
   - `0x950000` 在该候选范围内偏移 **+0x34868**；它不是 WLAN 起点。`0x920000` 偏移 +0x4868，`0x960000` 偏移 +0x44868。
5. **PDI 的 Broadcom WLAN 材料与 0x8411c8 是两回事。**
   - PDI 内确有独立 WLAN 副本证据（`7.10.48.2 (r629111)`、`reclaim section ... heap`、`AXI timeout`、`wlc_*`、WLAN 版本记录）；这些字符串距离 0x8411c8 很远，不能用来给 0x8411c8 分类。
   - 0x8411c8 的 BT 分类只依据局部 HCI 字节流，不依据远处关键字。
6. **AAC 仍无 proven 边界。** `aacenc_319` 0x8adb8c、`aacdec_315` 0x8c5034、`aacdec_318` 0x8d7e14 都没有函数引用/长度字段/装载器；只有描述符和零填充线索，未提取、未解析。

---

## 1. 方法与现成解析器

- 输入：`output/reference-decoded/body-3-2-cn/rodata.mapped.candidate.bin`，SHA-256 `3b06a163647b6d986bbb5d20a44a1ef08de38517eb398a8517b2b59d51126438`。
- HCI 解析：项目内 `temp/tool-deps/scapy` **2.8.0** 的 `HCI_Command_Hdr`（未安装全局、未联网）。
- 对每条命令：
  - 读 3 字节头，scapy 解析 `ogf/ocf/len`；
  - 断言 opcode 为 0xFC4C 或 0xFC4E；
  - 断言 payload 长度等于 `len`；
  - 按 `3+len` 前进，直到 0xFC4E 后停止。
- 没有新写 HCI 解码器；Write_RAM payload 的 4 字节地址按原字节小端解释，仅用于记录，不解释芯片内部语义。

---

## 2. BT HCD 精确解析

### 2.1 版本元数据

| 项目 | 地址/值 |
| --- | --- |
| 版本串 | 0x8411c8–0x8411e7 |
| 长度 | 32 字节（含 NUL） |
| 文本 | `BCM4343A1_001.002.009.0043.0178` |
| SHA-256 | `fdd2e25f58d9318d7ae2e995a19f676e040c66133df697c9c8faea4b07295e33` |

版本串的 NUL 后紧接 HCI 流，0x8411e8 是第一条命令起点。

### 2.2 流的第一、二条和终点

| # | 起始 | 原始头 | opcode | len | 地址 | payload 前缀 | 命令字节 |
| ---: | ---: | --- | --- | ---: | ---: | --- | ---: |
| 0 | 0x8411e8 | `4c fc 46` | 0xFC4C | 0x46 (70) | 0x00211810 | `BRCMcfgS\0...`（66 字节数据） | 73 |
| 1 | 0x841231 | `4c fc ff` | 0xFC4C | 0xFF (255) | 0x00211852 | `BRCMcfgD\0...`（251 字节数据） | 258 |
| 166 | 0x849e76 | `4e fc 04` | 0xFC4E | 4 | — | `ff ff ff ff`（Launch_RAM payload） | 7 |

- 第一条命令覆盖 0x8411e8–0x841230；第二条从 0x841231 开始，覆盖到 0x841332；后续命令继续写入。
- `BCM4343WA1 ... BT4.1 ...` 从 0x84124b 开始，位于第二条 Write_RAM 的 251 字节 payload 中（写向 0x00211852），不是独立头。
- `BRCMcfgD` payload 内的小端 0x7ca4 是更大的配置长度；后续多条 255 字节 Write_RAM 继续写该配置，因此不能把 0x841238–0x848eec 当作独立配置文件/映像。

### 2.3 统计与严格校验

| 项目 | 值 |
| --- | ---: |
| HCD 起点 | 0x8411e8 |
| HCD 终点点（不含） | 0x849e7d |
| HCD 字节 | 35,989 |
| HCD SHA-256 | `17954ada9a88b21a51f4f82896779407862a11079e974127729dc29f7e928f85` |
| 命令总数 | 167 |
| Write_RAM (0xFC4C) | 166 |
| Launch_RAM (0xFC4E) | 1 |
| 所有 `len` 之和 | 35,488 |
| Write_RAM 地址后数据 | 34,820 |
| Write_RAM 地址 min / max | 0x000d6220 / 0x002194d7 |
| 唯一地址数 | 166 |
| 地址高 16 位分布 | 0x0021xxxx: 156；0x000dxxxx: 10 |
| 地址单调 | 否 |
| 非 4 字节对齐地址 | 116（保留原始值，不修正） |

**严格校验结果**：

- scapy 解析 167/167 条成功，所有 opcode ∈ {0xFC4C, 0xFC4E}，所有长度匹配。
- 第一条/第二条 payload 前缀分别为 `BRCMcfgS`/`BRCMcfgD`。
- 最后一条为 0xFC4E、长度 4、payload `ffffffff`；流在 0x849e7d 结束。
- 0x849e7d 之后字节（`01 03 0c 00...`）不属于这个严格的 FC4C/FC4E 流，未纳入提取；不声称其语义。

**HCD 提取限制**：该流是严格可解析的 HCI vendor patchram 命令序列，但没有初始 Reset，不能直接声称是 Linux BlueZ 可直接加载的 `.hcd`；只称 “HCD-style raw HCI stream”。芯片内部地址/记录语义未在机身上验证。

---

## 3. WLAN near-identical candidate（修正）

### 3.1 两个窗口

| 项目 | 主 `.rodata` | PDI |
| --- | --- | --- |
| 起点 | 0x91b798 | 0x4904d4 |
| 终点（不含） | 0x9afe18 | 0x524b54 |
| 长度 | 607,872 | 607,872 |
| SHA-256 | `86b88705d7873e3cf920c1d63ca12814df23999a1060fc3b17bb250975896b4d` | `6263a891ef06a89d56ca38bc3cb4a2eb2d5b159777d9c5d69246987034c88154` |
| 相同字节 | **607,868 / 607,872** | 同左 |
| 不同字节 | **4**（末尾 `83 6b 5f 8c`） | 4（末尾 `00 00 00 00`） |
| 边界结论 | **false：near-identical candidate，不是 proven payload** | 同左 |

- 差异在候选范围偏移 0x9467c–0x9467f；即主 0x9afe14–0x9afe17 对 PDI 0x524b50–0x524b53。
- 重复窗口只说明两段内容高度相似；**不能**把窗口起点当作真实 payload 起点，也**不能**把 4 字节差异忽略成“逐字节相同”。
- `0x950000` 在候选范围内偏移 **+0x34868**，不是起点；`0x920000` +0x4868；`0x960000` +0x44868。
- 候选范围前 0x91b760–0x91b798 有 56 字节头候选，PDI 中不同，单独标为 candidate。

### 3.2 局部可确认记录（不证明周围 image 边界）

| 记录 | 地址 | 长度 | SHA-256 | 说明 |
| --- | ---: | ---: | --- | --- |
| WLAN 版本 A | 0x9669ec–0x966acb | 223 | `3e44a8eaa5061e57…` | 与 PDI 0x4db728 记录相同；38 字节前缀 + 版本串 |
| WLAN 版本 B | 0x9afac4–0x9afb7c | 184 | `f4e1ac510590c363…` | 与 PDI 0x524800 记录相同 |
| NVRAM 文本 | 0x9afb80–0x9afdea | 618 | `adc793e251d196d7…` | 0x26a 长度；0x43f404 写指针/长度，0x43a5c8 使用 |

- 版本/NVRAM 的记录边界是精确的（NUL/长度字段），但它们只证明“这些记录存在且主/PDI 相同”，不证明 607,872 窗口是完整 payload，也不提供装载起点。
- 主 `.data` 仍没有指向 0x91b798/0x920000/0x950000 的 32 位指针，也没有找到装载函数；`.rodata 0x776164` 的 0x00950000 位于 PHY 参数表，不是映像描述符。
- 因此 `wlan_near_identical_candidate` 的 `boundary_proven=false`，文件保留为候选，不称 payload。

---

## 4. PDI 的独立 Broadcom WLAN 材料

PDI 范围 0x440c00–0x527c00。以下证据与 0x8411c8 的 BT HCD 无关；它们只证明 PDI 另有 WLAN 材料：

| 地址 | 内容 |
| ---: | --- |
| 0x4b8687 | `7.10.48.2 (r629111)` |
| 0x4b869b | `reclaim section %s: Returned %d bytes to the heap\n` |
| 0x4b879d | `Malloc failure count: %d\n` |
| 0x4b8a1a | `AXI timeout` |
| 0x48ff98 | `BCM4343` |
| 0x4cc758 / 0x5161f0 | `wlc_bmac_info_init` |
| 0x4db74e / 0x524826 | WLAN 版本/CRC 记录 A/B，与主 0x966a12/0x9afaea 相同 |

PDI 的 WLAN 副本边界同样是 near-identical（607,868/607,872，4 字节差），不是 proven payload；完整 PDI 函数分析由另一个 Pi 负责，本报告不重复。

---

## 5. AAC

| 标识 | 地址 | 函数引用 |
| --- | ---: | --- |
| `aacenc_319` | 0x8adb8c | 无 |
| `aacdec_315` | 0x8c5034 | 无 |
| `aacdec_318` | 0x8d7e14 | 无 |

- 零填充线索：0x8c5068–0x8c7874（10,252 字节）、0x8d7e50–0x8da654（10,244 字节）。
- 没有起始地址、长度字段或装载器；标识后的指针样值（如 0x4010c9cc、0x4000afe0、0x60000420）不在主 `.text` 地址空间，架构未知。
- **不提取、不解析、不声称音频路径已定位。**

---

## 6. 提取清单（`output/embedded-radio-2026-10-29/`）

| 文件 | 来源 | 字节 | boundary_proven |
| --- | --- | ---: | --- |
| `bt_version_0x8411c8_0x8411e8.bin` | 0x8411c8–0x8411e8 | 32 | true（版本串 NUL 后紧接 HCD） |
| `bt_hcd_patchram_0x8411e8_0x849e7d.bin` | 0x8411e8–0x849e7d | 35,989 | true（HCI 严格解析，FC4C/FC4E） |
| `wlan_header_candidate_0x91b760_0x91b798.bin` | 0x91b760–0x91b798 | 56 | false（候选头） |
| `wlan_near_identical_candidate_0x91b798_0x9afe18.bin` | 0x91b798–0x9afe18 | 607,872 | **false（4 字节差；loader 未证）** |
| `wlan_version_record_A_0x9669ec_0x966acb.bin` | 0x9669ec–0x966acb | 223 | true（记录 NUL 边界，不证明外层） |
| `wlan_version_record_B_0x9afac4_0x9afb7c.bin` | 0x9afac4–0x9afb7c | 184 | true（同上） |
| `wlan_nvram_text_0x9afb80_0x9afdea.bin` | 0x9afb80–0x9afdea | 618 | true（0x26a 长度） |
| `pdi_wlan_version_record_A_0x4db728_0x4db807.bin` | PDI 0x4db728–0x4db807 | 223 | true（记录 NUL 边界） |
| `pdi_wlan_version_record_B_0x524800_0x5248b8.bin` | PDI 0x524800–0x5248b8 | 184 | true（记录 NUL 边界） |

- `manifest.json` 记录每个文件的起始、长度、SHA-256、边界证据和 `boundary_proven`。
- 已删除上一版错误的 `bcm4343_version_header`、`bcm4343_brcmcfgs`、`bcm4343_brcmcfgd_candidate`、`wlan_payload` 文件。
- 未提取：PDI 全镜像、AAC、0x903424–0x91b760 角色未明区域。

---

## 7. 检查与限制

### 7.1 检查

- 源 `.rodata` SHA-256 核对。
- HCI：167/167 命令由 scapy 解析；166 0xFC4C + 1 0xFC4E；首两条地址/前缀正确；terminal Launch_RAM 正确；HCD 提取哈希已记录。
- WLAN：607,868/607,872 相同，4 字节不同；`boundary_proven=false`。
- AAC：`not_verified`。
- 9 个提取文件，7 个局部边界证明，2 个候选（WLAN 候选范围、56 字节头候选）。

### 7.2 限制

1. HCD 是严格 HCI 命令流，但 **Linux `.hcd` 兼容性未证明**（无初始 Reset；vendor 流直接开始）。
2. HCD 的芯片内部地址/记录语义、下载后行为未验证；只做了字节级格式校验。
3. 0x849e7d 后的字节未纳入；它们可能属于其他数据/命令，本报告不解析。
4. WLAN 607,872 窗口只是 near-identical candidate；4 字节差异、无 loader、无真实起点证明，不能称“完整 payload”。
5. WLAN 版本/NVRAM 记录的精确边界不证明外层 image 边界。
6. AAC 未映射；没有边界/装载/架构结论。
7. 未连接相机、未访问网络、未遥控、未刷写、未改代码、未 git 提交。

---

## 8. 复现

```powershell
python -B temp/pi-offline-radio/build_radio.py
```

脚本只读 `output/reference-decoded/body-3-2-cn/rodata.mapped.candidate.bin`，使用项目内 `temp/tool-deps/scapy`，写入 `output/embedded-radio-2026-10-29/`、`temp/pi-offline-radio/` 和 `reports/pi-offline-radio-2026-10-29.json`。
