# demo 集成前的 LZSS 重压缩可行性试验

> **事故后状态：3.2-d1 已撤回，请勿刷写。** 本文保留离线研究阶段的证据与命令；参见[事前声明](../docs/pre-use-disclaimer.md)及[事故记录](firmware-incident-2026-10-29.md)。软件检查通过不代表硬件可启动。

日期：2026-10-29。范围：只测 `.rodata` 官方完整明文的重压缩容量与两种解码语义；未生成固件、未修改构建器/原输入、未连接相机或网络、未播放音频、未 git 提交。所有临时产物在 `temp/demo-repack/`，报告在 `reports/`。

## 0. 结论

| 问题 | 结果 |
| --- | --- |
| 官方 `.rodata` 完整明文能否用 ff7tools `compress()` 放回容量 | **能**：4,120,972 B ≤ 4,124,672 B，余量 **3,700 B** |
| 相对官方 packed | 小 **3,560 B**（官方 4,124,532 B） |
| 压缩时间 | **68.07 s**（单次完整 5,703,192 B 明文） |
| ff7tools 库解码 | 逐字节等于 full：**是** |
| `firmware_tokens` 顺序解码 | 逐字节等于 full：**是** |
| `firmware_tokens` snapshot / snapshot_zero | **不等**：新流 868,221 B / 177,013 段不同；官方流本身也不同（795,745 B / 164,114 段） |
| 选定的快门 MP3 是否已进入候选 rodata | **没有**：无快门 WAV ID/VA，未猜地址、未覆盖资源、未生成 FFmpeg 变体 |
| 原硬件解码是否已证明 | **未证明**；只能标 experimental |

**判断**：base 全量重压缩在容量上可行，且有余量；但这不等于“曝光预览 + 边界修补 + 快门音”集成 demo 已经能放下。快门音替换会改变明文，必须拿到实际 WAV 的 ID/VA 后重新压缩并重新测容量；不能把 3,700 B 当作替换音频的保证余量。

## 1. 输入与几何

| 项目 | 值 |
| --- | --- |
| 官方 rodata full | `output/reference-decoded/body-3-2-cn/rodata.full.candidate.bin` |
| full 长度 / SHA-256 | 5,703,192 B / `3b06a163647b6d986bbb5d20a44a1ef08de38517eb398a8517b2b59d51126438` |
| mapped 长度 / SHA-256 | 5,703,192 B / 同 full |
| full 与 mapped | 逐字节相同；rodata **没有额外尾字节** |
| 官方 packed 流 | 4,124,532 B（`output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.03127296` 的前 4,124,532 B） |
| 官方 padded 文件 | 4,124,672 B，后 140 B 全零；SHA-256 `0507731bcc743013345061ac149e4fa14aed7d2f72b57357fb1c826bd7225b38` |
| 容量 | **4,124,672 B** |
| 官方 packed 余量 | **140 B** |
| ff7tools 参考实现 | `vendor/ff7tools-reference/lzss.py`，5,704 B，SHA-256 `ee3b65e055231164d29ac53a67da1dd047c2e761b932c6a3efb27e6d7f102f84` |

说明：

- 本轮只对 **官方 full 明文**做一次完整重压缩；没有把音频写进任何位置。
- `rodata.full` 与 `rodata.mapped` 相同，说明该段没有 `.text/.data` 那种额外 `ff` 尾字节；本轮没有触碰 `.text/.data` 的尾字节处理。
- 官方 padded 文件的 140 B 零填充只用于容量占用；不是 token 流的一部分。

## 2. 方法

复用成熟实现，没有写新的 LZSS 匹配算法：

1. 用固定 SHA 的 `ff7tools-reference/lzss.py` 的 `compress()` 压缩 `rodata.full.candidate.bin`。
2. 将结果写入 `temp/demo-repack/rodata.full.recompressed.lzss.bin`；只写 temp，不写容器、不写 `output/firmware-builds/`。
3. 用同一库的 `decompress()` 解码，逐字节比较 full。
4. 用现有 `scripts/firmware_tokens.py` 的 `parse_stream()` + `decode(..., "sequential")` 解码，逐字节比较 full。
5. 额外用 `decode(..., "snapshot")` 与 `decode(..., "snapshot_zero")` 检查 snapshot 语义风险。
6. 对官方 packed 流做同样的 control，确认库/顺序解码能还原 full，并量化官方流本身的 snapshot 差异。
7. 进程设置为 Windows `IDLE_PRIORITY_CLASS`；并发 1；所有临时/缓存留在项目内。

没有做：没有 FFmpeg 转码候选、没有把 MP3 写入 rodata、没有猜快门 WAV 的 VA、没有改 `scripts/repack.py` 或 `scripts/firmware_tokens.py`、没有生成固件。

## 3. 容量与时间

### 3.1 base 完整重压缩

| 项目 | 值 |
| --- | ---: |
| 输出文件 | `temp/demo-repack/rodata.full.recompressed.lzss.bin` |
| 输出长度 | **4,120,972 B** |
| 输出 SHA-256 | `8be41830f482b605ad41a836c3ce8ab0c7b89fd026a26c7cb4359eeb269970da` |
| 容量 | 4,124,672 B |
| **余量** | **3,700 B** |
| 相对官方 packed | **−3,560 B** |
| 压缩时间 | **68.07 s** |
| token 数 | 3,236,312 |
| `unused_flags` | 0 |
| `orphan_flag` | 空 |
| 解析输出长度 | 5,703,192 B（等于 full） |

**base 可以放下**。如果容器构建器按 capacity 补零，需要补 3,700 个零字节；如果不补，流本身也小于容量。两种情况都不是“已构建”或“已刷写”。

### 3.2 压缩时间的含义

- 68.07 s 是本机单次完整重压缩的纯 Python 时间，包含字典查找和 5,703,192 B 输入；不是相机启动/解码时间。
- 本次低优先级、并发 1；没有与后台视频任务并行做重压缩。
- 该时间只用于估计构建阶段开销，不能作为真机性能或启动时间证据。

## 4. 解码校验

### 4.1 官方 packed control

| 解码器 | 结果 |
| --- | --- |
| `ff7tools.decompress(official[0:4,124,532])` | 等于 full |
| `firmware_tokens.decode(parse(official), "sequential")` | 等于 full |
| `firmware_tokens.serialize_stream(parse(official))` | 逐字节等于 official packed |
| `firmware_tokens.decode(parse(official), "snapshot")` | **不等**：795,745 B 不同，164,114 段，首个差异 offset 104（snapshot=0，full=7） |
| `firmware_tokens.decode(parse(official), "snapshot_zero")` | 与 snapshot 相同的差异统计 |

官方 token 数 3,240,392，`orphan_flag=ff`；官方 control 的库/顺序解码都逐字节等于 full。snapshot 的失败是官方流就存在的，不是本次重压缩引入的。

### 4.2 新重压缩流

| 解码器 | 结果 | 时间 |
| --- | --- | ---: |
| `ff7tools.decompress(new)` | **等于 full**（5,703,192 B） | 0.97 s |
| `firmware_tokens.decode(parse(new), "sequential")` | **等于 full** | 1.52 s |
| `firmware_tokens.serialize_stream(parse(new))` | **逐字节等于 new**（4,120,972 B；token 无损失） | — |
| `firmware_tokens.decode(parse(new), "snapshot")` | **不等**：868,221 B 不同，177,013 段，首个差异 offset 104（snapshot=0，full=7） | 1.88 s |
| `firmware_tokens.decode(parse(new), "snapshot_zero")` | **不等**：868,221 B 不同，177,013 段 | 1.83 s |

新流 token 数 3,236,312，`unused_flags=0`，没有 orphan flag；解析输出长度 5,703,192；`serialize_stream(parse_stream(new))` 与 new 逐字节相同（4,120,972 B），说明本轮 token 解析/序列化没有额外尾字节损失。

### 4.3 “二解码校验”的准确表述

- **通过**：ff7tools 库解码、`firmware_tokens` 顺序解码都逐字节等于 full。
- **未通过**：snapshot / snapshot_zero 语义下不等于 full；新流的 snapshot 差异比官方更大（868,221 vs 795,745 B）。
- **不能推出**：不能因为库/顺序解码通过，就宣称原硬件一定使用顺序语义。只能说明：在这两种软件语义下，新流是完整的；官方流本身也不符合 snapshot，提示 snapshot 是实现工具的 warm-up 复现，而非已证硬件行为，但这不是硬件证明。

## 5. snapshot 语义风险

### 5.1 事实

- 官方流和新流在 snapshot、snapshot_zero 下都不等于 full；首个差异都在 **offset 104**，snapshot 输出 0，full 为 7。
- 官方差异：795,745 B、164,114 段；新流差异：868,221 B、177,013 段。
- 新流的 snapshot 差异更多，说明重压缩改变了环状态/早期引用的使用，使“按 upstream 工具 warm-up 规则解码”的结果更偏离 full。

### 5.2 风险

1. **原硬件语义未证明**：现有资料只能证明顺序复制语义在字符串/指令统计上更合理，不能证明 SoC 解码器实际采用顺序复制；snapshot 是上游工具的复现，不是硬件规范。
2. **若硬件接近 snapshot**：新流会产生 868,221 B 的错误输出，远超官方流的 795,745 B；不能刷。
3. **即使硬件是顺序**：也需要真机/硬件解码器验证；本轮没有执行原厂解码器或相机。
4. **full 尾**：rodata full 与 mapped 相同，无额外尾；本轮没有改变 `.text/.data` 的尾字节处理，也没有改动 `firmware_tokens`。

**报告必须把新流标为 experimental，而不是“已验证可刷”。**

## 6. 快门音候选：未测

用户给定：

- `data/input/custom-sounds/shutter-selected.mp3`
- 32,023 B，SHA-256 `c65e5b132a1d11567ce2237da36a0a58fa320cc592d7605914e315aa020db772`
- 1.332208 s、44.1 kHz、stereo（用户提供）

本轮**没有**把它写入候选 rodata，原因是：

- 普通快门 WAV 的具体 ID/VA 由另一个 Pi 查；在主代理未给出该地址前，任何替换都是猜测。
- 9 段官方 WAV 全部是 PCM 48 kHz/16 bit；当前 MP3 不能被现有 WAV/PCM 播放路径直接消费（未分析 MP3 解码支持，也没有做 FFmpeg 变体）。
- 若替换成较小 PCM/其他格式，必须重新压缩整个 rodata，容量结果不能由 base 的 3,700 B 余量直接外推。
- 任务明确要求“不猜快门地址、不覆盖任何资源、先测 base”。

因此：**base 可行，但“只换快门音”的候选 rodata 还没有测量**。主代理下一步需要提供：

1. 目标快门 WAV 的索引/VA/长度（由另一个 Pi 查）；
2. 允许的替换格式（PCM 48k mono/stereo、位深、是否可转 MP3/ADPCM）和播放器是否支持；
3. 可接受的实际音频变体（FFmpeg 输出）。

拿到后应复制 full 明文、只在该 VA 区间替换、重新跑本报告的同一 `compress()`/双解码/容量检查；不能复用 base 的 3,700 B 结论。

## 7. 对集成 demo 的意义

- **有利**：官方 rodata 的完整重压缩比官方 packed 小 3,560 B，容量余量从 140 B 增加到 3,700 B（仅 base）。这说明“全量重压缩”本身不是不可行。
- **限制**：base 的 3,700 B 不是音频替换的可用预算；音频改变会改变压缩流。必须重压候选明文。
- **风险**：snapshot 语义不一致；硬件解码未证明。任何集成包都必须保留“experimental”标识，并准备官方 SD 恢复路径（升级器/恢复路径证据见既有报告）。
- **建议**：主代理先让另一个 Pi 给出快门 WAV ID/VA，再决定是否值得构建音频候选；在此之前不生成集成固件。

## 8. 产物

| 文件 | 内容 |
| --- | --- |
| `temp/demo-repack/measure_base_lzss.py` | 本次测量脚本；固定 lzss.py SHA、只读输入、低优先级 |
| `temp/demo-repack/rodata.full.recompressed.lzss.bin` | 4,120,972 B 重压缩流；仅 temp，不是容器/固件 |
| `temp/demo-repack/measurement.json` | 完整测量、时间、解码、容量结果 |
| `temp/demo-repack/snapshot_diff.py` | 官方/新流 snapshot 差异统计 |
| `temp/demo-repack/snapshot-diff.json` | 差异字节数、段数、首个差异 |
| `reports/demo-compression-feasibility-2026-10-29.json` | 机器可读结论 |
| `reports/demo-compression-feasibility-2026-10-29.md` | 本报告 |

复现：

```powershell
python -B temp/demo-repack/measure_base_lzss.py
python -B temp/demo-repack/snapshot_diff.py
```

## 9. 限制

- 单次完整压缩；时间随主机负载变化，不能作为构建 SLA。
- 新流是整段重压缩，不是“只改音频”的等长 token 补丁；所有 token 边界都可能变化。
- 只验证了软件库/顺序解码；原硬件解码未证明。
- 没有验证 `.secinfo`、容器 `SUM`、升级器写入或真机启动；这些属于后续构建阶段。
- 没有生成/修改固件，没有覆盖任何官方音频资源。
