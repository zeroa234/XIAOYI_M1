# 嵌入式 @PDI ARM 子 CPU 映像：隔离 Ghidra 全量分析

日期：2026-10-29。范围：官方 3.2-cn 参考解码候选 `.rodata` 内的 `@PDI` 子 CPU 映像。只做离线静态分析；未连接相机、未访问 `192.168.*`、未使用遥控/USB/网络，未修改固件、未重打包、未 git 提交。所有地址均为候选映像/载荷地址，不是真机内存验证值。

## 0. 结论摘要

1. **容器与加载关系已逐字节核对**：`.rodata@0x440c00` 有 `@PDI` 头，头长字段 `0x200`，payload 长度字段 `0xe6e00`；payload 从 `0x440e00` 到 `0x527c00`，SHA-256 `a48744ebf2e7f8c4fe895f8ddd7b4823dab82b7307acb19a185e31684579cc7a`。主程序 `0x42eb90` 的 `memcpy` 源=`0x440e00`、目标=`[0xc0a020f0+0xc]=0xdfc90000`、长度=`0xe6e00`，与头字段、描述符和原 loader 字面量一致。
2. **隔离 Ghidra 工程建立成功**：新建独立 headless 工程，raw `BinaryLoader` 基址 `0xdfc90000`，`ARM:LE:32:v5t`，`-analysisTimeoutPerFile 180`，`-max-cpu 2`，`-Xmx2G`；未使用主程序工程，也未套用主程序的 27 个 outline helper。7 个向量入口由 `PrepareEmbeddedSubcpu` 建立，随后 Ghidra 自动分析。
3. **识别函数与导出计数**：识别 **12,940** 个函数；成功反编译 **12,869**，失败 **71**（全部为 `Bad instruction count exceeded`/`No pcode could be generated` 类）；`decompiled/` 共 **12,940** 个 `.c` 文件，成功与失败的 C/反汇编替代一一对应。识别函数共 **191,101** 条指令、**541,533** 字节函数体。
4. **字符串与调用目录**：原始块扫描得到 **20,647** 条 ASCII 串，其中 **1,903** 条有函数引用；`functions.tsv` 含完整调用者/被调用者/字符串/MMIO/payload 引用。**9,382** 个调用流带 Thumb 低 bit，已归一化为偶数函数入口；归一化后仍有 **445** 个未解析调用目标（421 个单调用点、24 个多调用点），见 `unrecognized-call-targets.tsv`。
5. **结构证据**：`0xdfc90ac4` 注册 `task`、`semaphore`、`eventflag`、`mailbox`、`messagebuffer`、`rendezvous`、`mutex`、`memorypool`、`fix_memorypool`、`cyclichandler`、`alarmhandler`、`subsystem`、`timer` 等对象名，显示该子 CPU 内有 T-Kernel 类对象管理；`0xdfcb4ebc` 引用 `BAD SOCKET CALL`、`SET SOCKET OPTIONS CALL`、`select error`、`fnsSendTo failed`；`eth0`、`ICMP` 和 BCM43430 Wi-Fi 版本串也在该映像内。**这些是静态字符串/函数引用，不是运行期行为证明。**
6. **向量表**：`+0x20` 复位入口 `0xdfc90100`；`+0x24..+0x30` 与 `+0x3c` 是 `b .` 自旋桩；`+0x38` IRQ 入口 `0xdfc94e04` 是 `b 0xdfc9d5d4`。复位桩在若干初始化调用后也以 `b .` 结束；其是否通过被调函数切换上下文未证明。
7. **真实限制**：raw binary 无符号；Ghidra 只覆盖它识别出的函数；71 个反编译失败、445 个未解析目标、7,345 条反编译警告、29 条 Ghidra ERROR 行都保留在输出中，不把“12,940 个函数”当作完整代码覆盖率。`BinaryLoader` 把块放在 `0xdfc90000`，但 Ghidra 的 image base 仍是 0；本文地址是块地址。

## 1. 输入与容器核对

### 1.1 输入哈希

| 段 | 文件 | SHA-256 |
| --- | --- | --- |
| `.rodata` | `output/reference-decoded/body-3-2-cn/rodata.mapped.candidate.bin` | `3b06a163647b6d986bbb5d20a44a1ef08de38517eb398a8517b2b59d51126438` |
| `.data` | `output/reference-decoded/body-3-2-cn/data.mapped.candidate.bin` | `0c7bc4e420b8b24ad6ca36f0c931d415add9a56a23cf70537e9b79e545c5df98` |
| `.text` | `output/reference-decoded/body-3-2-cn/text.mapped.candidate.bin` | `da781ebd70ce1cae6ded261e2e8e66d66c165ad1939c90bdc9a6eb7432610992` |

运行前后逐文件重新哈希，三者均未改变；payload 副本 SHA-256 也未改变。原始输入只读。

### 1.2 `@PDI` 头

头 VA `0x440c00`（rodata 偏移 `0x1400`），长 `0x200`：

```text
00: 40 50 44 49 00 00 00 00 00 02 00 00 00 6e 0e 00  @PDI........n..
10: 56 65 72 30 2e 30 2e 30 30                       Ver0.0.00
```

| 字段 | 值 | 说明 |
| --- | ---: | --- |
| magic | `@PDI` | 4 字节 |
| `+0x08` | `0x00000200` | 头长 0x200 |
| `+0x0c` | `0x000e6e00` | payload 长 945,664 |
| `+0x10` | `Ver0.0.00` | 版本串，后面到 0x200 基本为 0 |

payload 从 `0x440e00` 到 `0x527c00`，长度 `0x527c00-0x440e00=0xe6e00=945664`。最后非零字节在 payload 内偏移 `0xe6c93`（绝对 `0x527a93`），尾部 364 为零；与 `reports/pi-offline-coverage-2026-10-29.json` 的记录一致。

### 1.3 主程序 loader 与 `.data` 描述符

主程序 `0x42eb90` 的原始指令（`.text`）：

```text
0042ebbc  mov r0,r5
0042ebc0  bl  0x42eb44
0042ebc4  cmp r0,#0
0042ebc8  movne r0,#1
0042ebcc  popne {r4,r5,pc}
0042ebd0  ldr r0,=0x440c00       ; @PDI header
0042ebd4  ldr r1,=0x527c00       ; payload end
0042ebd8  sub r1,r1,r0           ; 0xe7000
0042ebdc  sub r2,r1,#0x200       ; 0xe6e00
0042ebe0  add r1,r0,#0x200       ; 0x440e00
0042ebe4  ldr r0,[r5,#0xc]       ; descriptor destination
0042ebe8  bl  0x18db8c           ; memcpy(dest, src, len)
```

逐字核对结果：

| 地址 | 原字 | 含义 |
| --- | ---: | --- |
| `0x42ebd0` | `e59f005c` | `ldr r0,[pc,#0x5c]` |
| `0x42ebd4` | `e59f1060` | `ldr r1,[pc,#0x60]` |
| `0x42ebd8` | `e0411000` | `sub r1,r1,r0` |
| `0x42ebdc` | `e2412c02` | `sub r2,r1,#0x200` |
| `0x42ebe0` | `e2801c02` | `add r1,r0,#0x200` |
| `0x42ebe4` | `e595000c` | `ldr r0,[r5,#0xc]` |
| `0x42ebe8` | `ebf57be7` | `bl 0x18db8c` |
| `0x42ec34` | `00440c00` | header 字面量 |
| `0x42ec38` | `c0a020f0` | descriptor 基址 |
| `0x42ec3c` | `00527c00` | payload end 字面量 |

`.data@0xc0a020f0` 的四个字：

| 偏移 | 值 | 说明 |
| ---: | ---: | --- |
| `+0x0` | `0x00000002` | 观察到的描述符字段 |
| `+0x4` | `0x00000072` | 观察到的描述符字段 |
| `+0x8` | `0x00300000` | 观察到的描述符字段 |
| `+0xc` | `0xdfc90000` | `memcpy` 目标；与用户给出的 `+0xc` 一致 |

因此：`payload = rodata[0x440e00:0x527c00]`，`dest = 0xdfc90000`，`len = 0xe6e00`。提取后的副本在 `temp/pi-embedded-subcpu/payload.bin`，SHA-256 `a48744ebf2e7f8c4fe895f8ddd7b4823dab82b7307acb19a185e31684579cc7a`。

## 2. 隔离 Ghidra 工程与参数

- 工具：项目内 Ghidra 12.2 + Java 25；来源标记 `vendor/ghidra/.verified-source.json`、`vendor/java25/.verified-source.json`。
- 工程：`temp/pi-embedded-subcpu/ghidra-project-<timestamp>`，项目名 `embedded-subcpu`；独立于主程序 `output/ghidra-projects/m1-3-2-candidate`。
- 导入：`BinaryLoader`，`-loader-baseAddr 0xdfc90000`，`-processor ARM:LE:32:v5t`。
- 分析：`-analysisTimeoutPerFile 180`，`-max-cpu 2`，`-Xmx2G`，`-XX:ParallelGCThreads=2`，`-XX:CICompilerCount=2`，进程优先级 `IDLE_PRIORITY_CLASS`（宿主支持时）。
- 每函数反编译超时：30 秒；`limit=0`（全量）。
- 缓存/Java 用户目录/TMP/TEMP 全部在 `temp/pi-embedded-subcpu/ghidra-*`；未使用网络。
- **未套用主程序 27 个 outline helper**：`ExportEmbeddedSubcpu` 没有 HELPERS 表，也没有 `setInline` 调用；输出 C 头部明确写 `no main-program outline helpers applied`，`summary.json` 的 `outline_helpers_applied` 为 `false`。

### 2.1 向量入口 seed

payload 起始 0x20 字节是 ARM 向量桩：`0x00/0x04/0x08/0x0c/0x10 = e59ff018`（`ldr pc,[pc,#0x18]`），`0x14 = eafffffe`（`b .`），`0x18/0x1c = e59ff018`；7 个绝对目标放在 `+0x20..+0x3c`。这与用户给出的向量表偏移一致。

`PrepareEmbeddedSubcpu` 只做块几何校验、读取 `+0x20..+0x3c` 的 7 个向量字、`disassemble` + `createFunction`，不修改指令/数据。

| slot | 向量字 | 目标 | 导出函数 |
| --- | ---: | ---: | --- |
| `0xdfc90020` | `0xdfc90100` | `0xdfc90100` | `subcpu_vec_20`（reset 桩，28 字节/7 指令） |
| `0xdfc90024` | `0xdfc9011c` | `0xdfc9011c` | `subcpu_vec_24`（4 字节，`b .`） |
| `0xdfc90028` | `0xdfc90120` | `0xdfc90120` | `subcpu_vec_28`（4 字节，`b .`） |
| `0xdfc9002c` | `0xdfc90124` | `0xdfc90124` | `subcpu_vec_2c`（4 字节，`b .`） |
| `0xdfc90030` | `0xdfc90128` | `0xdfc90128` | `subcpu_vec_30`（4 字节，`b .`） |
| `0xdfc90038` | `0xdfc94e04` | `0xdfc94e04` | `thunk_FUN_dfc9d5d4`（`b 0xdfc9d5d4`，IRQ） |
| `0xdfc9003c` | `0xdfc9012c` | `0xdfc9012c` | `subcpu_vec_3c`（4 字节，`b .`） |

复位桩 `0xdfc90100` 的原始序列：

```text
dfc90100  bl 0xdfc953a4
dfc90104  msr cpsr_c,#0xdf
dfc90108  bl 0xdfc9541c
dfc9010c  bl 0xdfc954bc
dfc90110  bl 0xdfc954d8
dfc90114  bl 0xdfc9014c
dfc90118  b  .                 ; 复位桩自身不返回
```

IRQ 向量 `0xdfc94e04`：`b 0xdfc9d5d4`；`0xdfc9d5d4` 为 132 字节/33 指令，3 个被调用者。其余异常向量为 `b .`，本映像未给出可恢复处理。

> `PrepareEmbeddedSubcpu` 第一次试跑曾因 Ghidra image base 为 0 而误报；已改为只校验块基址/大小，并在最终运行中成功。`run-inputs.json` 记录最终命令。

## 3. 覆盖计数与产物

### 3.1 总计数

| 项目 | 数值 |
| --- | ---: |
| payload 基址 / 大小 | `0xdfc90000` / 945,664 |
| 识别函数 | **12,940**（其中 7 个为 `PrepareEmbeddedSubcpu` 的向量 seed；其余由 Ghidra 自动分析识别） |
| 反编译成功 | **12,869** |
| 反编译失败 | **71** |
| `decompiled/*.c` | **12,940**（成功 C + 71 个反汇编替代） |
| 成功+失败是否等于文件数 | 是（`decompile_coverage_complete=true`） |
| 识别函数指令总数 | **191,101** |
| 识别函数体字节总数 | **541,533** |
| ASCII 串（原始块扫描） | **20,647** |
| 有函数引用的串 | **1,903** |
| 未解析调用目标 | **445**（421 单调用点、24 多调用点） |
| Thumb 低 bit 调用流 | **9,382** |
| `functions.tsv` 数据行 | **12,940** |
| `strings.tsv` 数据行 | **20,647** |
| catalog（导出器内） | 1.71 秒 |
| postScript（导出+反编译） | 122.27 秒 |
| 整个 headless 墙钟 | 289.12 秒 |
| `analysisTimeoutPerFile=180` 是否触发 | 否（日志未出现 analysis timed out） |

识别函数体共 541,533 字节，约占 payload 945,664 字节的 57.3%；其余字节包含数据、字符串、对齐/填充以及未被 Ghidra 识别为函数的代码，不能视为已恢复代码。`summary.json` 与 `run-verification.json` 的数字一致；`functions.tsv` 的 12,940 个入口与 `decompiled/` 的 12,940 个文件名集合逐一对齐（无缺失、无多余）。

### 3.2 地址分布

| 64 KiB 区间 | 函数数 |
| --- | ---: |
| `dfc90000` | 327 |
| `dfca0000` | 247 |
| `dfcb0000` | 252 |
| `dfcc0000` | 218 |
| `dfcd0000` | 232 |
| `dfce0000` | 1,754 |
| `dfcf0000` | 1,474 |
| `dfd00000` | 1,336 |
| `dfd10000` | 1,177 |
| `dfd20000` | 407 |
| `dfd30000` | 2,298 |
| `dfd40000` | 1,521 |
| `dfd50000` | 1,086 |
| `dfd60000` | 569 |
| `dfd70000` | 42 |

函数分布与字符串/网络/Wi-Fi 证据一致：`dfce`–`dfd5` 是主要代码/数据密集区，`dfd6`–`dfd7` 主要是尾部数据/配置。

### 3.3 产物

```text
output/embedded-subcpu-2026-10-29/
├── summary.json
├── run-inputs.json
├── run-verification.json
├── console.log
├── ghidra.log
├── ghidra-script.log
├── vectors.tsv
├── functions.tsv
├── strings.tsv
├── unrecognized-call-targets.tsv
├── failures.tsv
├── decompile-timings.tsv
└── decompiled/<entry>.c
```

`functions.tsv` 在主目录列基础上增加 `payload_refs` 与 `payload_count`（映像内地址引用），其余列与主程序目录相同：`entry/end/body_bytes/instruction_count/caller_count/callee_count/callers/callees/strings/ram_globals/mmio/.../name/string_addresses`。

## 4. 子系统结构证据（静态）

### 4.1 T-Kernel 类对象表

`0xdfc90ac4`（236 字节/59 指令，1 个调用者）依次引用：

```text
task, semaphore, eventflag, mailbox, messagebuffer, rendezvous,
mutex, memorypool, fix_memorypool, cyclichandler, alarmhandler,
subsystem, timer
```

字符串地址：`dfc90bbc`、`dfc90bc8`、`dfc90bd8`、`dfc90be8`、`dfc90bf4`、`dfc90c08`、`dfc90c18`、`dfc90c24`、`dfc90c34`、`dfc90c48`、`dfc90c5c`、`dfc90c70`、`dfc90c80`。这与主程序 `.rodata` 的 T-Kernel 对象名表同构，但地址、函数和调用关系独立。说明该子 CPU 内有 T-Kernel 类对象管理/注册逻辑；**不证明具体调度器版本或 ABI**。

### 4.2 网络 / socket 错误路径

`0xdfcb4ebc`（1,640 字节/410 指令，1 个调用者）引用：

| 字符串 | 地址 |
| --- | --- |
| `BAD SOCKET CALL` | `dfcb535c` |
| `SET SOCKET OPTIONS CALL` | `dfcb536c` |
| `select error` | `dfcb55d0` |
| `fnsSendTo failed` | `dfcdeb80` |

该函数有 18 个被调用者、40 余处 payload 引用，形态像 socket/select/send 的公共错误/分派路径。`eth0` 字符串出现在 `dfc9b11c`（被 `dfc9acd8`、`dfc9ad98` 引用）和 `dfcdea1c/21/26`（被 `dfc9a4bc` 引用）；`dfc9a4bc` 为 1,484 字节/371 指令的网络相关函数。`ICMP` 位于 `dfcdeb0c`，`inittsk` 位于 `dfcde914`。

### 4.3 Wi-Fi / BCM43430 证据

| 字符串 | 地址 | 引用函数 |
| --- | --- | --- |
| `43430a1-roml/sdio-g-pool-idsup-idauth-keepalive-txbf-pktfilter-mchan-proptxstatus Version: 7.10.48.2 ...` | `dfd2a94e` | `dfd28778` |
| `43430a1-roml/sdio-g-pool-apcs-idsup-idauth Version: 7.10.48.2 ...` | `dfd73a26` | `dfd7374e`;`dfd7376e` |
| `XC_WLAN_CoreInitializeBody` | `dfd74a08` | `dfd34a02` |
| `XC_WLAN_DrvStaGetRssiBody` | `dfd74840` | `dfd05826` |
| `Invalid/Unsupported xtal value %d` | `dfd6747f` | `dfd66f3c` |
| `TCAM: %d used: %d exceed:%d\n` | `dfd07aca` | `dfd078d8` |
| `TRAP %x(%x): pc %x, lr %x, sp %x, cpsr %x, spsr %x\n` | `dfd07afd` | `dfcf0b22` |

这些字符串与 `eth0`/socket 证据共同表明子 CPU 映像包含网络/Wi-Fi 相关代码和数据；**不能仅凭字符串确定实际运行模式、硬件通路或用户功能**。

### 4.4 规模最大的函数（示例）

| 入口 | 指令数 | 调用者数 | 备注 |
| --- | ---: | ---: | --- |
| `dfcd8cf8` | 1,415 | 1 | 大函数，含格式化/字符串引用 |
| `dfd1e786` | 1,156 | 1 | 大函数 |
| `dfcbc840` | 1,123 | 0 | 大函数，无直接调用者（可能间接/入口） |
| `dfcbfd00` | 1,032 | 5 | 大函数 |
| `dfd66f3c` | 812 | 1 | 引用 `Invalid/Unsupported xtal value` |
| `dfcb4ebc` | 410 | 1 | socket/select 错误路径 |
| `dfc9a4bc` | 371 | 0 | `eth0` 网络相关 |

调用者最多的函数：`dfcb5670`（204）、`dfcc82f0`（194）、`dfcb56b4`（164）、`dfd2c7dc`（91）、`dfcc831c`（89）。这些是后续人工阅读的优先入口，不表示语义已恢复。

## 5. 分析不完整 / 失败项（必须保留）

### 5.1 反编译失败 71 个

`failures.tsv` 共 71 行，全部为：

```text
Low-level Error: Bad instruction count exceeded:
...
No pcode could be generated at address: ...
```

或同一类中的指令重叠错误，例如：

```text
dfce6f86  Bad instruction count exceeded / No pcode at r0xdfce701c
dfce96ca  Bad instruction count exceeded / No pcode at r0xdfce9a5a
dfced164  Instruction at (ram,0xdfced16e) overlaps instruction at (ram,0xdfced16c)
```

这些函数的 `.c` 是**反汇编替代**，不是可读 C；报告和 `failures.tsv` 已列出。它们不是“成功反编译”。

### 5.2 未解析调用目标 445 个

- 9,382 个调用流带 Thumb 低 bit；导出器把 `target & ~1` 归一化到偶数函数入口后再查表，避免把 `dfce1803`（实际函数 `dfce1802`）误报为缺失。
- 归一化后仍有 **445** 个偶数目标不在任何识别函数体内：421 个只有 1 个调用点，24 个有多个调用点；最大调用点数 4（`dfcf98f4`）。
- 这些目标可能是未被 Ghidra 识别的函数、数据/跳转表目标、或跨函数共享标签；不能确认全部是真实函数入口。
- 文件：`unrecognized-call-targets.tsv`，含目标、调用点、调用者函数。

### 5.3 Ghidra 日志错误

`console.log` 中 29 条 `ERROR`：

| 类别 | 数量 | 说明 |
| --- | ---: | --- |
| `failed_create_function` | 8 | 函数体包含 referring thunk，Ghidra 拒绝创建，例如 `dfce8ff4`、`dfcebcfe`、`dfd036de`。 |
| `function_body_overlap` | 21 | 函数体修复与已有函数重叠，例如 `dfd358be`、`dfd47b54`。 |
| `arm_analyzer_exception` | 0（最终运行） | 最终运行未记录 ArmAnalyzer ContextChangeException；第一次试跑有，但不作为最终结果。 |

这些错误与 raw binary/Thumb/ARM 混合、函数边界重叠有关；它们限制了“全部代码”覆盖，不能把 12,940 当作完整函数总数。

### 5.4 反编译警告

`console.log` 中 7,345 条 `WARN  Decompiling`：

| 类别 | 数量 |
| --- | ---: |
| `unresolved_constructor` | 6,995 |
| `other_pcode` | 191 |
| `flow_outside_memory` | 147 |
| `unreadable_memory` | 12 |

大量 `Unable to resolve constructor` 说明反编译器的 p-code/调用恢复不完整；C 代码必须回到原始指令核对。`flow_outside_memory` 指向 `bfad12d0` 等未映射地址，说明某些跳转/数据指针超出本 payload 块。

### 5.5 字符串噪声

原始块扫描得到 20,647 条“字符串”，但：

- 只 1,903 条有函数引用；
- 长度 ≥8 的只有 1,204 条，≥16 的 420 条；
- 扫描覆盖代码字节，短串/二进制巧合串大量存在。

因此 `strings.tsv` 是**线索目录**，不是已确认的字符串资源表。

## 6. 真实限制与未证明事项

1. **不是运行期内存**：payload 是从 `.rodata` 提取的静态映像；`0xdfc90000` 是 loader 目标，不代表已读取该地址的运行期内容。
2. **不是完整代码覆盖**：12,940 是 Ghidra 识别函数数；445 个未解析调用目标、8 个拒绝创建函数、21 个函数体重叠、71 个反编译失败都说明仍有未覆盖/未恢复代码。
3. **CPU/ABI 未证明**：选择 `ARM:LE:32:v5t` 是分析模型；payload 明显包含 Thumb 低 bit 调用，Capstone 在若干地址可解出 Thumb/Thumb-2 形态，但不能据此证明真实核心型号或原始 ABI。
4. **image base 为 0**：BinaryLoader 把块放在 `0xdfc90000`，但 `currentProgram.getImageBase()` 记录为 `0x00000000`；导出地址是块地址，不能把 Ghidra 的 image-base 语义当成运行期基址。
5. **无符号/类型信息**：函数名、参数、结构体、字符串关联都是 Ghidra 启发式；C 代码不是原项目源码，不能直接编译或当事实。
6. **无运行期/硬件验证**：未执行该子 CPU，未访问相机/网络/USB，未验证网络、Wi-Fi、T-Kernel 调度或异常路径；所有子系统判断只来自静态字符串/函数引用。
7. **未比较 3.1**：本轮只分析 3.2-cn 的 `@PDI`；没有做 3.1/3.2 payload diff。
8. **未修改固件**：没有重打包、没有生成可刷写镜像、没有改主程序工程或原始输入。

## 7. 复现

```powershell
python -B scripts/analyze-embedded-subcpu.py
python -B temp/pi-embedded-subcpu/build_report_data.py
```

脚本会：

1. 校验 `.rodata/.data/.text` 哈希；
2. 校验 `@PDI` 头、payload 长度、payload SHA；
3. 校验 `0x42eb90` 的 7 条指令字、3 个字面量和 `.data` 描述符 `+0xc`；
4. 提取 payload 到 `temp/pi-embedded-subcpu/payload.bin`；
5. 创建独立 Ghidra 工程并运行 `PrepareEmbeddedSubcpu.java`、`ExportEmbeddedSubcpu.java`；
6. 复核输入/payload 未变、C 文件数与 summary 一致；
7. 输出 `run-inputs.json`、`run-verification.json` 和报告 JSON。

## 8. 主要产物与核验点

| 文件 | 用途 |
| --- | --- |
| `output/embedded-subcpu-2026-10-29/functions.tsv` | 12,940 个识别函数的入口/末端/指令数/调用者/被调用者/字符串/MMIO/payload 引用 |
| `.../decompiled/<entry>.c` | 12,940 个 C 或反汇编替代；失败项在 `failures.tsv` |
| `.../strings.tsv` | 20,647 条原始块 ASCII 串及函数引用 |
| `.../unrecognized-call-targets.tsv` | 445 个未解析调用目标 |
| `.../vectors.tsv` | 7 个向量槽、目标、导出函数 |
| `.../summary.json` | 函数/字符串/成功/失败/耗时 |
| `.../run-inputs.json` | 哈希、头、loader、命令、限制 |
| `.../run-verification.json` | 输入未变、payload 未变、C 覆盖、日志 flags |
| `reports/embedded-subcpu-analysis-2026-10-29.json` | 机器可读汇总（计数、向量、关键函数/字符串、失败原因、限制） |

**主代理核验建议**：

1. 重新计算 `payload = rodata[0x440e00:0x527c00]` 的 SHA，确认 `a48744eb...`；核对 `@PDI +0x08=0x200`、`+0x0c=0xe6e00`。
2. 核对 `0x42ebd0–0x42ebe8` 的 7 个原字和 `0x42ec34/38/3c` 三个字面量；核对 `.data c0a020f0+0xc=0xdfc90000`。
3. 抽查 `vectors.tsv` 与 `functions.tsv`：`dfc90100`、`dfc94e04`、`dfc9d5d4`、`dfc90ac4`、`dfcb4ebc`。
4. 抽查 `summary.json` 与 `decompiled/` 文件名集合是否 12,940 对 12,940；查看 `failures.tsv` 71 行和 `unrecognized-call-targets.tsv` 445 行。
5. 查看 `console.log` 29 条 ERROR、7,345 条反编译警告；不要把 12,940 当作完整代码覆盖。

---

**最终判断**：该 `@PDI` payload 已被隔离 Ghidra 12.2 以 `ARM:LE:32:v5t` 在 `0xdfc90000` 完成自动分析并导出 12,940 个识别函数、20,647 条串和完整调用目录；容器/loader 关系有逐字节证据。分析仍有 71 个反编译失败、445 个未解析调用目标、8 个拒绝创建函数和 21 个函数体重叠，且存在大量反编译警告；不能把本次结果称为该子 CPU 的完整代码恢复。未修改任何固件或原始输入。
