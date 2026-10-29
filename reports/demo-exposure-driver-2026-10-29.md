# demo-exposure-driver：取景时间边界的实验包装器

> **事故后状态：3.2-d1 已撤回，请勿刷写。** 本文保留离线研究阶段的证据与命令；参见[事前声明](../docs/pre-use-disclaimer.md)及[事故记录](firmware-incident-2026-10-29.md)。软件检查通过不代表硬件可启动。

日期：2026-10-29。状态：**实验性、离线局部验证、默认禁用、未在相机验证、未生成固件包**。本设计不使用旧 `cfg+0x30` 注入；它直接接入取景时间施加调用点 `0x365684`，只改变传给原时间驱动的时间参数。

- 补丁草案：`config/patches/demo-exposure-driver.json`
- 机器可读结果：`reports/demo-exposure-driver-2026-10-29.json`
- 设计/汇编/测试：`temp/demo-exposure/`（`design.md`、`wrapper.S`、`hook.S`、`wrapper.bin`、`hook.bin`、`test_wrapper.py`、`test-results.json`）
- 未修改 `config/patches/exposure-preview.json` 或其他公共代码；未连接相机/网络、未刷写、未 git 提交。

## 1. 调用点与原指令

```text
0036567c: ldr r0, [r4, #0x38]   ; state 0xc14707e0 + 0x38，原取景时间量
00365680: mov r1, #0
00365684: bl  0x35b35c          ; 原时间施加；本补丁只改这 4 字节
00365688: strb r6, [r4, #0xe3]
```

- 位于 AE 回调 id=4 `0x365634`；`r4=state=0xc14707e0`，`r5=0xc14708d0`，`r6` 来自前面的回调代码。
- 原字节 `34d7ffeb`；新字节 `b71100eb` = `bl 0x369d68`（Capstone 已核）。
- 包装器最终仍执行真正的 `0x35b35c`；没有用桩替代原时间驱动。

## 2. M 门控：读当前 `ctrl+0x4c`

- `0x36e8b8` 明确把 `ctrl+0x4c` 复制到 snapshot `+0x1c`；`0x361ad4` 再把 snapshot `+0x1c` 复制到 cfg `+8`。所以 `0xc1469694+0x4c` 是 cfg+8/snapshot+1c 的共同来源，值为 **1 = M**。
- 调用点 `r5=0xc14708d0`，其 `+8` 语义在本次有界核对中**没有证明**，因此包装器不读 `r5+8`，也不猜 `r4/r5` 布局；直接读 `ctrl+0x4c`。
- 已核对的写入路径（静态 C/TSV，非全程序别名穷举）：
  - `0x354c04`：`ctrl+0x4c = param[1]`；caller `0x87f1c` 从 setting `+0xb7` 写入，是档位/AE 模式更新路径。
  - `0x35b678`：`ctrl+0x4c = payload[2]`（AE 字段应用）。
  - `0x35f9d4`（取用/写入代码在 0x35f9d8 一带）：AE 调试参数 `+0x20` 写入 `ctrl+0x4c`。
  - 另发现 `0x3580e4`、`0x38c760`、`0x3e9a4c`、`0x3fa89c` 等函数含 `+0x4c` 存储且引用 `c1469694`；未做完整 points-to/alias 证明，因此列为限制。
- 读取在每次调用时发生，取当前值，不缓存旧模式。

## 3. 包装器

位置：`0x369d68–0x369dcf`，**104 字节**；候选死区 `0x369d68–0x369e18` 共 176 字节，剩余 72 字节未用。旧 88 字节补丁不再使用。

伪代码：

```text
save r4,lr; pad; save r0-r3,ip          ; 32-byte frame, 8-byte call alignment
if ctrl+0x4c != 1: goto original
if [0xc150f9f4] == 0: goto original
  r0 = original time (stack)
  r1 = EV cache (tenths EV)
  bl 0x35d254                           ; 原缩放/目标助手
  r1 = 0
  bl 0x35b35c                           ; 原时间驱动
  goto done
original:
  r0 = original time
  r1 = original r1 (0)
  bl 0x35b35c
done:
  [sp] = r0                             ; 原调用返回值
  pop r0-r3,ip; add sp,#4; pop r4,pc
```

- **不写 `state+0x38`**；每帧都从原值开始，避免永久累乘。
- 非 M 与 M+EV=0：原参数、原 `0x35b35c`、原返回路径；额外保存/恢复 `r1-r3/ip`（比原调用更保守）。
- M 且 EV 非零：先调原 `0x35d254` 缩放时间，再把结果交给原 `0x35b35c`；原驱动的帧期/行计数/限幅继续执行。
- **CPSR**：不显式恢复入口 CPSR；所有路径最后都执行真正的 `0x35b35c`，其后的 `str/pop` 不改标志。因此非 M 的 CPSR/标志效果与原调用一致；测试中基线、非 M、M+EV0 的 CPSR 均为 `0x20000013`。
- **寄存器/SP**：`r4-r11/SP/LR` 恢复；`r1-r3/ip` 也保存恢复；`r0` 为原 `0x35b35c` 返回值。栈帧 8+4+20=32，调用时 8 字节对齐，返回后 SP 等于入口。

### 3.1 原始字节

- Hook `0x365684`：`b71100eb`
- Wrapper `0x369d68`，104 字节：
  `10402de904d04de20f102de94c309fe54c30d3e5010053e30900001a40309fe5003093e5000053e30500000a00009de50310a0e12ccdffeb0010a0e36cc5ffeb020000ea00009de504109de568c5ffeb00008de50f10bde804d08de21080bde8949646c1f4f950c1`
- SHA-256：`44cef90c5b7275dd908a425ed43773aafc87739aa1a185e62b217f716e5961bc`
- 汇编器：项目内 `vendor/arm-binutils/usr/bin/arm-none-eabi-as` 2.45.50（WSL Ubuntu 调用；未安装全局、未联网）。汇编源码见 `temp/demo-exposure/wrapper.S`、`hook.S`；未自写 ARM 编码器。

反汇编关键点：

```text
369d68: push {r4, lr}
369d6c: sub sp, sp, #4
369d70: push {r0, r1, r2, r3, ip}
369d74: ldr r3, =0xc1469694
369d78: ldrb r3, [r3, #0x4c]
369d7c: cmp r3, #1
369d80: bne 0x369dac
369d84: ldr r3, =0xc150f9f4
369d88: ldr r3, [r3]
369d8c: cmp r3, #0
369d90: beq 0x369dac
369d94: ldr r0, [sp]              ; time
369d98: mov r1, r3               ; EV cache
369d9c: bl 0x35d254
369da0: mov r1, #0
369da4: bl 0x35b35c
369da8: b 0x369db8
369dac: ldr r0, [sp]              ; original path
369db0: ldr r1, [sp, #4]
369db4: bl 0x35b35c
369db8: str r0, [sp]
369dbc: pop {r0, r1, r2, r3, ip}
369dc0: add sp, sp, #4
369dc4: pop {r4, pc}
369dc8: .word 0xc1469694
369dcc: .word 0xc150f9f4
```

> 上列地址为链接视图；实际 wrapper 的 `bl` 目标由 `objdump` 核对为 0x35d254/0x35b35c。literal 位于 0x369dc8/0x369dcc；补丁清单包含完整 104 字节。

## 4. 局部原指令仿真

`python -B temp/demo-exposure/test_wrapper.py`

复用 `scripts/check-exposure-preview-patch.py` 的 Unicorn ARM926 内存图与 `execute()`；为 104 字节包装器把补丁代码读取允许范围扩到 `0x369dd0`。执行从 `0x36567c` 到 `0x365688` 的**真实调用点**，内部执行真正的 `0x35d254` 和 `0x35b35c` 链（含 `0x391fdc → 0x3b8ef8 → 0x3ba548 → 0x2445e8`），不是函数桩。

合成硬件模型：帧行数/行时钟、`0x30100590` 的 ready 位、SPI 完成位；这些是 Unicorn 夹具输入，不是相机证据。

结果（`temp/demo-exposure/test-results.json`）：

- **22 个用例，0 失败**。
- 基线：时间 33333、M 模式、EV=20（基线不读缓存）→ 8 个 MMIO 时间字，`r0=0x8229`，CPSR `0x20000013`。
- 非 M 模式 0/2/3/4/5，EV=20：`r0` 与 8 个 MMIO 时间字与基线**一致**；`r4-r11/SP/LR/CPSR` 与基线一致；`state+0x38` 不变；`r1-r3/ip` 恢复。
- M 且 EV=0：与基线一致。
- M 且 EV=+20/−20/+50/−50/INT_MIN/INT_MAX：MMIO 时间字改变；`state+0x38` 不变；稳定寄存器/CPSR 一致。**不把这些字节解释为物理曝光量。**
- 时间 1/250/33333/1300000/60000000 与 EV ±20：无非法访存/越界写，`state+0x38` 不变；长帧期行为只跑到原驱动，未做物理闭环。

**验证范围**：调用点单次执行、原时间驱动分支、M/非 M 门控、寄存器/SP/CPSR/返回值、单帧不累乘。**未执行**完整 `0x365344` AE 闭环、调度器、AF/镜头、真实测光、传感器寄存器或 LCD/遥控通路。

## 5. 为什么不直接接用户快门

用户快门在 `setting+0xc`/`ctrl+0x70` 一侧，`0x124a94` 只做了钳位；要把“用户快门”直接送到 `0x35b35c`，必须先证明 setting 值到驱动时间/行计数单位的映射、帧期拆分和镜头/模式门控。本阶段没有找到比 EV 缓存→原 `0x35d254`→原 `0x35b35c` 更可靠且可离线验证的最小接入；直接改 `state+0x38` 或 `0x36be00` M 目标会导致每帧累乘/状态污染，因此不采用。

## 6. 限制

1. `0xc150f9f4` 的十分之一 EV 语义**没有物理标定**；本补丁不声称绝对曝光预览、精确 EV 倍率或最终取景亮度。
2. 缩放后的时间可能超过帧周期；原 `0x391fdc/0x35b35c` 的帧期处理与原驱动限幅继续执行，但未证明所有长快门/边界都正确。
3. M 门控读当前 `ctrl+0x4c`；已核对主要写入路径，但未做全程序别名/points-to 穷举；若运行期有未识别写者，门控可能不反映当前档位。
4. 包装器占 104/176 字节候选死区；死区“顺序入口不可达”仍是既有直接分支/ADR/对齐指针扫描结论，未重新做全量动态证明。
5. 未在相机验证；非 M 仅局部 Unicorn 验证，不能外推整机所有模式、AF、闪光、录像、长曝光或恢复行为。
6. 不生成固件包、不修改重打包工具、不修改现有 `exposure-preview.json`；本清单只是实验草案，默认禁用。

## 7. 复现

```powershell
# 汇编（WSL，项目内工具）
wsl -d Ubuntu -- bash -lc 'cd <project-root-in-wsl> && ./vendor/arm-binutils/usr/bin/arm-none-eabi-as -march=armv5te -o temp/demo-exposure/wrapper.o temp/demo-exposure/wrapper.S'
# 验证
python -B temp/demo-exposure/test_wrapper.py
```

脚本只读原参考解码文本/数据，写入 `temp/demo-exposure/`、`config/patches/demo-exposure-driver.json` 和本报告/JSON；没有相机、网络、刷写或 git 操作。
