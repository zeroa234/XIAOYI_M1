# M1 LZSS 解码语义：原始启动代码交叉核实

状态：**未证明**（证据不足，明确保留未知）
问题：能否从未压缩的原始启动代码证明 M1 实际 LZSS 解码是逐字节回填（允许 overlap），而不是按通常 LZSS 定义推断？

## 结论先行

**不能。** 本轮只证明了“IPL 是未压缩的 ARM 启动代码，且启动链中存在解码/加载路径”；**没有定位到 LZSS 解码 routine 本体**，因此“逐字节回填 / 允许 distance < length”在本型号上仍是**未验证语义**。现有 `.decompressed` 反汇编、`lzss.js` 自压自解、以及 `codec-check` 统计出的 overlaps（362/36873 等）都不能作为真机语义证据，因为它们都预先假定了该格式与逐字节回填行为。

## 1. 输入、哈希与来源偏移

| 文件（相对路径） | 字节数 | SHA-256 | 在 `m1-3.2-cn.analysis.bin` 中的精确偏移 | 性质 |
|---|---:|---|---:|---|
| `output/body-3-2-cn/m1-3.2-cn.analysis.bin` | 11704832 | `92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4` | 0 | 官方 3.2-cn 拆包容器 |
| `output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00000000` | 4096 | `c90e6cb73c65f6a54e260b169eb511a3a32268af194c69086bdfebecfb8a5bc7` | `0x00000100`（`.0` 内偏移 0） | 未压缩原始段（unpack-summary: `compressed:false`） |
| `output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00004096` | 4096 | `d84cd8d1da041f09cc3acff9e4f76dcd3813abf42169458c87589065f4900810` | `0x00001100`（`.0` 内偏移 `0x1000`） | 未压缩原始段（`compressed:false`） |
| `output/body-3-2-cn/m1-3.2-cn.analysis.bin.2.IPL` | 131072 | `3513946d8068f6a03706bc5ec142fe45122773b2163ef688806afa7e03012dc4` | `0x00b08900` | 原始未压缩 IPL（本报告核心输入） |
| `output/body-3-2-cn/m1-3.2-cn.analysis.bin.0` | 7370752 | `c57a83a6f99896b514d0dde8d4a8d3d037cff71c4470511a7295a0b23a13c950` | `0x100` 起 | body 容器（含 2 个 raw + 3 个压缩段） |
| `vendor/yi-mirrorless-firmware-tools/lzss.js`（只读） | 13739 | `b4a59e82e77b541521d31d6d023fd5c398c6d05dfdafa044c0ae1b8bbe1f09e6` | — | 第三方工具，**未修改** |

偏移是用完整文件内容在容器内逐字节检索得到的，不是按头长度推算。`.0` 的 raw 段位于容器 `0x100` 起，所以 `.0` 内偏移 = 容器偏移 − `0x100`。IPL 在 `.2.IPL` 文件内偏移 0 处即为 ARM 向量表，说明该 artifact 已去掉容器头。

## 2. 已证明（有直接字节/指令证据）

1. **raw 段确实是未压缩的**：`reports/unpack-summary.json` 对两段标记 `compressed:false`，且其内容为 ARM 向量表和段表（`.dtcm/.picbase/.vector/.itcm` 等字符串），不是压缩流。
2. **IPL 是原始未压缩 ARM 代码**：
   - offset `0x00`：`e59ff018` ×5（`ldr pc,[pc,#0x18]`）、`eafffffe`（`b .`）；`0x20`：`000000fc 00000118 0000011c ...` 异常向量目标。
   - offset `0x100`：`e321f0df`（`msr cpsr_c,#0xdf`），随后 `eb000028`（bl `0x1ac`）、`eb00004f`（bl `0x24c`）、`eb000050`（bl `0x254`）、`ebffffca`（bl `0x40`），`eafffffe`。目标地址已按第二阶段 Capstone 结果修正；第一阶段手算分支地址有误。
   - 这些是 ARMv5 指令，不是压缩数据。IPL 的 0x0–0x3fff 低熵（3.52 bit/byte），`0x4000` 起出现 ASCII 数据（`@VRIEV9XES1.0`、`PURENAND1`），约 `0x12000` 之后为全零；即该 128 KB 分区中只有前 ~68 KB 有内容。
3. **启动链中存在“解码”环节（仅此而已）**：IPL 数据/字符串区可见
   - `0x10ae0` `"LoadData[ %-20s ] not found "`
   - `0x110c8` `"loading [%08lx:%8s] ...... "`
   - `0x110f4` `"Decode Error!"`
   - `0x10a58` `".rodata"`、`0x10b5c` `".ver_table"`
   这说明 IPL 有按段名加载 + 解码/校验的路径，但**字符串存在不等于解码算法已定位**。
4. **在原始 raw/IPL 中没有找到 overlap 回填的直接指令证据**：
   - 第一阶段模式扫描不完整。第二阶段 Capstone 确认 `0x0f580` 是字符串比较函数，纠正了第一阶段误判为 memcpy 的结论；另在 `0x5018` 发现逐字节前向拷贝循环，但没有证明其调用者或它属于 LZSS 解码。
   - 两个 raw 4 KB 段内未出现任何 `LDRB/STRB` 字节循环。
   - 第一阶段未匹配到 Thumb-2 形式，不能据此排除 ARMv5 的 Thumb-1 代码。第二阶段已用 ARM 与 Thumb 模式实际反汇编部分区域。
   - 常量扫描不足以确定窗口大小；第二阶段还见到若干硬件配置使用 `0x1000`。它们与解码窗口的关系未证实。
   - 未发现指向 `0x110f4`/`0x110c8`/`0x10ae0` 的镜像内绝对字面量（含低 16 位匹配、MOVW/MOVT 扫描均为 0），所以无法用字符串 xref 追到加载函数，更追不到其调用的解码器。

## 3. 未证明（缺口）

- **解码 routine 的位置、调用关系、输入/输出参数均未知**；因此无法检查其输出指针回填顺序。
- **未证明**“每写出一字节后，匹配拷贝的下一次读取会看到该字节”（即 overlap 语义）；也未证明它会拒绝 `length > distance`。
- **未证明**窗口 4096、最小匹配 3、最大匹配 18、flag 位序等参数适用于本型号。`LOOKUP_BUFFER_SIZE=0x1000`、`LOOKUP_DATA_MAX_INDEX=0x0FFF`、`LOOKUP_DATA_MAX_LENGTH=0x0F`、`LOOKUP_MIN_LENGTH=3` 只出现在 `vendor/.../lzss.js:9-13`，是第三方实现的假设。
- **未证明** vendor 解压产物正确。`codec-check-results.json` 的 overlap 统计（例如子段 00008192 的 362 个）是用该 JS 的 token 解析得到的；若真实格式/边界不同，这些数字本身就不成立，属于循环论证。
- 本报告**没有**使用 `.decompressed` 反汇编或 `lzss.js` 自压自解来论证解码器语义。

## 4. 为什么不能退回到“标准 LZSS 定义”

标准 LZSS 只规定一类编码框架；不同实现中匹配拷贝可以是快照式（先取 length 字节）或逐字节回填（读已写出的输出），二者对 `distance < length` 的 token 产生不同结果。M1 的 routine 未被定位，因而不能用“通常实现允许 overlap”替代本型号证据。当前唯一确定的只是：**原始压缩流里是否存在这种 token，取决于尚未验证的解析器**。

## 5. 环境与工具限制（据实记录）

- 已检查并确认**不存在**：`objdump`、`arm-none-eabi-objdump`、`llvm-objdump`、`clang`、`radare2`、`ghidra`、Python `capstone`/`lief`/`unicorn`/`keystone`。`vendor/.../node_modules` 只有 `string`。
- 因此只能做字节/指令模式扫描与人工 ARM 解码；`temp/boot-decoder-audit/scan.py` 是**模式扫描器，不是反汇编器，也不是新解码器**，未执行任何解压。
- 无网络、无设备、未写 `C:`/`E:`、未改 `vendor/`、未 git 操作、未刷机。

## 6. 若要真正补齐证据（建议的最小路径）

1. 确定 IPL 的运行基址（向量表 `0x20` 的目标是镜像内偏移；需从启动流程/ROM 映射确认基址），然后用真正的 ARM/Thumb 反汇编器解析 IPL 代码段，找到对 `0x110f4 "Decode Error!"`、`0x110c8 "loading..."` 的 xref。
2. 从该加载函数追到解码函数；在匹配分支中确认：
   - 输出指针是否在每次 `strb` 后立即递增；
   - 匹配循环是从 `out - distance` **逐字节**读并写回，还是先缓存 length 字节；
   - 是否有 `length > distance` 的拒绝分支。
3. 或用设备 ROM/厂商源码/可信第三方对该 exact IPL 的反汇编交叉验证。仅当上述任一完成，才能对 overlap 语义下结论。

## 7. 本轮产物

- `temp/boot-decoder-audit/scan.py`：只读模式扫描脚本（LDRB/STRB/Thumb 传输/常量）。
- `temp/boot-decoder-audit/scan.json`：扫描命中列表。
- 本报告与 `logs/boot-decoder-validation.txt`。临时内容均在 `temp/boot-decoder-audit/`。

---

## 第二阶段补充（Capstone，2026-10-26）

- 项目安装的发行包为 **capstone 5.0.9**；模块内 `__version__` 自报 **5.0.7**，核心 API 返回 `(5,0,1280)`。两者须区分，详见 `reports/disassembly-environment.json`。
- **修正**：`0xF580` 是 **strcmp**，不是上一阶段所称的 memcpy；详见 `reports/boot-decoder-capstone.md` §5。
- 新证据：
  - IPL `0x0–0x3FFF` 是 4 份完全相同的 4 KB 启动块（sha256 前缀 `9b80671870cb9656…`）；启动块内只有 ARM 启动/内存清零和 Thumb 硬件初始化，无解码循环。
  - `0x4FF8`/`0x5018` 有后向/前向逐字节拷贝助手；`0x5018` 若以 `src=out-distance`、`dst=out` 调用会自然支持 overlap，但对全镜像 BL/BLX 扫描显示其调用者为 **0**，不能作为证据。
  - `"Decode Error!"`/`"loading"` 等字符串无绝对字面量、无 `base+offset` 字面量、无 ADR、无 MOVW/MOVT、无立即数 xref；加载器使用 `0x2300d080/0x2300d0a4/0x2300d1a0` 的 RAM 表/函数指针。
  - 加载器部分定位：`0x7EA8`（名字匹配）、`0x7C48`/`0x8000`（分块/更新）、`0x793C`/`0x79C0`（块页计算）、`0x4Cxx`（文件系统分发）；其中未见 LZSS 循环。
- **结论不变**：仍未证明真机解码为逐字节回填/允许 overlap；具体缺口见 `reports/boot-decoder-capstone.md` §7。未使用 `.decompressed` 作为证据。
