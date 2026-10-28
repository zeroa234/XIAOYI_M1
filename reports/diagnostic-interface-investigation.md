# YI M1 诊断/日志读取接口离线审计

日期：2026-10-26。对象：官方 3.2-cn 机身固件（C59Y1 / M1CN / Ver1.42），镜头 12-40mm 与松下镜头均出现取景亮度不随曝光变化；用户报告随机完全挂死 5 次，电源开关无效、必须拔电池，且无可复现的最后操作。

本报告只回答“有没有可验证的只读诊断/日志入口”，不定位、不修复根因。没有运行相机、没有访问 E:、没有连接蓝牙/Wi-Fi 设备、没有改网络、没有刷写或写入 SD 卡。固件文本来自实验性解压，字符串和偏移只作线索；本报告把“固件字节/表项直接证据”和“仅字符串/二手分析”分开标注。

## 结论摘要

1. **本次检查未找到经过验证的、可由普通用户读取的系统崩溃日志接口；这不等于该接口绝对不存在。** 未发现崩溃文件名/路径、HTTP 日志端点、BLE 日志特征或 USB 串口；现有 USB 证据只是 Windows 侧 SD 卡大容量存储。
2. **有原始实现佐证的软件接口主要有两类；其中只有状态/文件读取是只读，`RCStartRemoteCtl`/`RCStopRemoteCtl` 会切换相机模式，不是只读操作：**
   - Wi-Fi HTTP：`GetCameraStatus`（电池、剩余张数、镜头版本）和 `GetFileList`/`GetFile`（枚举/下载相机可见文件）。它们是状态/文件接口，不是 CPU、内存、任务或崩溃日志接口。
   - BLE：可读机身/镜头固件信息和区域，配对后开 Wi-Fi、取 SSID/密码。没有日志特征。
3. **固件内确实存在与“日志”有关的实现线索，但没有一条被验证为可读的系统崩溃记录：**
   - `.log_save` 是主程序内未压缩装载/节表（`0.00004096`，不是独立 PTBL 分段）中的一块 **2 MiB RAM 区域**（0xc1c00000–0xc1dfffff），名字像日志保存区，但本次未找到读取它的文件/协议入口。
   - `AE_DBG.TXT`、`ESTEG*.DBG` 是成像/启动阶段调试输出文件名，未验证是否在正常拍摄中生成，也没有可读路径。
   - `WIFIDUMP.SDK` 是服务模式触发名，二手静态分析认为它只把 Wi-Fi 调试打印送到控制台/UART，不写文件；不能把它当日志文件，也不应据此在 SD 卡上创建触发文件。
   - `TRAP`、`errlog:`、`syslogTask`、`wlc_dump*` 属于 Broadcom Wi-Fi 固件调试，不是主系统崩溃记录。
   - `INTERNAL MEMORY DUMP!!!` 位于固件升级/装载路径，不是运行期崩溃转储。
4. **如果一定要取得挂死时的直接证据，下一步应是“一次有仪器的运行”（UART/JTAG 或至少下一次挂死时先做只读保全），而不是继续让用户反复复现。** 详见最后一节。

## 证据分级

| 级别 | 含义 | 本报告中的例子 |
| --- | --- | --- |
| A | 有原始开源实现，且作者在 3.2-int 实机验证 | Wi-Fi HTTP 命令、BLE 配对/固件信息、USB 大容量存储 |
| B | 本机 3.2-cn 固件字节/表项直接可见，但解压器实验性 | `.log_save` 表项、`GetCameraStatus` JSON 模板、`.SDK` 文件名表 |
| C | 只有字符串、代码引用或二手静态分析，未独立验证行为 | `AE_DBG.TXT`/`ESTEG*.DBG` 的生成条件、`WIFIDUMP.SDK` 的文件行为、UART 控制台 |
| D | 未找到或不可用 | 系统崩溃日志文件、CPU/内存/任务状态、可读的 `.log_save`、PTP/MTP |

## 一、有原始实现佐证的接口（区分只读与非只读）

### 1. Wi-Fi HTTP（最可用的软件入口）

来源与验证：

- `bullbin/xiaoyi_m1_re_liveview`：README、`prot_http/const_http_cmd.py`、`command_http.py`、`debug_html.py`。作者称在 3.2-int 上验证；相机地址 `192.168.0.10`，命令通过 `GET http://192.168.0.10/?data={...}` 发送。
- `echeetah/yi-m1-monitor`：`fable research/live-testing-findings.md` 记录了 3.2-int 实机返回：`GetCameraStatus` 为 200，返回电池 75%、691 张剩余；`GetFileList` 的条目含 `path/date/filetype/protectStatus`。
- 本机 3.2-cn 固件中直接找到 `GetCameraStatus` 的 JSON 模板（`m1-3.2-cn.analysis.bin.0.00008192.decompressed` 偏移 1385508）：

  ```text
  {"batteryLevel":"%d","SurplusPhotoCnts":"%d","lenVer":"%d.%d","lenType":"%s"}
  ```

  这说明它只含电池、剩余张数、镜头版本/类型，不含 CPU、内存、任务、错误计数或崩溃信息。

可用命令（均有原始实现；仅状态/文件读取是只读）：

| 命令 | 作用 | 诊断价值 | 限制 |
| --- | --- | --- | --- |
| `GetCameraStatus` | 电池、剩余张数、镜头版本 | 可作为“相机是否仍响应”的心跳；挂死时若网络栈仍活，可记录最后响应时间 | 不含 CPU/内存/崩溃信息；Wi-Fi 模式下屏幕会被占用，可能改变挂死条件 |
| `GetFileList` | 枚举相机可见文件 | 可检查挂死后 SD 根目录是否多出日志文件（若接口能看到根目录） | 现有客户端只验证了媒体文件；是否接受根目录/隐藏文件未验证 |
| `GetFile` | 按路径下载文件 | 唯一已知的只读文件下载原语；若将来确认日志路径，可下载 | 路径白名单/可接受范围未验证；不能读 RAM |
| `RCStartRemoteCtl`/`RCStopRemoteCtl` | 开始/结束远程控制、UDP 实时取景 | 可取实时取景元数据（ISO/快门/光圈等），用于曝光预览问题 | **非只读**，会切换相机工作模式；不是崩溃日志 |

**本次未找到** HTTP 侧的日志下载命令、CPU/内存状态命令或崩溃查询命令；不能据此断言这些接口绝对不存在。固件命令表中的 `GetFileList/GetFileInfo/GetFile/GetCameraStatus` 都是文件/状态类；`CheckPreUpdate/UpdateFW` 是升级类，不应作为诊断入口。

### 2. BLE（只读固件信息，不是日志）

来源与验证：

- `bullbin/xiaoyi_m1_re_liveview` 的 `prot_ble/ble_keyhack.py`、`const_ble_uuid.py`，README 说明在 3.2-int 实机验证。
- 服务 UUID：`41106dd9-25ad-477b-a884-5038b6de4649`。
- 可读固件信息特征：`41106da2-25ad-477b-a884-5038b6de4649`，返回协议版本、机身固件、区域、镜头固件。
- 其他特征用于配对、会话、Wi-Fi 开关、SSID/密码；未知通知特征 `41106dae/daf` 在原实现中只是打印未处理数据，未证明是日志。

**结论：BLE 可以只读机身/镜头版本和区域，不能读系统日志、CPU、内存或崩溃记录。** 若只想确认版本/区域，BLE 是低风险入口；对挂死诊断帮助有限。

### 3. USB 大容量存储（只能看 SD 卡）

项目前一轮只读检查中，Windows 将设备枚举为 `YI YI-M1 USB Device`/DiskDrive，E: 为 exFAT SD 卡；本机未实际读取 USB 描述符，`bInterfaceClass=8` 来自二手实机记录（echeetah），未在本机复核。现有证据只能说明 Windows 侧表现为大容量存储，不是 PTP/MTP 或 USB 串口；不能由此推定可访问运行中的相机内存或故障日志。

完全挂死后 USB 是否仍能枚举尚未测试，不能预设为不可用。若仍能枚举，这是无需拆机就可能拿到“SD 上新生成文件”的途径。

## 二、固件内的日志线索：哪些是文件、哪些只是打印

### 1. `.log_save`：2 MiB RAM 区域，但不是可读文件

本机 3.2-cn 主程序内未压缩装载/节表 `output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00004096`（不是独立 PTBL 分段）中，`.log_save` 表项位于文件偏移 0x5f0，其 24 字节头（0x5e0 起）解析为：

```text
address = 0xc1c00000
length  = 0x00200000  (2 MiB)
flags   = 0x0000000c
name    = .log_save
```

这是本机固件的直接表项证据（B 级）。它说明装载/节表为日志预留了 2 MiB RAM，**不证明**：

- 它保存的是崩溃日志还是普通运行日志；
- 它跨复位保留；
- 有任何 HTTP/BLE/USB 读取路径。

没有找到 `.log_save` 的文件名、路径或协议入口。它只能作为将来 UART/JTAG/内存转储的目标线索，不能作为当前可用的诊断接口。

### 2. `WIFIDUMP.SDK`：Wi-Fi 调试开关，不是日志文件

本机 3.2-cn 证据：

- `.rodata` 偏移 989649 处字符串 `WIFIDUMP.SDK`（`ascii-strings.txt` 第 6833 行）。
- `.data` 虚拟地址 0xc09b4b20 起有一张 10 项文件名表：`NOSLEEP.SDK`、`SLEEP1.SDK`、`IMAGER.SDK`、`BATLIFE.SDK`、`NONAIL.SDK`、`NODIST.SDK`、`AUDIOADJ.SDK`、`WIFIDUMP.SDK`、`SHORTPIC.SDK`、`SHORTMOV.SDK`。
- `.text` 虚拟地址 0xabbc4 的常量池引用该表；`TEST MENU`、`PLAY TEST`、`DARK TEST`、`TSD TEST` 等字符串也在同一区域被引用。

二手静态分析（`echeetah/yi-m1-monitor` 的 `agent-tasks/AGENT_RESULT_10_wifidump.md`）对 3.2-int 的结论是：`WIFIDUMP` 被 7 处代码以索引 7 读取，命中后只调用一个类似 `printf/puts` 的函数输出 `[WIFI] ...` 网络事件，**没有打开/写入任何文件**。本机 3.2-cn 在对应地址（0x21870、0x219cc、0x21fe0、0x22100、0x22248、0x24e44、0x24ff0）确实存在相同的 `mov r0,#7` 调用序列，说明该分析至少与本机代码布局一致；但“只打印、不写文件”仍是二手静态结论，未在本机动态验证。

**因此：**

- 不能把 `WIFIDUMP.SDK` 当日志文件名；
- 不应在 SD 卡上创建它来“打开日志”；
- 它最多说明服务模式可把 Wi-Fi 调试打印送到控制台/UART，而控制台是否可接触仍未验证。

### 3. `AE_DBG.TXT`、`ESTEG*.DBG`：普通成像/启动调试文件，生成条件不明

本机 3.2-cn 中直接可见：

- `.rodata` 偏移 4333093 处 8.3 文件名 `AE_DBG  TXT`（对应 `AE_DBG.TXT`），附近有 `pz:%03d`、`ev:%03d`、`fl:%02d`、`shut:%06d`、`sens:%04d`、`fno:%03d`、`so:%d em:%03d ccd:%03d` 等格式化字符串；`.text` 虚拟地址 0x35f488 有对该文件名的引用。
- `.rodata` 偏移 0xb2e 处 `ESTEG.DBG`，附近还有 `ESTEG1.DBG`…`ESTEG4.DBG`；`.text` 虚拟地址 0xf218 有对 `ESTEG.DBG` 的引用。它们与 `BT_*` 启动阶段字符串相邻。

这些证据说明固件包含**成像/启动调试文本输出**的实现线索（B/C 级），但：

- 没有验证正常拍摄或正常启动时是否真的会在 SD 根目录生成；
- 没有找到开关、文件名路径或“何时写”的条件；
- 即使生成，也只是普通成像调试输出，不是系统崩溃记录。

用户下次挂死后，若 SD 根目录出现这些文件，应原样复制后再分析；不建议为了触发它们而主动制造 SD 调试配置。

### 4. 其他“日志”字符串的归属

| 字符串/区域 | 归属 | 是否系统崩溃记录 |
| --- | --- | --- |
| `[WIFI] DHCP...`、`errlog: lo...`、`TRAP ...`、`Memory usage`、`Stack bottom...`、`syslogTask`、`wlc_dump*` | Broadcom Wi-Fi 固件/驱动调试（`.rodata` 495k–509k 附近可见 `BRCM4`、`43430a1`、`7.10.48.2` 等） | **不是**主系统崩溃文件；更像 UART/控制台输出 |
| `DBG:Error log`、`ERR %s`、`ERR!! REFFER LOG`、`Function LOG:%s`、`SIGPRO_*DUMP*` | 成像/AWB/校准调试打印 | 不是 |
| `INTERNAL MEMORY DUMP!!!` | 固件升级/装载路径（`.text` 偏移 284076 附近与 `NANDDATA VERSION`、`LOADDATA UPDATE` 同区） | 不是运行期崩溃转储 |
| `SYSTEMERR %d`、`OS ERROR %d`、`STACK ERR %d`、`0 DIV ERROR` | 启动/系统错误码字符串，可能显示在屏幕 | 没有找到写文件或读取路径 |
| `AE_DBG.TXT`、`ESTEG*.DBG` | 成像/启动调试文件 | 不是 |

## 三、明确不可用/未证实的接口

1. **系统崩溃日志文件**：本次未找到文件名、路径、HTTP 命令、BLE 特征或 USB 接口，不能据此断言绝对不存在。`errlog`/`syslogTask`/`TRAP` 均不能证明存在可读的持久化崩溃记录。
2. **CPU/内存/任务状态**：已知 `GetCameraStatus` 模板只有电池/张数/镜头；本次未识别出可读取 CPU 负载、内存、任务栈或看门狗计数的已验证 HTTP/BLE/USB 入口。
3. **`.log_save` 读取**：当前只有装载/节表中的内存区域线索，未找到可用读取入口；后续内存获取方式待验证。
4. **UART 控制台**：固件有 UART 代码和大量调试打印，但没有 `console/shell/login` 等交互式控制台字符串；UART 同时被蓝牙 HCI 使用。没有找到外部调试口、引脚、波特率或 USB CDC 配置。拆机接 UART 是可能路径，但不是已验证的现成接口。
5. **内部 TEST MENU / `.SDK` 服务模式**：字符串和表项存在，但进入方式、行为、风险均未验证；其中 `IMAGER.SDK`、`AUDIOADJ.SDK`、`NODIST.SDK` 等带有校准/调整含义，不能作为诊断建议。
6. **PTP/MTP**：固件含 MTP 字符串，但 Windows 侧枚举为 Mass Storage；本次未发现可用的 PTP 诊断通道。

## 四、对“挂死 5 次、无最后操作”的具体建议

目标是在**不再增加挂死次数**的前提下取得证据。建议按下面顺序，只做一次“挂死保全”，不做反复复现：

### 第 1 步：下一次挂死时，先保全现场（不增加新挂死）

在拔电池之前，按顺序尝试（全部只读）：

1. **拍照/录像记录屏幕**：若出现 `SYSTEMERR`、`OS ERROR`、`STACK ERR` 等错误码，记录完整数字；这些字符串存在，但含义未解析。
2. **插 USB，看 SD 是否还能挂载**：若电脑还能看到 SD 卡，立即：
   - 列 SD 根目录，记录新增文件名和时间戳；
   - 只复制，不写入、不删除、不格式化；
   - 重点看是否出现 `AE_DBG.TXT`、`ESTEG*.DBG`、`.SDK` 或其他新文件。
   这一步可以把“普通成像调试输出是否落盘”变成事实，而不是猜测。
3. **若挂死前 Wi-Fi 已开启且电脑仍连着相机网络**：只发一次 `GetCameraStatus`，记录是否有响应、返回内容、时间。若还能响应，说明网络栈/部分系统仍活；若不能，至少得到“最后响应时间”。不要在挂死状态下反复发命令。
4. 之后再拔电池/重启。重启后再次对比 SD 根目录，确认是否有重启后才写出的文件。

### 第 2 步：若第 1 步没有任何新文件/错误码

则**不要继续用用户机反复试**。后续可能需要硬件调试条件，但它不是已经验证可用的现成方案：

- 本次没有确认主控 UART/JTAG 的引脚、电平、接入条件或运行期可用性，不提供接线或供电数值。
- 若以后确认可用调试口，可考虑一次从启动到挂死的有仪器捕获；先区分主系统与 Wi-Fi 控制器的输出。
- `.log_save`（装载/节表记录为 0xc1c00000、2 MiB）可作为内存读取线索；是否存有相关日志和是否能读取均未知。

在没有 UART/JTAG 的条件下，**不建议**通过创建 `WIFIDUMP.SDK` 或其他 `.SDK` 文件来“打开日志”：行为未验证，部分模式可能触碰校准数据，而且现有分析认为 `WIFIDUMP` 本来就不写文件。

### 第 3 步：与曝光预览问题分开处理

曝光预览可以独立于挂死做低风险只读验证：

- 用 Wi-Fi HTTP + UDP 实时取景元数据读取 `ISOSetting`、`ShutterSpeed`、`Fnumber`、`EV` 等字段，确认调整参数后相机内部状态是否真的变化；
- 同时拍一张照片检查最终文件曝光。这样可区分“参数没生效”“实时取景不模拟曝光”“视频/照片路径不同”，不需要制造挂死。

### 关于 3.1 回退

用户已确认回退可行。3.1 应只作为**对照和恢复备用**，不是本轮修复目标；在取得 3.2 的挂死现场证据前，不能把“回退后较少挂死”当作根因结论。目标仍是保留 3.2 功能，修复稳定性与曝光预览。

## 五、来源与复现入口

本机固件证据（实验性解压，偏移仅对本地文件）：

- `output/body-3-2-cn/ascii-strings.txt`：第 6833 行 `WIFIDUMP.SDK`；第 6836 行 `TEST MENU`；`ESTEG.DBG`、`AE_DBG  TXT`、`GetCameraStatus` 等可按文本检索。
- `output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00004096`：主程序内未压缩装载/节表（不是独立 PTBL 分段），`.log_save` 表项在 0x5e0–0x5ff。
- `output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00008192.decompressed`：主 `.text`；`GetCameraStatus` JSON 模板偏移 1385508；`INTERNAL MEMORY DUMP!!!` 偏移 284076；`DBG:Error log` 偏移 4001140。
- `output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.03127296.decompressed`：`.rodata`；`WIFIDUMP.SDK` 偏移 989649；`AE_DBG  TXT` 偏移 4333093；`TRAP`/`errlog`/`syslogTask` 在 495k–509k 附近。
- `reports/unpack-summary.json`、`reports/findings-2026-10-26.md`：输入哈希、分段和实验解压限制。

开源实现/公开来源：

- https://github.com/bullbin/xiaoyi_m1_re_liveview （HTTP 命令、BLE 配对、3.2-int 验证说明）
- https://github.com/echeetah/yi-m1-monitor （3.2-int 实机 HTTP 结果、`AGENT_RESULT_10_wifidump.md`、Ghidra 分析）
- https://github.com/protyposis/yi-mirrorless-firmware-tools （固件拆包，实验性）
- 项目内 `reports/findings-2026-10-26.md`、`docs/research.md`、`docs/reproduction.md`

## 六、边界声明

- 本报告没有定位或修复挂死根因，也没有证明 3.2 的挂死由 CPU 性能、某个死锁、SD 卡、镜头或参数记忆导致。
- 字符串存在不等于功能存在；二手静态分析不等于本机动态验证；实验性解压偏移不等于运行期地址。
- 没有验证的外部接口（UART、服务模式、PTP）不能写成“可用”，也不能写成“绝对不存在”；本报告只说明当前没有可验证的现成读取途径。
