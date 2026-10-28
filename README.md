# YI M1 firmware investigation

目标：研究小蚁 M1 最终官方固件中用户报告的随机卡死、操作卡顿及对焦慢问题。

用户明确的交付方向：以官方 **3.2-cn** 为基线保留现有功能，优先定位并修复完全挂死/响应问题，补充曝光亮度预览。3.1 作为对照和恢复备用；用户确认可以回退，回退本身不替代这些修复。

状态（2026-10-27 下午）：已产出第一个测试样机固件 `canary-3.2cn`（只把版本串改为 `3.2-cm`，不改代码，离线验证通过，**尚未刷写**）。远程命令越界修复有补丁清单和模拟器验证，M 档曝光预览只有实验候选，二者都还没打进固件；完全挂死、卡顿、对焦慢仍未定位。当前入口：`docs/project-status.md`。

- 当前设备：YI M1，12-40mm f/3.5-5.6 镜头。
- 版本：用户确认机身及镜头均为官方最新版；待需要时独立读取设备版本。
- 存储：闪迪 64 GB SD 卡；USB 存储卷为 exFAT。用户确认卡内资料已有备份。
- 症状：卡死时机随机，可在不同操作中发生；对焦慢。不能据此认定是 CPU 性能或算法缺陷。
- 最新复测：用户认为参数有记忆，撤回“参数普遍不保存”的初步判断；M 档、固定 ISO、闪光关闭时，光圈/ISO/快门影响成片却不改变照片及视频取景亮度，小蚁与松下镜头均复现。
- 稳定性优先：用户测试期间报告完全挂死 5 次，电源开关无效、必须拔电池恢复，多种操作均可能触发；已停止要求反复真机测试。根因仍未定位。
- 输入：用户提供的三个官方发布包，仅使用项目内副本分析，保留原包。

调查记录见 `docs/research.md`；结果放 `reports/`。固件副本、拆包产物和第三方工具不提交到本仓库，哈希和工具版本记录在报告中。

当前研发状态见 `reports/status-2026-10-26.md`；第一轮事实核实见 `reports/findings-2026-10-26.md`；真机复现步骤见 `docs/reproduction.md`。

其他功能的分层可行性见 `reports/feature-feasibility-2026-10-26.md`：区分已有局部修补、国际版实测但 CN 待验证的录像模式、待逆向的机身 UI 功能，以及可复用现成实现的外部辅助。

取得运行期证据的分阶段路线见 `docs/deeper-debug-plan.md`，包括免拆机调查、主板识别、UART 日志与条件满足后的 JTAG 调试；当前没有已验证的 M1 调试口针脚。

用户现选择免拆机路线。当前软件调查新增了曝光属性/内部消息调用链、24个分派隔离用例及5个消息错误尾部用例；范围和未证实的因果关系见 `reports/software-only-investigation.md`。尚无整机挂死或曝光预览修复。

已在真机建立直接HTTP/UDP取景链路，第二次3秒采集保存13帧且启停回复正常。工具与限制见 `docs/direct-liveview-capture.md`；实测记录见 `reports/liveview-baseline-2026-10-26.md`。这不是机身性能或曝光预览修复。

另测得：每次成功进入遥控后约68秒，相机的 USB 大容量存储会从主机消失，三次复现；取景链路不使用 USB 也不受影响，但读卡需在抓取前完成或改用读卡器。记录见 `reports/usb-storage-teardown-2026-10-26.md`。

已做两轮ISO 100→200→100对照。拉窗帘并用室内灯的那轮，三阶段取景JPEG亮度几乎相同，参数头确认ISO切换；结果及退出状态见 `reports/exposure-probe-results-2026-10-26.md`。快门/光圈尚未由脚本变化测试。用户提出的照片/取景标定及相对曝光模型见 `docs/exposure-simulation-model.md`；没有据此宣称机内功能已经实现。

显示入口调查已定位LCD设备描述关联的命令分派，以及上层成像配置到7项下层处理函数的调用；部分下层函数有寄存器写入。尚未连通到实时取景增益或可独立修改的帧处理接口，详见 `reports/display-entry-investigation.md`。

2026-10-27 下午，用户授权产出测试样机固件，固件工作改由 codex 子代理完成、主代理审查。主程序由 SoC 硬件模块解压（IPL `0x107ac`，无超时），无法在模拟器里证明 token 格式，因此打包采用"官方 token 原样保留、改动处只用字面量"的方法，不依赖硬件未知细节（`scripts/repack.py`、`scripts/verify-build.py`、`tests/test-repack.py`）。零补丁构建与官方包逐字节相同；canary 与官方包只差 4 字节。真机对照证实 P/A/S 已有曝光补偿预览、只有 M 档缺失（`reports/exposure-matrix-2026-10-27.md`），取景快门/增益施加链已定位（`reports/exposure-apply-path-2026-10-27.md`），候选补丁及其未完成部分见 `reports/exposure-preview-patch-2026-10-27.md`。机身上报的镜头识别状态时有时无，与电量下降同步，见 `reports/lens-status-observations-2026-10-27.md`。刷写步骤、风险和下一步见 `docs/project-status.md`。

2026-10-27 起由 Claude 接手离线定位（暂不生成刷机镜像）。已核实：头中 `SUM=` 为段体字节简单累加；两种 LZSS 复制语义在差异处的统计明确支持顺序复制（`reports/pipeline-foundation-2026-10-27.md`，`scripts/check-container-and-decode.py`）。官方升级器在主程序 UI 内，会重写包内列出的 IPL/PTBL；IPL 只在 NAND 的 FIRM 与独立 BOOT 分区间选择启动，外层查不到 FIRM 描述符时回退 BOOT（后经 `reports/repack-pipeline-2026-10-27.md` 收窄：内层解码错误被吞掉、不回退），没有 SD/USB 启动分支（`reports/update-recovery-path-2026-10-27.md`）。取景 AE 核心、档位枚举与 M 档分支已定位，传感器施加路径未找到（`reports/monitor-ae-locate-2026-10-27.md`）。

离线拆包使用现成的 `protyposis/yi-mirrorless-firmware-tools`。自写的 `scripts/unpack.cjs` 只负责固定输入哈希核对、在内存补充已核实的 CN 版本标识和收集分析产物，没有实现新的压缩算法或修改相机程序。安装该工具的锁定依赖后，从项目目录运行：

```powershell
node scripts/unpack.cjs 3.2-cn
node scripts/unpack.cjs 3.1-cn
```

第三方工具源码固定于 `b90b96c124a3b076fa0283404e6595a4a40d20d0`，唯一运行依赖为 `string@3.3.3`。它的重压缩验证存在未解决问题，输出仅供研究。

后续独立审计见 `reports/codec-investigation.md`。另复用了未经修改的 `cebix/ff7tools` 编解码实现；运行 `python -B scripts/reference-decode.py` 可按原厂表长生成单独的候选分析输入，完整尾部明确记录。说明见 `reports/reference-decode-notes.md`。这些候选文件均不是相机更新包。

ARM 静态分析使用项目内 Capstone，固定发行版本见 `config/analysis-requirements.txt`；安装与模块自报版本的区别见 `reports/disassembly-environment.json`。

进一步使用项目内 Ghidra 12.2 / Java 25，来源及摘要记录在 `reports/toolchain-sources.json`。`scripts/analyze-candidate.py` 装载候选并导出重点函数，`--export-only` 复用现有分析数据库。所有偏好、缓存和产物保留在项目内；反编译文本不能代替指令核对。曝光路径复核见 `reports/exposure-decompile-review.md`。

复用 Unicorn 2.1.4 对远程命令搜索循环执行 106 个隔离用例，说明见 `reports/command-bounds-investigation.md`。`scripts/check-command-bounds.py` 只修改模拟器 RAM，不输出修改版固件；此结果尚未与用户日常卡死关联。

USB 大容量存储连接提供的是 SD 卡文件访问，不能由此推定可以访问运行中的相机内存或故障日志。任何修复必须有定位证据、离线验证和真机测试。
