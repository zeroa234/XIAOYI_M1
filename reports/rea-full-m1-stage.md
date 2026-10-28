# 完整 M1 REA 分析阶段存档

2026-10-26。用户要求本阶段结束后暂停并交给 Claude。本轮完成离线分析、验证与证据归档；没有修复性能/曝光预览，没有刷机或相机操作。交接入口：`docs/project-status.md`。

## 分析是否真正完成

完整分析包装已由 REA/Ghidra 12.1.4 以 `ARM:LE:32:v5t`、compiler spec `default` 完成自动分析，日志耗时约 717 秒。此前 600000ms startup 超时有权威 provider_timeout 结果并完成清理；M1 profile 调整至 1200000ms 后重试成功。通用 REA 默认不受影响。

- 目标 SHA-256：`8ec01587ac5df600ee58cf35ce99d80f3010a17793d5d64b35105c608ed06056`，分析前后不变。
- 实际 profile digest：`1a6b688add6ff76066434c8ebc602fdcb968c25441053b29b603484bae13e7e9`。
- Ghidra 中 `.text`（0x2000，4445240 字节）、`.rodata`（0x43f800，5703192 字节）、`.data`（0xc09b0000，339536 字节）整块哈希与独立候选数据一致；详见 `rea-full-m1-verification.json`。
- 五个 RAM 范围 `.bss/.noinit/.heap/.rtosmem/.log_save` 保持未初始化，内容未知。不能当零值或实测 RAM。
- REA `inspect_native_load_image` 的独立格式专用 attestation 状态是 `unsupported`，因为当前不支持该 ELF 格式；但其 observations 给出了实际加载块和全块哈希。这里比较的是这些 observations，**没有把 unsupported 改写成完整独立认证成功**。
- ELF 是 GNU 工具构造的分析容器。入口、ARM/EABI 属性由调用者指定，均不证明原固件启动入口、ABI 或实际 CPU 身份，也不证明候选解码已由相机验证。

## 模式、context 与 Y 曲线

`0x3d613c` 的选择器以候选原指令完成 284 项无调用桩 Unicorn 验证，见 `native-curve-mode-validation.md`。完整 REA dossier 给出108字节、27指令、27 callers/37 incoming references，与验证相容。

| 条件 | 结果 |
| --- | --- |
| path=1 | 读 u8[ctx+0x120]；等于1→mode2，否则mode1 |
| path=3 | 读 u32[ctx+0x130]；2→5，3→4，5/6/7→9/8/7，其余已测边界→6 |
| 其他已测 path | mode3 |

`0x8742d2` 是已取得的 rodata，不是未知运行期 RAM。`0xc09e360c` 的十项 provider 指针为：`3dd624, 3dd624, 3df1ac, 3e09b4, 3e1a0c, 3e30ac, 3e2588, 3e3bd0, 3e3e24, 3e419c`。

### 分派与共享助手的实际作用

`0x3d7fa0` 使用表 `0xc09e388c`：`3d622c,3d65f8,3d6750,3d6b28,3d7560,3d6f60,3d7a5c`。path=1 从 idx1 遍历到6，其余分支从 idx0 遍历到6。`0x3bfe18` 是 `add r4,#1; cmp r4,#7; mov pc,lr`，循环调用点在3d7ff4/3d8014，不能因起始索引0/1就断言只调用两项。

`0x126188` 是 `mov r1,r6; mov r0,r5; mov pc,lr`，不是独立读取 mode 的 getter。分派中的 sl/r10 来自 `0x3d609c(path)`：0→2、1→1、3→3、0x15..0x17 经 rodata 表得6/7/8，其他已见分支为0。共享尾 `0x19cf0` 依赖标志。

其他必须按指令核对的助手：`0x35096c` 调 `0x395e7c`；后者 `ldr r0,[r1]; mov r1,#1; mov pc,lr`，解引用的是 r1。`0x350994` 则 `mov r1,sp; ldr r0,[r2]; mov pc,lr`。新 REA 数据库没有旧导出器的 inline 标注，C 伪代码不足以恢复跨助手寄存器语义；部分 value-flow 达3000操作上限，不能宣称分析覆盖完整调用效果。

### 本轮找到的输入生产者

- `0x3d8a08` 构造 context：`ctx+0x120` 字节来自全局 `0xc14699a1`，`ctx+0x130` 字来自 `0xc14699b0`，`ctx+0x148` 初始为0。
- `0x3d8d3c` 调 `0x3d8d10(path)`，将返回 bank 写入 `ctx+0x148`；Y 写入侧取低字节。后者对 path `{1,2,6,7,0xf,0x17}` 返回1，其他为0。bank 尚无真实取景业务名称。
- `0xc14699a1` 写引用在358270（函数3580e4）、392d78（392d4c）、3cf404（3cf3c4）。`0xc14699b0` 写引用在355b80（355b38）、358214（3580e4）、358870（3587ec）。
- `0x355b38` 在355b7c/80将 input+0x60 写到 c14699b0，首字节保存为 path；355bac调3d8a08，355bd8调3d8d3c，355be0调3d7fa0（中间有 outlined helper32240c）。
- `0x81da4` 通过 `0x889f8` 填 input+0x60；`0x81f04` 先调用81da4再调用355b38。889f8受19c5c(2)门控，读取 c140119d 枚举并转换；该枚举的产品含义未证实。
- 81f04的调用者已导出：87da8、3522c、fe834、9e81c、9eb7c、85368、9bb90、abd18。已见传0/1/3及寄存器传参，仍未证明0/1/3分别代表照片取景、拍摄或录像。

### Y 曲线入口仍缺什么

`0x3d6f60` 以 `[0x877e30 + normalizedPath*4 + 0x6e4]==1` 为门控，选 provider、enable 和曲线；`[0x8786e8+0x54]==1` 时在3d7448调用4192fc。前几个 provider 通过共享 `0x3e0748` 存 enable=0，曲线来自 c15a3a64/c15a41c8/c15a4920 等运行期 RAM，当前实际值未知。

既有28项验证已证明 `0x41e7d4 → 0x41ef2c/0x4192fc` 的曲线格式化和72字节配置写入，bank表 `0x853c9c` 前两项为0和0x30000。尚未证明这一阶段控制实际 LCD 取景，更未取得真实取景曝光基准，因此目前没有可验证的曝光预览补丁。

## 卡死：锁初始化有新定位，根因未确认

主代理已从 REA 原指令找到全局 `0xc140e5e0` 的初始化：函数 `0x1fa4c` 清24字节参数块，设置0、0、1、1，在1fad0调用 `0x198b9c`，1fad4载全局地址、1fad8存返回句柄并检查正值。

槽信号量由另一路 `0x126c78(200,524)` 在126d24调用198b9c创建，放入对象+0xc。两条构造调用已找到；198b9c的完整计数语义、运行期句柄生命周期/是否存在别名仍需核实，不能由静态构造直接证明不会死锁。

已知发送侧持外层锁再等空槽；worker在 `0x126e1c` 接收后先清槽/释放槽，再于26abc执行回调。下一步应查回调是否可重入同队列，以及实际错误/等待条件。内核发送199874已见返回0/-18/-42/-17，有效ID1..150；126df8对某些未处理错误自旋，仅有合成条件证明，不等于用户真机故障。不要通过丢弃消息或去掉锁来冒充优化。

Pi pa-89c9d755先前没有找到外层初始化；本轮主代理的1fa4c证据更新了这个缺口。Pi pa-b0d3dfb7的“只有idx0/1”及“rodata未知RAM”已纠正，不引用旧标题作为结论。

## 证据与暂停状态

最终 bundle：`output/rea-mode-review/final-evidence-20261026.json`，90条记录，SHA-256 `6a2fcc810ac7e1aefe1eba1d4731d1112abaa543ae666922c4fa0ae7c80c594d`。

快照：`output/rea-mode-review/analysis-snapshot-20261026.json`，SHA-256 `844f12ad145e824f82f2ec1ae753986f41bce8524a5548ebcee628f485f27ce8`。导出后 close_binary 成功；最终只读复核 open=false、cleanup_pending=false、Pi running_agents=0，WSL ps未见上述分析进程。用户恢复前不启动新调查。

另一条 IPL 线保存在 `ipl-rea-provisional.md`：Pi 原始 session/meta 已复制到 `output/rea-ipl/`，新线索还未主代理逐指令复核。不能把它当作已找出原生 LZSS 解码器。
