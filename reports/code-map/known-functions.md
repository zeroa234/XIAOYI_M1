# 已知主程序函数与全局地址总表（种子表）

整理日期：2026-10-27（只读汇总，未新增任何分析）。数据来源仅限 `reports/*.md` 与 `docs/*.md` 中已被报告明确写出的地址与含义；`reports/*.json` 只用于核对邻近说明，未整读。

## 使用须知（读表前必看）

1. 除标为「IPL 文件偏移」的地址外，本表地址都是**主程序候选解码映像的静态 VA**：`.text@0x2000`（长 0x43d438，止于 0x43f438）、`.rodata@0x43f800`（长 0x570618）、`.data@0xc09b0000`（长 0x52e50）。这些 VA 来自标准 LZSS 语义候选解码，**未经真机内存对照**（`freeze-static-audit.md`、`exposure-candidate-disassembly.md`、`rea-full-m1-stage.md`）。
2. 解码语义本身仍只是【统计/结构证据】：token 格式（flag 低位先、1=字面量）由官方流无损往返与两种独立解码器一致支撑，不是硬件原生解码证明；主程序实际由 SoC 硬件模块解压（`0x30140000` 一带，`repack-pipeline-2026-10-27.md` §4）。所以本表适合当"通读代码的种子"，不适合当补丁地址清单。
3. 证据等级一律照抄来源报告的标注：`【主核】`（主代理用 Capstone 亲自核对）、`【子核】`（子代理给出指令、主代理未逐条重看）、`【指令核实】`、`【Unicorn 验证】`、`【真机实验】`、`【统计/结构证据】`、`【推断】`；报告没标的一律写 `未标`。
4. 同一地址在多份报告里有不同说法时，行内标 `冲突`，并在 §4 列出取舍（以较新日期、且被明确纠正过的说法为准）。
5. IPL（另一个映像）的函数与地址**全部**放在 §5，未混入 §1–§3。IPL 运行期 VA = 文件偏移 + `0x22ffc000`。

---

## 1. 主程序函数表（按地址升序）

| 地址 | 暂定名称 | 作用（一句话） | 证据等级 | 来源报告 |
| --- | --- | --- | --- | --- |
| 0x00f880 | `always_zero` | `mov r0,#0; bx lr`，恒返回 0，使 `0x369d50` 的分支恒跳（主核确认属实）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x019c5c | `gate_19c5c` | 门控 `0x889f8` 的调用条件（参数 2）。 | 【主核】 | rea-full-m1-stage.md |
| 0x01b264 | `mode_bsearch_lookup` | 读 `[0xc1401074+0xa9]`，用描述符 `0x531eb8` 二分查找后跳转，写 AE 内部模式。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x01fa4c | `lock_object_init` | 清 24 字节参数块、设 0/0/1/1，在 0x1fad0 调 `0x198b9c`，把返回句柄存入全局 `0xc140e5e0`。 | 【主核】 | rea-full-m1-stage.md |
| 0x02076c | `updater_battery_gate` | `cmp r0,#0x32` 检查电量 ≥50%，是 UI 进升级器前的门。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x0208ac | `updater_ui_menu_entry` | UI 菜单路径，以 mode 0 调用升级执行体 `0x10fe64`。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x026590 | `exposure_mode_json_index` | `ldrb r2,[0xc1401074+0xa9]` 经字节表 `0x5285b3` 换成 JSON 的 ExposureMode 索引。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x026abc | `queue_callback_exec` | worker 接收消息后在此执行回调。 | 【主核】 | rea-full-m1-stage.md |
| 0x026b4c | `queue_object_init` | 装 `0xc14e1258`，调 `0x126c78(200,524)`，再经共享助手 `0x26e38` 写入队列句柄。 | 【主核】 | native-math-and-queue-validation.md |
| 0x026c8c | `message_build_0x15` | 构造编号 0x15、长度 0x20c 的内部消息，把输入指针放到 +0x208，经 `0x126d9c` 传递。 | 【指令核实】 | iso-callback-review-2026-10-26.md |
| 0x026e38 | `shared_store_helper` | `str r0,[r5]` 型共享收尾助手（用于写队列句柄）。 | 【主核】 | native-math-and-queue-validation.md |
| 0x040c84 | `iso_state_select` | 从 `0xc150b5a4` 与输入数值选状态（0x31/0x7f/0x3a 或表 `0x52a52c` 项）。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x040d10 | `iso_state_write` | 真实字面量取 `0xc1401074`（`0x40cc4`），把 r4 写入 `[r5+0xb9]` 并向另两个 RAM 字节写同样值。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x041d98 | `tail_to_message_build` | `mov r2,#0xc; b 0x26c8c`，被 `0x420d0` 尾跳进入。 | 【指令核实】 | iso-callback-review-2026-10-26.md |
| 0x0420c8 | `iso_property_wrapper` | ISO 属性包装：`0x15c67c: bl 0x420c8 → 0x420d0: b 0x41d98 → 0x26c8c`。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x042294 | `callback_descriptor_entry` | `0x420cc` 字面量指向的回调表项，内容为 ISO 回调 `0x44338`。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x042db4 | `ev_property_wrapper` | EV 属性后续包装之一。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x043198 | `shutter_property_wrapper` | 快门属性后续包装之一。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x0432cc | `aperture_property_wrapper` | 光圈属性后续包装之一。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x044338 | `iso_state_dispatch` | 从 `0xc1401074+0xb9` 取状态字节，经 `0x18e740` 查表 `0x52a996` 后按返回值跳转；**该字节业务含义未定**。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x044364 | `dispatch_jump_base` | 调用点把二分查找结果加此基址后跳转。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x0455f0 | `ev_property_callback` | EV 属性查表后跳入的回调。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x045efc | `shutter_property_callback` | 快门属性回调。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x046008 | `aperture_property_callback` | 光圈属性回调。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x07d36c | `ev_json_value_read` | 校验输出指针，读 `[0xc1401074+0xb7]`；等于 1 时调 `0x85d30(0,0)`，否则返回 0。 | 未标 | ev-metadata-source-review.md |
| 0x081450 | `sync_apply_common` | 公共同步调用，5 个调用者（`0x2881c/0x89a0c/0x8de80/0x9785c/0xb7330`）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x081470 | `sync_apply_wrapper` | `add r0,sp,#0xc; bl 0xb7758` 填 8 字 payload，再 `bl 0x354b24`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x081da4 | `imaging_input_fill` | 填 0xf0 字节成像输入结构，`input+0x60` 经 `0x889f8` 写入；也读 `+0xb9` 状态做条件判断。 | 【主核】 | rea-full-m1-stage.md；iso-callback-review-2026-10-26.md |
| 0x081f04 | `imaging_apply_entry` | 栈上准备 0xf0 结构 → 调 `0x81da4` → 0x81f18 调 `0x355b38`；调用者 `0x87da8/0x3522c/0xfe834/0x9e81c/0x9eb7c/0x85368/0x9bb90/0xabd18`（path 0/1/3 业务名未证）。 | 【指令核实】 | iso-callback-review-2026-10-26.md；rea-full-m1-stage.md |
| 0x085d30 | `ev_cache_accessor` | `0xc150f9f4` 的带可选写入访问器：第一参数为 1 时写第二参数，然后返回缓存值。 | 未标 | ev-metadata-source-review.md |
| 0x086898 | `ev_input_build` | 构建 `0x36102c` 的输入（之后 `0x3544c8 → 0x36102c → 0x360f4c`）。 | 【Unicorn 验证】 | native-math-and-queue-validation.md |
| 0x086914 | `shutter_forward_gate` | `ldrsb [0xc1401074+0xb7]; cmp #1/#4`，**只有 M 或 S 档才转发 `[+0xc]`**。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x087f14 | `af_to_ctrl_write_call` | 调 `0x354c04` 把 `af` 送到 `ctrl+0x40`（M 键重配路径）。 | 【Unicorn 验证】 | exposure-preview-patch-2026-10-27.md |
| 0x087f1c | `mode_to_ctrl_write` | 把 `+0xb7` 经 `0x354c1c` 写入 AE 控制块 `+0x4c`。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0x0889f8 | `input60_fill` | 填 `input+0x60`，读取 `0xc140119d` 枚举并转换（枚举产品含义未证）。 | 【主核】 | rea-full-m1-stage.md |
| 0x08c8c4 | `state_save_restore` | 先把 `+0xb9` 字段保存到 sl，调用其他函数后在 `0x8c8d0` 写回（保存/恢复，不是独立曝光设置）。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x10be58 | `pending_flag_upgrade_call` | 读到 RAM 标志 `0xc14ca473` 为 1 时以 mode 1 调 `0x10fe64`。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x10be80 | `boot_pending_upgrade_check` | 以 mode 1 调用升级执行体、先读 `0xc14ca473`，像是开机时检查待升级标志；标志写入者未找到。 | 【推断】 | update-recovery-path-2026-10-27.md |
| 0x10f324 | `ipl_compare` | 逐页比较新旧 IPL，**返回非 0 表示相同**（调用点据此跳过写入）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10f46c | `nand_write_pages` | 写入层：512 字节页、每批 12 页，**无重试、无回滚、无写后回读**，失败返回 -1。 | 【子核】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x10f644 | `updater_write_first_segment` | 写入**无名首段正文**（升级器最后一步）。 | 【主核】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x10f6bc | `segment_dispatch` | 按段号分派写入（0/1/3/5/10，**没有 BOOT**）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10f6fc | `nd1_write` | 段 1（ND1）写入，从 0xb000 扇区起，上限 0x7700 扇区。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10f744 | `nprog_write` | 命名段 NPROG/NPG（段号 0）写入，位置 = `0xb000 − ceil(长度/0x20000)·0x100` 扇区；**冲突**：旧报告把它当作"无名首段"处理。 | 【主核】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x10f774 | `nd2_write` | 段 3（ND2）写入，0x6e00 起，上限 0xb800 扇区。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10f790 | `ptbl_write` | 段 10（PTBL）写入，经 `0x1104a4(…,0x2083/0x2082)`。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10f7c4 | `ipl_write` | 段 5（IPL）写入，先经 `0x10f324(0x64)` 比较，相同则跳过。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10f954 | `updater_parse_header` | 解析 0x100 字节 ASCII 头（`LENGTH=`/`SUM=`/`LOADADDRESS=`），并对段体逐字节累加校验。 | 【主核】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x10fd70 | `counter_toggle` | 在 `0x0115cc00`/`0x00d68400` 两个值之间切换的计数函数，**无静态调用者**，不能据此认为有 A/B 双槽。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10fdd4 | `reboot_after_upgrade` | 成功分支：设 RAM 标志后复位。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x10fe64 | `updater_execute` | 升级执行体，5 个调用点（mode 0 = UI 菜单，mode 1 = RAM 标志触发）。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x110048 | `named_segment_loop` | 循环处理包头列出的命名段：长度 0 则跳过，顺序由固定表 `0x54c1ec` 决定。 | 【主核】 | repack-pipeline-2026-10-27.md |
| 0x1100ac | `first_segment_write` | 循环结束后**总会**尝试写无名首段，不受 ND1/IPL/PTBL 名字是否存在控制。 | 【主核】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x110244 | `source_type_set` | 写入来源类型字节（SD 路径）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x1102c0 | `header_length_check` | 要求段头以 `LENGTH=` 开头。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x1102d4 | `model_string_check` | 要求 `C59Y1` 出现在前 0x40 字节内；`VER=` 只限长度 ≤10 字符。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x110420 | `header_name_find` | 在 0x100 字节头里查找指定段名（找不到则该项长度保持 0）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x1104a4 | `ptbl_write_helper` | PTBL 写入辅助，参数含 `0x2083`/`0x2082`。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x11ba10 | `helper_add1e` | 3 条共享指令：`add r0,r0,#0x1e; mov r1,#0xe; mov pc,lr`（不能按普通六参调用解读）。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x1247b4 | `cmd_0fedbebe_handler` | 第二条升级通路：命令 `0x0fedbebe` 的子命令 0 清 RAM 缓冲、1 追加数据、2 置 `0xc14ca473=1`。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x124a94 | `shutter_clamp` | 把设置结构 `+0xc` 钳到 ≥250（形如快门微秒下限，**单位未证**）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x126188 | `helper_mov_r5r6` | `mov r1,r6; mov r0,r5; mov pc,lr`，不是独立 getter。 | 【主核】 | rea-full-m1-stage.md |
| 0x126c78 | `slot_semaphore_create` | 以 `(200,524)` 创建槽信号量（消息队列容量参数）。 | 【主核】 | rea-full-m1-stage.md；native-math-and-queue-validation.md |
| 0x126d24 | `slot_semaphore_store` | 调 `0x198b9c` 建槽信号量并把句柄放到对象 `+0xc`。 | 【主核】 | rea-full-m1-stage.md |
| 0x126d9c | `message_post` | 发送内部消息，调用 `0x199874` 内核发送。 | 【指令核实】 | iso-callback-review-2026-10-26.md；software-only-investigation.md |
| 0x126df8 | `error_spin` | 未处理的发送错误返回值会走到 `b 0x126df8` 原地自旋（已隔离执行证实）。 | 【指令核实】+【Unicorn 验证】 | software-only-investigation.md |
| 0x126e1c | `queue_worker_receive` | worker 接收后先清槽/释放槽，再在 `0x26abc` 执行回调。 | 【主核】 | rea-full-m1-stage.md |
| 0x126ed4 | `message_error_tail` | 返回 0 直接恢复父栈并返回；返回 -43 时转换为 2。 | 【指令核实】 | software-only-investigation.md |
| 0x14ee54 | `m1cn_compare` | 字符串比较读的是 **`M1CN`**，不是前面的 `3.2-cn`（型号串保持不变）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x1509dc | `version_display_path` | 从 `.rodata 0x6b7f54` 取 `3.2-cn`，以 `Ver`、`%s: %s` 格式化并调用文本测量/绘制（屏幕显示路径，不是 HTTP 版本返回）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x152ecc | `liveview_json_build` | 取景 JSON 生成函数，键名以 PC 相对取址的内嵌字符串逐项拼接。 | 未标 | ev-metadata-source-review.md |
| 0x153038 | `exposure_mode_string_index` | 按索引使用 `0x6b80fc` 的 `{Auto,P,A,S,M}` 字符串。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x153280 | `exposure_mode_string_table` | 指向 `Auto/P/A/S/M` 字符串表，索引 4 确为 M。 | 未标 | ev-metadata-source-review.md |
| 0x1537dc | `ev_field_mode_branch` | 调 `0x156b78`；非 M 跳 `0x1538ac`，M 则 `0x1537e8` 调 `0x7d36c`。 | 未标 | ev-metadata-source-review.md |
| 0x1537e8 | `ev_field_m_read` | M 档把 `0x7d36c` 的结果写入局部数值（部分特殊快门编码会置零）。 | 未标 | ev-metadata-source-review.md |
| 0x153820 | `ev_format_clamp` | 把数值格式化为一位小数，超出 +50/−50 分别显示 5.0/−5.0（机器指令证据的 ±5 限幅）。 | 未标 | ev-metadata-source-review.md |
| 0x1538ac | `ev_field_non_m_read` | 非 M 档从内部属性 0x12 的字符串视图读值。 | 未标 | ev-metadata-source-review.md |
| 0x154ac0 | `app_file_interface` | App 文件接口；`\FIRMWARE.BIN`、`\LENS_FW.lin` 只被它引用。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0x155894 | `http_aperture_handler` | HTTP 光圈命令处理函数（输出动作号 0x1a）。 | 【指令核实】 | software-only-investigation.md |
| 0x155940 | `http_shutter_handler` | HTTP 快门命令处理函数（0x1b）。 | 【指令核实】 | software-only-investigation.md |
| 0x1559a8 | `http_ev_handler` | HTTP EV 命令处理函数（0x1c）。 | 【指令核实】 | software-only-investigation.md |
| 0x155a10 | `http_iso_handler` | HTTP ISO 命令处理函数（0x1d）。 | 【指令核实】 | software-only-investigation.md |
| 0x1568a4 | `remote_cmd_table_copy` | 把 360 字节远程命令表复制到 `sp+0x34`。 | 【指令核实】 | command-bounds-investigation.md |
| 0x1568bc | `remote_cmd_lookup_loop` | 用 `r6*8` 读条目、索引自零递增。 | 【指令核实】 | command-bounds-investigation.md |
| 0x156910 | `remote_cmd_bound_check` | 比较 `r6,#0x168`（360）而非 45 条 → 未知命令时越界读栈；`command-bounds.json` 的补丁点。 | 【指令核实】+【Unicorn 验证】 | command-bounds-investigation.md；exposure-preview-patch-2026-10-27.md |
| 0x15a5b8 | `helper_15a5b8` | 被 `0x156b78` 调用的助手（行为未详述）。 | 未标 | ev-metadata-source-review.md |
| 0x15a7e0 | `property_apply_stage1` | 属性应用到 `0x15db34` 后的第一段（间接跳转未恢复）。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15a840 | `iso_dispatch_block1` | ISO 属性的第一分派块（分析标签）。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15abcc | `ev_dispatch_block1` | EV 属性第一分派块。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15abe0 | `shutter_dispatch_block1` | 快门属性第一分派块。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15ac10 | `aperture_dispatch_block1` | 光圈属性第一分派块。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15c5bc | `property_apply_stage2` | 属性应用第二段（间接跳转未恢复）。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15c670 | `iso_dispatch_block2` | ISO 属性第二分派块。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15c6b4 | `aperture_dispatch_block2` | 光圈属性第二分派块。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15c77c | `ev_dispatch_block2` | EV 属性第二分派块。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15c920 | `shutter_dispatch_block2` | 快门属性第二分派块。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x15db34 | `property_apply_path` | 先调 `0x15a7e0` 再转 `0x15c5bc` 的公共属性应用路径。 | 【Unicorn 验证】 | software-only-investigation.md |
| 0x1623f4 | `action_dispatch` | 用动作号减 `0x13`，从 `0x833040` 的 23 项函数表分派。 | 【指令核实】 | software-only-investigation.md |
| 0x162878 | `property_handler_common` | 属性处理公共段。 | 【指令核实】 | software-only-investigation.md |
| 0x162988 | `aperture_dispatch_entry` | 内部属性 0x14（光圈）分派入口。 | 【指令核实】 | software-only-investigation.md |
| 0x1629a4 | `shutter_dispatch_entry` | 内部属性 0x13（快门）分派入口。 | 【指令核实】 | software-only-investigation.md |
| 0x1629ac | `ev_dispatch_entry` | 内部属性 0x12（EV）分派入口。 | 【指令核实】 | software-only-investigation.md |
| 0x1629b4 | `iso_dispatch_entry` | 内部属性 5（ISO）分派入口。 | 【指令核实】 | software-only-investigation.md |
| 0x17904c | `firmware_info_version_draw` | 从 `.rodata 0x834674` 取 `3.2-cn`，`mov r2,#7` 拷 7 字节后进文本测量/绘制。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x18e740 | `table_bsearch_halfword` | 对表 `0x52a996`（14 项）做字节二分查找取前置半字偏移。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x198b9c | `semaphore_create` | 创建/初始化信号量（被 `0x1fa4c`、`0x126d24` 调用；完整计数语义未核实）。 | 【主核】 | rea-full-m1-stage.md |
| 0x199874 | `kernel_message_send` | 内核消息发送：ID 不在 1..150 返回 -18；注册项 +8 为 0 返回 -42；标志位 2 且节点 +4 非正返回 -17；正常 0。 | 【指令核实】+【Unicorn 验证】 | native-math-and-queue-validation.md |
| 0x2088c4 | `lcd_config_sequence` | 由 `0x223570` 可能调用的 LCD 配置序列处理。 | 未标 | display-entry-investigation.md |
| 0x223390 | `lcd_cmd_routine` | LCD 命令分派表的操作例程之一。 | 未标 | display-entry-investigation.md |
| 0x223570 | `lcd_descriptor_select` | 装载 `0xc09d0638`、读结构指针与输入索引（仅接受 0/1）。 | 未标 | display-entry-investigation.md |
| 0x2235b8 | `lcd_cmd_entry` | LCD 设备命令分派入口（描述符 `0xc09d0638` 偏移 0x48 的函数指针）：命令减 1 查范围后走字节跳转表。 | 未标 | display-entry-investigation.md |
| 0x241a94 | `hw_field_increment` | 对硬件字段加 1（`0x3b8ef8` 时间换算的前置）。 | 【指令核实】 | exposure-preview-patch-2026-10-27.md |
| 0x2423f0 | `tail_read_c1595420` | `0x395c44` 尾跳目标，读取 u32 `0xc1595420`。 | 未标 | exposure-decompile-review.md |
| 0x242604 | `sensor_transport_submit` | 传感器传输提交包装（`bl 0x2445e8`）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x2445e8 | `sensor_transport_write` | 传输层，向 `0x21c00014/0x21c00018` 写命令与数据。 | 【指令核实】+【Unicorn 验证】 | exposure-apply-path-2026-10-27.md |
| 0x244684 | `sensor_transport_poll` | 完成位轮询，最多 10000 次，未完成也返回 0（可能掩盖超时）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md；exposure-preview-patch-2026-10-27.md |
| 0x2adbd8 | `config_item_builder` | 用 `0x2af604` 生成大量配置项（含 Gamma 相关地址）。 | 【指令核实】 | native-math-and-queue-validation.md |
| 0x2af604 | `config_item_encode` | 把地址/长度/后备位置编码成一个 32 位配置项写入给定内存（178 个调用者，无一在 0x340000–0x3b0000）。 | 【指令核实】 | native-math-and-queue-validation.md；monitor-ae-locate-2026-10-27.md |
| 0x2fca3c | `power_key_latch` | 读 `0x22000314` 的 bit2 并锁存，调用点之一是关机路径。 | 【子核】+【推断】 | update-recovery-path-2026-10-27.md |
| 0x30fd20 | `helper_flag_args` | 共享助手：准备 `r0=1, r1=0`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x30fd48 | `flag_test_helper` | `ldrb r0,[r4]; cmp r0,#0` 的一次性标志读取。 | 未标 | sd-log-gates-review.md |
| 0x30fd54 | `flag_set_helper` | `mov r0,#1; strb r0,[r4]` 的一次性标志置位。 | 未标 | sd-log-gates-review.md |
| 0x314ff4 | `exposure_chunk_submit` | 每帧拆分量的提交点（`0x352c38` 调用）。 | 【主核】（归属存疑） | monitor-ae-locate-2026-10-27.md |
| 0x32240c | `helper_prepare_dispatch_call` | 把 r0 设为输入模式、r1 设为栈上配置结构，再调 `0x3d7fa0`。 | 【主核】 | display-entry-investigation.md |
| 0x32ed84 | `helper_zero_store` | 3 条共享指令：`mov r1,#0; strb r1,[r0]; mov pc,lr`。 | 【主核】 | exposure-decompile-review.md |
| 0x35096c | `helper_35096c` | 调 `0x395e7c`（后者 `ldr r0,[r1]; mov r1,#1`）。 | 【主核】 | rea-full-m1-stage.md |
| 0x350994 | `helper_350994` | `mov r1,sp; ldr r0,[r2]; mov pc,lr` 共享助手。 | 【主核】 | rea-full-m1-stage.md |
| 0x351720 | `diag_helper_351720` | 被 `0x36227c` 调用的助手（行为未详述）。 | 未标 | exposure-candidate-disassembly.md |
| 0x3544c8 | `payload_apply` | 用共享助手保存输入/输出指针，经 `0x36102c → 0x360f4c` 得 EV 值。 | 【Unicorn 验证】 | native-math-and-queue-validation.md |
| 0x354b24 | `thunk_35b678` | `0x81480` 唯一调用者，thunk 到 `0x35b678`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x354c04 | `ctrl40_write` | 把 `af` 写到 `ctrl+0x40`。 | 【指令核实】 | exposure-preview-patch-2026-10-27.md |
| 0x354c1c | `mode_to_ctrl_write_thunk` | 把 AE 内部模式写入 `ctrl+0x4c` 的搬运 thunk。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0x355628 | `prepare_flag_value` | 准备 `(flag=1, value)` 供 `0x361024` 写入访问器使用。 | 未标 | project-status.md（docs） |
| 0x355a00 | `loop_helper_cmp10` | 循环助手：`add r0,#1; cmp r0,#0xa`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x355b38 | `imaging_config_apply` | 从输入结构取值写向 `ctrl` 多个偏移，并依次调 `0x3d8a08`、`0x3d8d3c`、`0x3d7fa0`（中间经 `0x32240c`）。 | 【主核】 | display-entry-investigation.md；rea-full-m1-stage.md |
| 0x3564ac | `helper_3564ac` | 已核实的共享助手（inline 标注用）。 | 【主核】 | display-entry-investigation.md |
| 0x358544 | `video_capture_publish` | 录像采集把 `ctrl+0x13c/+0x144` 写回 `0xc146f4d4/0xc146f4d8`。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0x35894c | `set_monit` | 先快照 AE 状态，再依次调 `0x3d8d04/0x358f18/0x3d8d0c/0x3d8d3c/0x3d913c/0x3d7fa0`，**不写 ctrl 曝光字段**（显示/监视模式设置）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x358c7c | `monitor_param_apply` | 接收结构体指针的通用参数应用函数（读 `[r5]` 字节、比较两个 helper 返回值、写 `0xc1469694` 附近字段）；9 个调用点都先经 `0x358d5c` 拷贝；**冲突**：曾被当作 `SetMonit`。 | 【主核】 | exposure-candidate-disassembly.md；exposure-control-investigation.md |
| 0x358d34 | `zeroing_call_site` | 之后写 `0xc14dbe8f/0xc14dbe90/ctrl+0x104` 的值为零。 | 【主核】 | exposure-decompile-review.md |
| 0x358d5c | `byte_copy_helper` | 极小字节拷贝助手：`cmp r0,#0; cmpne r1,#0; ldrbne r0,[r0]; strbne r0,[r1]`。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x358f18 | `setmonit_callee` | `SetMonit` 序列中被调用的显示链函数之一。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x359318 | `hold_threshold_getter` | `0x3600b8` 用它取"曝光已到位"判定阈值。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x35944c | `stack_return_helper` | 从栈快照取 `[sp+0x58]` 返回（`0x3595f0` 的返回路径）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3594c8 | `m_limit_getter` | M 分支里用于 `+0x140 = min(+0x13c, …)` 的上限值。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3595f0 | `m_third_quantity` | 经 `0x370d70`、`0x36e8b8` 快照后 `ldr [ctrl+0xa4]` 原样返回 → `+0x14c = ctrl+0xa4`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x359e9c | `m_second_quantity` | `+0x144 = 0x359e9c(+0x74)`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x359fc4 | `helper_359fc4` | 被 `0x358c7c` 调用的助手之一。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x35a648 | `lens_aperture_convert` | 由当前镜头状态换算光圈，供 `0x363c14` 取景计算使用（`LensStatus=0` 时结果可能不同）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md；lens-status-observations-2026-10-27.md |
| 0x35a708 | `expo_ref_copy_a` | `AFT:ExpoRef` 序列中复制 Ref 的调用之一。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x35a84c | `expo_ref_copy_b` | 同上，第二个复制调用。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x35b35c | `time_request_entry` | 取景时间量入口（`0x365634` 调用），尾跳 `0x391fdc`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x35b678 | `ctrl_field_applier` | payload[0..7] 依次写入 `ctrl+0x70/+0xa4/+0x4c/+0x7c/+0x58/+0x5c/+0x48/+0x74`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x35d254 | `liveview_target_adjust` | 由 `0x362bbc` 用 `cfg+0x30` 调整取景目标；表 `0x860d08` 中 10 单位 = 1EV（−20/0/+20→0.25/1/4 倍）。 | 【指令核实】+【Unicorn 验证】 | exposure-preview-patch-2026-10-27.md |
| 0x35e208 | `ref_compose` | A 档（与 M 档共用）Ref 合成：`[+0x124]` 与 `+0x60` 合成。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x35e248 | `ratio_to_q10` | 把比值换成 Q10 定点后分档。 | 【子核】+【推断】 | monitor-ae-locate-2026-10-27.md |
| 0x35e2b4 | `ratio_helper` | M 分支 `+0x130 = 0x35e2b4(+0x128, …, +0x14c)`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x35e390 | `ratio_min_formula` | 计算 `min(a, f(b))·b/c` 形式的比值（再经 100、+0x144 改写）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x35f194 | `state_id_check` | 从 `0xc1400444` 读 `[+0x930]` 与 `0x2345/0x3456/0x4567` 比较后调 `0x39c154`（状态/ID 检查）。 | 未标 | exposure-candidate-disassembly.md |
| 0x35f3e0 | `ae_dbg_param_reader` | 门控 `[0xc159d68c+4]==0x2c308` 通过后清 0x44 字节、读取/解析最多 17 项数值写回参数区（更像调试参数输入，不是日志输出）。 | 【指令核实】 | sd-log-gates-review.md |
| 0x35f9d8 | `ae_param_consumer` | 同一门控值 `0x2c308` 的第二处：把 `+0x20` 起 8 个字段搬到 `ctrl+0x4c/0x50/0xce/0x60/0x74/0x70/0xa4/0x5c`。 | 【指令核实】 | sd-log-gates-review.md |
| 0x35fc00 | `ae_dbg_value_bucket` | `0x35f3e0` 的唯一 BL 调用点，把入参按 `0x2bf20/0x2c308/0x2c6f0/0x2cad8/0x2cfc0` 分档。 | 【指令核实】 | sd-log-gates-review.md |
| 0x35fc90 | `m_mode_gate` | M 分支门控：返回 0 走 `0x36be00`，否则走 `0x369d34`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x35fcb8 | `ae_debug_csv_writer` | AE 调试 CSV 写入器，每 500 ms 轮换两个日志（开关与输出位置未确认）。 | 未标 | monitor-ae-locate-2026-10-27.md |
| 0x36005c | `const_return_helper` | 返回 `r0=0x2c, r2=0`（`r1` 保留文件名），不是文件操作。 | 【主核】 | sd-log-gates-review.md |
| 0x3600b8 | `exposure_hold_check` | `ctrl+3==1`、`+0x14c==+0x164`、`+0x144==+0x160` 且 `+0x130` 偏低时调 `0x366288(ctrl+0x384)`；形似"曝光到位后保持"，不写传感器。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x360150 | `tail_helper_360150` | `0x3d613c` 使用的真实尾助手。 | 【Unicorn 验证】 | native-curve-mode-validation.md |
| 0x360f4c | `ev_delta_math` | 区间外差值 → `/1024` → 量化到 1/3 → 以最接近的 1/10 输出（显示 EV 的原生数值路径）。 | 【Unicorn 验证】 | native-math-and-queue-validation.md |
| 0x361024 | `s16_input_write_accessor` | 有符号 16 位输入 `0xc159d74c` 的可选写入访问器。 | 未标 | project-status.md（docs） |
| 0x36102c | `ev_delta_producer` | 读 `0xc159d74c`（s16）与表 `0xc1470010`，写输出 `+0x14`、`+0x18`，状态取自 `0xc1469694` 若干字段。 | 【Unicorn 验证】 | native-math-and-queue-validation.md |
| 0x361ad4 | `liveview_cfg_fill` | 构建取景算法配置（含拍摄 AE 模式、用户时间/光圈/ISO 映射量与补偿），输出到栈上 cfg。 | 【指令核实】 | exposure-apply-path-2026-10-27.md；exposure-preview-patch-2026-10-27.md |
| 0x362010 | `monit_ae_step` | 取景 AE 步进：`0x36eee8` 快照 → `0x361ad4` 配置 → 回调表 `0x86253c` 取 id==1 → `0x365344` 执行 → 发布 `0xc146f4d4/4d8/4f8/4fc/500` 与 `ctrl+0x118`(Ref)。 | 【指令核实】 | monitor-ae-locate-2026-10-27.md；exposure-preview-patch-2026-10-27.md |
| 0x362084 | `patch_site_cfg_fill_call` | 原 `bl 0x361ad4` 的调用点（曝光预览候选补丁把目标改到 `0x369d68` 包装器）。 | 【指令核实】+【Unicorn 验证】 | exposure-preview-patch-2026-10-27.md |
| 0x36227c | `diag_event_handler` | 拷 0x48 字节 rodata 到栈，调 `0x3656e8`、`0x351720`，从 `0x1549c0` 返回；形似诊断事件处理，**不是主 AE 循环**（`AFT:monit_ae` 字符串在此处是相邻字面量造成的假引用）。 | 未标 | exposure-candidate-disassembly.md |
| 0x362bbc | `cfg_compensation_path` | 经 `0x35d254` 用 `cfg+0x30`（来源 AE 快照 `+0x30`/`ctrl+0x60`）调整取景目标。 | 【指令核实】+【Unicorn 验证】 | exposure-preview-patch-2026-10-27.md |
| 0x363518 | `ae_math_container` | 含 `0x3635c4` 的现有函数（Ghidra `--existing-only` 验证的归属）。 | 未标 | native-y-curve-validation.md |
| 0x3635c4 | `s16_write_call_site` | 先调 `0x369790`（并存 `0xc09e06c0`），经 `0x355628` 准备 `(1,value)` 后调 `0x361024`。 | 未标 | project-status.md（docs） |
| 0x363a88 | `ratio_helper_363a88` | 取景三量分配链中的比值助手。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x363b84 | `limit_helper_363b84` | 同上，限制/钳位助手。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x363c14 | `liveview_calc_normal` | 普通取景计算：用 state `+8`、`0x35a648()` 镜头光圈换算、配置表 `context+0x48` 生成取景三量并按表限制积分时间（**不是复制 M 档拍照三量**）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md；exposure-preview-patch-2026-10-27.md |
| 0x364434 | `liveview_calc_alt` | 取景数值路径的另一个入口（与 `0x363c14` 并列）。 | 【指令核实】 | exposure-preview-patch-2026-10-27.md |
| 0x364504 | `state_triplet_copy` | 把 state `+0x2c` 的 12 字节复制到结果 `+0`，`+0x38` 的 12 字节复制到结果 `+0xc`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x3648d0 | `ae_callback_id0_2` | 回调表 id 0 与 2 共用的处理函数。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3652bc | `state_triplet_write` | 把一条输入记录的三个字写到 state `+0x38/+0x3c/+0x40`（连续取景实际读取的曝光三元组）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x365344 | `ae_core_algorithm` | AE 核心算法（回调表 id==1），以 APEX（Bv/Tv/Av/Sv）计算 ref/时间/光圈/感光度。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3654d8 | `ae_callback_id6` | 回调表 id 6。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3655dc | `ae_callback_gain` | 回调表 id 3：`state+0xe5` 有效时取 `state+0x3c` 调 `0x3b9158`（模拟+数字增益施加）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x365634 | `ae_callback_time` | 回调表 id 4：`+0xe3/+0xe4` 条件下取 `state+0x38` 调 `0x35b35c`（积分时间施加）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x3656a8 | `ae_callback_id5` | 回调表 id 5。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3656e8 | `ae_callback_id8` | 回调表 id 8（也被 `0x36227c` 调用）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3657cc | `ae_callback_id7` | 回调表 id 7。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3658b0 | `ae_history_maintain` | 维护 `+0x44 + 12*i` 的历史曝光组。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0x365920 | `ae_callback_id9` | 回调表 id 9。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x365c54 | `callback_invoke` | 从表取 `ip = fn`，准备栈参 `{r5=0xc14708d0, r6=0xc14707e0}`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x366288 | `post_settle_action` | 曝光到位判定后调用，参数 `ctrl+0x384`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x369790 | `fixed_point_convert` | 定点/浮点转换与加减，并把同一值保存到 `0xc09e06c0`。 | 未标 | project-status.md（docs） |
| 0x369d34 | `m_alt_branch` | M 档门控为假时的替代分支。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x369d50 | `dead_gate_check` | 调恒返回 0 的 `0xf880` 后 `cmp #1; bne 0x369e18`，使 `0x369d68–0x369e14` 顺序不可达。 | 【指令核实】 | exposure-preview-patch-2026-10-27.md |
| 0x369d68 | `dead_zone_block` | 176 字节候选死区（原写 `0xc146f5ac`），曝光预览补丁包装器占用其前 88 字节。 | 【子核】/【指令核实】 | monitor-ae-locate-2026-10-27.md；exposure-preview-patch-2026-10-27.md |
| 0x36b978 | `a_mode_target` | A 档目标计算入口。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36b984 | `a_mode_ref` | A 档 `ldr [+0x124]` → `0x35e208` 合成 → `str [+0x128]`（Ref）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36be00 | `m_mode_target` | M 档专用目标计算：算 `+0x128`、`+0x144`、`+0x14c`、`+0x130`，最后 `+0x13c = +0x70`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36be6c | `m_target_store` | `streq r0,[r4,#0x13c]`，M 分支调用者传 1 所以总会执行，随后被 `0x36be90` 覆盖。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36be90 | `m_work_exposure_write` | `ldr r0,[r4,#0x70]; str r0,[r4,#0x13c]`，把 `ctrl+0x70` 直接写成工作曝光量。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36c34c | `s_mode_target` | S 档目标计算入口。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36c4b8 | `ae_mode_dispatch` | 按 `ctrl+0x4c` 的 AE 模式分派到 A/S/M 目标链。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36e0c8 | `helper_36e0c8` | 被 `0x358c7c` 调用的助手之一。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x36e2d8 | `expo_ref_sequence` | `AFT:ExpoRef`：状态条件下调 `0x35a708/0x35a84c` 复制 Ref，再进 SetFocus/SetAE 序列。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x36e7d0 | `helper_36e7d0` | 被 `0x358c7c` 调用的助手之一。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x36e8b8 | `ctrl_snapshot_to_stack` | 把控制块快照到栈（如 `0x36e988 ldr [ctrl+0xa4]`）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x36eee8 | `ctrl_snapshot` | 把控制块字段快照到 `sp+8`（`0x362010` 第一步）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3703c4 | `read_ctrl_30e` | 读取 u8 `0xc1469694+0x30e`。 | 【主核】 | exposure-decompile-review.md |
| 0x370d70 | `prologue_helper` | `sub sp,#0x2a8` 型共享序言助手。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x371634 | `helper_371634` | 被 `0x358c7c` 调用的助手之一。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x375668 | `helper_375668` | 被 `0x358c7c` 调用的助手之一。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x388550 | `m_settled_writer` | `ldr r4,=0xc1469694; mov r5,r0`，M 分支调用者传 1。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x38dcd8 | `acqloop_flag_printer` | `ACQLOOP AE`/`DEFOCUS AE` 打印的是 `0xc1400444+0x1b9..0x1bc` 的 0/1 标志。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0x391fdc | `time_request_handler` | 保存请求积分时间到 `0xc14abf44`，处理超过帧周期的情况。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x392014 | `call_3b9254` | 调用 `0x3b9254`（→`0x3b8ef8`）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x392030 | `call_3b90c0` | 调用 `0x3b90c0`（→`0x3ba548`）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x394264 | `exposfixed_status_write` | `ExposFixed` 路径写 `0xc159eb30` 后打印 `0xc159eb40/38/3c`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x39427c | `exposfixed_value_write` | 写 `0xc159eb38+8`，为零时清 `+0/+4`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x395ba8 | `indirect_dispatch_unrecovered` | 间接分派尚未恢复的代码块。 | 未标 | exposure-decompile-review.md |
| 0x395c44 | `tail_read_c1595420_cmp` | 尾跳到 `0x2423f0` 读 u32 `0xc1595420`，与 `ctrl+0x30e` 低字节比较决定重配置路径。 | 【主核】 | exposure-decompile-review.md |
| 0x395da8 | `helper_sub_sp14` | 真实作用含 `sub sp,sp,#0x14`（当普通调用会误读栈布局）。 | 【主核】 | exposure-decompile-review.md |
| 0x396390 | `monit_rec_mode_print` | `MONIT_REC_MODE=` 位于 `RAW_MODE=/RAW_SIM=/FLASH_TEST=` 调试设置回读块。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0x399b58 | `exposfixed_wrapper` | `ExposFixed:` 工厂/调试包装器，写一组独立状态。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x399ef0 | `output_helper` | 打印/输出公共出口（`0x39b4e4: b 0x399ef0`）。 | 未标 | exposure-candidate-disassembly.md |
| 0x39af84 | `defect_stats_print` | `MONITOR MODE:`/`MONITOR MODE(ACQUIRED):` 是坏点统计按帧率模式分类的打印（邻近串 `DEFECT DEFINITION:`、`-MONIT1 30FPS`）。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0x39b48c | `monitor_mode_format` | 取 `r0` 为模式值，按 `3/4/5/6/0x19/8/0x1b/0xb/0xc` 选标签的格式化函数（不是状态设置器）。 | 未标 | exposure-candidate-disassembly.md |
| 0x39b51c | `monitor_mode_format2` | 另一个按 `3/4` 选标签后跳 `0x39b700` 的格式化函数。 | 未标 | exposure-candidate-disassembly.md |
| 0x39b700 | `print_path` | 上述格式化函数共用的输出路径。 | 未标 | exposure-candidate-disassembly.md |
| 0x39c154 | `state_check_callee` | `0x35f194` 调用的后续函数。 | 未标 | exposure-candidate-disassembly.md |
| 0x3b8ef8 | `time_to_line_counts` | 读帧长/时钟参数，把整数时间换算为行相关计数。 | 【指令核实】+【Unicorn 验证】 | exposure-apply-path-2026-10-27.md |
| 0x3b90c0 | `wrapper_to_3ba548` | 包装到 `0x3ba548`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x3b9158 | `gain_convert` | 经 `0x3bca88` 把输入换算成打包值并保存到 `0xc14ac6f0`（高 15 位为 0 时用 100）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x3b9254 | `wrapper_to_3b8ef8` | 包装到 `0x3b8ef8`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x3ba548 | `shs_command_pack` | 两计数各钳到 0xfff，打包 `0x0702/0x0802/0x0302/0x0402` 等寄存器命令。 | 【指令核实】+【Unicorn 验证】 | exposure-apply-path-2026-10-27.md |
| 0x3bc684 | `sensor_gain_pack` | 打包值低 16 位钳到 0xf00，打包 `0x7502/0x7602/0x7702/0x7802` 命令（传感器模拟增益）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x3bca88 | `gain_pack_split` | 把增益输入拆成传感器部分与 ISP 数字部分。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0x3d6074 | `helper_3d6074` | 已核实的共享助手（20 字节）。 | 【主核】 | display-entry-investigation.md |
| 0x3d609c | `path_to_sl_map` | path→sl：0→2、1→1、3→3、0x15..0x17 经 rodata 表得 6/7/8，其他为 0。 | 【主核】 | rea-full-m1-stage.md |
| 0x3d613c | `ycurve_mode_select` | Y 曲线模式选择器：path=1 读 `ctx+0x120` 字节、path=3 读 `ctx+0x130` 字，映射为 mode 1..9。 | 【Unicorn 验证】 | native-curve-mode-validation.md；rea-full-m1-stage.md |
| 0x3d622c | `ycurve_cb0` | `0xc09e388c` 回调表索引 0。 | 【主核】 | display-entry-investigation.md |
| 0x3d65f8 | `ycurve_cb1` | 回调表索引 1。 | 【主核】 | display-entry-investigation.md |
| 0x3d6750 | `ycurve_cb2` | 回调表索引 2。 | 【主核】 | display-entry-investigation.md |
| 0x3d6b28 | `ycurve_cb3` | 回调表索引 3。 | 【主核】 | display-entry-investigation.md |
| 0x3d6f60 | `ycurve_cb5_handler` | 回调表索引 5：以 `[0x877e30 + normalizedPath*4 + 0x6e4]==1` 门控，选 provider/enable/曲线；下层经 `0x420220` 写 `0x30210fd8+实例偏移`。 | 【主核】 | display-entry-investigation.md；rea-full-m1-stage.md |
| 0x3d7448 | `ycurve_apply_callsite` | `[0x8786e8+0x54]==1` 时调 `0x4192fc` 的调用点。 | 【主核】 | rea-full-m1-stage.md |
| 0x3d7560 | `ycurve_cb4` | 回调表索引 4。 | 【主核】 | display-entry-investigation.md |
| 0x3d7a5c | `ycurve_cb6` | 回调表索引 6。 | 【主核】 | display-entry-investigation.md |
| 0x3d7fa0 | `ycurve_dispatch` | 用初始化 `.data` 表 `0xc09e388c` 的 7 项回调分派；path=1 从索引 1 起、其他从 0 起，经 `0x3bfe18` 递增比较 7。 | 【主核】 | display-entry-investigation.md；rea-full-m1-stage.md |
| 0x3d8a08 | `ycurve_ctx_build` | 构造 context：`+0x120`←全局字节 `0xc14699a1`、`+0x130`←全局字 `0xc14699b0`、`+0x148` 初始 0。 | 【主核】 | rea-full-m1-stage.md |
| 0x3d8d04 | `setmonit_callee_b` | `SetMonit` 调用的显示链函数。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3d8d0c | `setmonit_callee_c` | 同上。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3d8d10 | `path_to_bank` | path `{1,2,6,7,0xf,0x17}` 返回 1，其他返回 0。 | 【主核】 | rea-full-m1-stage.md |
| 0x3d8d3c | `ctx_bank_write` | 调 `0x3d8d10(path)` 把 bank 写入 `ctx+0x148`（Y 写入侧取低字节）。 | 【主核】 | rea-full-m1-stage.md |
| 0x3d8d9c | `helper_3d8d9c` | 被 `0x358c7c` 调用的助手之一。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x3d8de8 | `display_curve_select` | 读 `0xc146f4d8`、用 `ctrl+0x170` 写回，再以 path 0x15 调 `0x3d8d10`（bank）与 `0x3d7fa0`（曲线分派）——方向是"记录后选曲线"。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3d913c | `setmonit_callee_d` | `SetMonit` 调用的显示链函数。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x3d9294 | `addr_to_backup_map` | 把寄存器地址映射到配置后备位置。 | 【指令核实】 | native-math-and-queue-validation.md |
| 0x3e0748 | `enable_store_helper` | 共享助手：为前几个 provider 存 `enable=0`。 | 【主核】 | rea-full-m1-stage.md |
| 0x4192fc | `ycurve_apply_wrapper` | 清空描述符后调 `0x41e7d4` 格式化 + `0x41ef2c` 写入。 | 【Unicorn 验证】 | native-y-curve-validation.md |
| 0x41e7d4 | `ycurve_format` | 读 17 个 u16 点与使能参数，生成点及系数字段。 | 【Unicorn 验证】 | native-y-curve-validation.md |
| 0x41ef2c | `ycurve_write` | 把描述符前 34 字段按两组 17 字段打包，写出 18 个 u32（72 字节）到 `0x30210e4c + bank*0x30000`。 | 【Unicorn 验证】 | native-y-curve-validation.md |
| 0x41fa5c | `reg_write_group_a` | 写 `0x30210020+f34/f38/f3c/f40` 等；**曾被误当作 Gamma 写入口**。 | 【主核】 | project-status.md（docs） |
| 0x41fae4 | `reg_write_30210e9c` | 实际使用 `0x30210e9c` 的相邻函数（不能与 Y-Gamma 混称）。 | 【主核】 | project-status.md（docs） |
| 0x41fbd4 | `reg_write_group_b` | 同样向 `0x30210xxx` 类地址写入的指令块。 | 未标 | display-entry-investigation.md |
| 0x420220 | `imaging_param_pack` | 读输入结构、打包后写向 `0x30210fd8 + 实例偏移` 及后续两字（已进入寄存器配置层）。 | 未标 | display-entry-investigation.md |
| 0x429704 | `isp_digital_gain_write` | 把 `(value*1024+50)/100` 钳到 65535 后写 `0x300f0310/0x300f0314`（四路同值）——**有真实 MMIO 写入的 ISP 数字增益路径**。 | 【指令核实】+【Unicorn 验证】 | exposure-apply-path-2026-10-27.md |

### 1.1 非函数锚点（.rodata / .data 表与字符串，供交叉引用；不属于函数表）

| 地址 | 名称/内容 | 含义 | 证据等级 | 来源报告 |
| --- | --- | --- | --- | --- |
| 0x430bb0–0x430bdc | `sha1_assert_descriptor` | 函数体中间的内联断言描述符表（文件名/格式串/魔数 `0x66666667`）。 | 未标（等级 P：有指针表、可达性未证） | freeze-static-audit.md |
| 0x440322 / 0x44032e | `esteg_dbg_names` | `ESTEG   DBG`/`ESTEG.DBG` 8.3 名对，ESTEG1–4 各有两份。 | 未标 | sd-log-gates-review.md |
| 0x4b88fe | `trap_format` | `TRAP %x(%x): pc %x, lr %x, sp %x, cpsr %x, spsr %x`，三段中无 4 字节指针命中。 | 未标（等级 S） | freeze-static-audit.md |
| 0x4b869b / 0x4b879d / 0x4b8a1a | `wifi_diag_strings` | `reclaim section …heap`、`Malloc failure count`、`AXI timeout`，属 Broadcom Wi-Fi 驱动块（`7.10.48.2 (r629111)`）。 | 未标（等级 S） | freeze-static-audit.md |
| 0x5285b3 | `exposure_mode_byte_table` | `[0x0b,0,1,2,3,4,5,6,7]`，把 `+0xa9` 换成 JSON 索引。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x52a52c | `state_select_table` | `0x40c84` 选状态时可能取的表项。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x52a996 | `halfword_offset_table` | 14 项，供 `0x18e740` 二分查找。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0x531eb8 | `mode_key_descriptor` | 键 `02 03 04 05 06 07 1c f7 fa` 的二分查找描述符。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x54c1ec | `segment_name_table` | 10 项 `{名字,段号}`：PTBL→10、NPROG/NPG→0、NDATA/ND1→1、NLIPI/NPI→2、NDAT2/ND2→3、IPL→5。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x54c23c | `ptbl_name_table` | `PTBL NPROG/NPG NDATA/ND1 NLIPI/NPI NDAT2/ND2 IPL` 名字表。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x61ce80 | `version_string_copy3` | 第三份 `3.2-cn\0`；未发现显式指针（只纳入 canary 同长补丁）。 | 【静态搜索】 | repack-pipeline-2026-10-27.md |
| 0x6b7f54 | `version_string_copy2` | 第二份 `3.2-cn\0`，由 `0x1509dc` 取用（屏幕显示）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x6b80fc | `exposure_mode_strings` | `{Auto,P,A,S,M}` 字符串表。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x6b8668 / 0x6b8412 | `rc_video_format_strings` | `RCVideoFormatSet`、`Resolution`。 | 未标 | feature-feasibility-2026-10-26.md |
| 0x6b86a8 | `remote_cmd_table` | 45 条 × 8 字节（360 字节）远程命令表；3.1-cn 在 `0x6b86ac`。 | 【指令核实】 | command-bounds-investigation.md |
| 0x6b881c / 0x6b88ac–0x6b88c4 / 0x6b8cfa | `video_mode_strings` | `MF-PEAK`、`720P_60/30/24`、`VGA_240`、`FHD_24`。 | 未标 | feature-feasibility-2026-10-26.md |
| 0x833040 | `action_table` | 23 项函数表，`0x1623f4` 用动作号减 0x13 索引。 | 【指令核实】 | software-only-investigation.md |
| 0x834674 | `version_string_copy1` | 第一份 `3.2-cn\0`，唯一精确指针字在 `0x179118`，由 `0x17904c` 取用。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x83f578 | `lcd_name_string` | `INLX_30_103_LCD`，被 `.data 0xc09d0638` 指向。 | 未标 | display-entry-investigation.md |
| 0x853c9c | `bank_offset_table` | 前两项为 0 与 0x30000（Y 曲线 bank 步长）。 | 【主核】 | rea-full-m1-stage.md；native-y-curve-validation.md |
| 0x860d08 | `liveview_comp_table` | 取景补偿表：10 单位 = 1EV，−20/0/+20 → 0.25/1/4 倍。 | 【指令核实】 | exposure-preview-patch-2026-10-27.md |
| 0x861625 | `ae_dbg_filename` | `AE_DBG  TXT`（8.3，12 字节含 NUL），取用指令在 `0x35f3f0`（池字在 `0x35f488`）。 | 【指令核实】 | sd-log-gates-review.md |
| 0x86253c | `ae_callback_table` | `{id, fn}` ×10：id8→0x3656e8、7→0x3657cc、6→0x3654d8、1→0x365344、5→0x3656a8、3→0x3655dc、4→0x365634、0/2→0x3648d0、9→0x365920。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0x86258c | `numeric_table` | 被 `0x362288` 的 `ldr r1,[pc,#0x2e8]` 装载（曾被误认成 `AFT:monit_ae` 字符串）。 | 【主核】 | exposure-candidate-disassembly.md |
| 0x8742d2 | `curve_index_table` | `00 00 06 07 08 09 08 07 00 00 00 00`（已解码 rodata，不是运行期 RAM）。 | 【主核】 | native-curve-mode-validation.md |
| 0x877e30 (+0x6e4) / 0x8786e8 (+0x54) | `ycurve_gate_tables` | `0x3d6f60` 的 provider 门控表与 `0x4192fc` 的使能门控。 | 【主核】 | rea-full-m1-stage.md |
| 0xc09b4b20 | `sdk_filename_table` | 10 项 `.SDK` 文件名：`NOSLEEP/SLEEP1/IMAGER/BATLIFE/NONAIL/NODIST/AUDIOADJ/WIFIDUMP/SHORTPIC/SHORTMOV`。 | 未标 | diagnostic-interface-investigation.md |
| 0xc09d0638 / 0xc09d06e0 | `lcd_descriptors` | `INLX_30_103_LCD` 描述结构；偏移 0x48 为函数指针 `0x2235b8`。 | 未标 | display-entry-investigation.md |
| 0xc09e06c0 | `saved_value_cell` | `0x369790` 把同一值保存到此（与 `0xc159d74c` 同源）。 | 未标 | project-status.md（docs） |
| 0xc09e360c | `ycurve_provider_table` | 10 项 provider 指针：`3dd624, 3dd624, 3df1ac, 3e09b4, 3e1a0c, 3e30ac, 3e2588, 3e3bd0, 3e3e24, 3e419c`。 | 【主核】 | rea-full-m1-stage.md |
| 0xc09e388c | `ycurve_callback_table` | 7 项：`3d622c,3d65f8,3d6750,3d6b28,3d7560,3d6f60,3d7a5c`。 | 【主核】 | display-entry-investigation.md |

---

## 2. 全局 RAM 结构表

地址空间：RAM `0xc0000000–0xd0000000`。下表的 `+0xNN` 均为相对该基址结构内偏移。

| 地址（含字段） | 含义 | 证据 | 来源报告 |
| --- | --- | --- | --- |
| 0xc1401074 | **相机设置结构基址**（`src`，由 outlined 助手 `0xb7aac` 给出，按 `+0xb7` 用法推断）。 | 【主核】+【推断】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xa9 | 拍摄档位：1 Auto、2 P、3 A、4 S、5 M。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xb7 | AE 内部模式（P→2、A→3、S→4、**M→1**）；`0x87f1c` 写入 `ctrl+0x4c`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xb9 | 曝光/ISO 回调的状态字节（`0x44338` 读、`0x40d10` 写，并向另两个 RAM 字节镜像）；**业务含义未定**。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0xc1401074+0x2c | 经 `0x3544c8` 搬到 `ctrl+0x70`（M 档工作曝光量来源）；5 个写者 `0x2a6f0/0x33528/0xb1924/0xf37a8/0xf3fd8`，语义未定。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xc | payload[0] 来源；被 `0x124a94/0x124a9c` 钳到 ≥250（像快门微秒，单位未证）；仅 M/S 档被转发。 | 【主核】+【推断】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0x14 | payload[1] 来源，最终进 `ctrl+0xa4`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0x1c | payload[5] 来源，进 `ctrl+0x58`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xa0 | payload[4] 来源（字节），进 `ctrl+0x5c`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xb0 | payload[7] 来源，进 `ctrl+0x74`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xbf | payload[6] 来源（字节），进 `ctrl+0x48`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1401074+0xaf | M 档重配分支中置 0（`0xad85c`，M 键 5 → `+0xb7=1,+0xaf=0`）。 | 【Unicorn 验证】 | exposure-preview-patch-2026-10-27.md |
| 0xc1400444+0x930 | `0x35f194` 读取的 ID/状态字，与 `0x2345/0x3456/0x4567` 比较（`LastMonit` 邻近，未证为预览状态）。 | 未标 | exposure-candidate-disassembly.md |
| 0xc1400444+0x1b9..0x1bc | `ACQLOOP AE`/`DEFOCUS AE` 打印的 0/1 标志。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0xc140116c+0x16 | payload[3] 来源字节。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc140119d | 枚举值（被 `0x889f8` 读取并转换），产品含义未证。 | 【主核】 | rea-full-m1-stage.md |
| 0xc140e5e0 | 外层锁/信号量对象：`0x1fa4c` 初始化并经 `0x198b9c` 存句柄（24 字节参数块）。 | 【主核】 | rea-full-m1-stage.md |
| 0xc1469694 | **AE 控制块 `ctrl`**（拍照目标侧），见下列偏移。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x4c | AE 内部模式（由 `+0xb7` 经 `0x354c1c` 写入），`0x36c4b8` 据此分派。 | 【子核】/【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x40 | `af` 值（`0x354c04` 写入），`0x362010` 由此转成 kind；非零 kind 业务含义未证。 | 【Unicorn 验证】 | exposure-preview-patch-2026-10-27.md |
| 0xc1469694+0x48 / +0x58 / +0x5c / +0x7c | payload[6]/[5]/[4]/[2] 落点。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x60 | 取景补偿来源（AE 快照 `+0x30`），进 `cfg+0x30`。 | 【指令核实】 | exposure-preview-patch-2026-10-27.md |
| 0xc1469694+0x70 | M 档工作曝光量来源（来自设置 `+0xc`），`0x36be90` 写入 `+0x13c`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x74 / +0xa4 | M 档另两个工作量的来源（`+0x144`/`+0x14c`）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x80 | 作为参数传出到 `0x358c7c` 路径；含义未定。 | 【主核】 | exposure-decompile-review.md |
| 0xc1469694+0x104 | `0x358d34` 之后被置零。 | 【主核】 | exposure-decompile-review.md |
| 0xc1469694+0x118 | 发布的 Ref（`0x362100` 写入）；除 CSV 日志外**无读者**。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x124 | A 档 Ref 输入（`0x36c4b8` 由 `+0x1ac` 拷入）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x128 | A/M 档 Ref 结果。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x130 | M 档 `0x35e2b4` 比值的改写目标。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x13c | **工作曝光量（时间相关）**；M 档最终被 `ctrl+0x70` 覆盖。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x140 | 与 `+0x13c` 一起被 `0x352c38` 当 64 位量读取（该归属存疑）。 | 【主核】（归属存疑） | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x144 | 工作曝光量（增益相关），M 档 = `0x359e9c(+0x74)`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x14c | 工作曝光量（第三量），M 档 = `ctrl+0xa4`。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x160 / +0x164 | `0x3600b8` "曝光到位"比较用字段。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x170 | 由 `0x3d8de8` 用 `0xc146f4d8` 写入（显示侧记录）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x1ac | 拷入 `+0x124` 的源字段。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+0x30e | u8，被 `0x3703c4` 读、与 `0xc1595420` 低字节比较；含义未定。 | 【主核】 | exposure-decompile-review.md |
| 0xc1469694+0x384 | `0x366288` 的实参（曝光到位后的动作）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1469694+3 | 与 `0x3600b8` 判定相关（`ctrl+3==1`）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc14707e0 | **连续取景 AE 状态 `state`**，见下列偏移。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14707e0+8 | 普通取景计算的状态输入之一（`0x363c14`）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14707e0+0x2c | 12 字节，被 `0x364504` 复制到结果 `+0`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14707e0+0x38 | 取景三量之一（时间相关），`0x365634` 读取后进 `0x35b35c`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14707e0+0x3c | 取景三量之二（增益相关），`0x3655dc` 读取后进 `0x3b9158`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14707e0+0x40 | 取景三量之三（光圈相关）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14707e0+0x44 + 12*i | 历史曝光组（`0x3658b0` 维护）。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0xc14707e0+0xe3 / +0xe4 | 时间施加回调（id=4）的状态门控。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14707e0+0xe5 | 增益施加回调（id=3）的状态门控。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14708d0 | 传给 AE 回调的栈参之一（`0x365c54` 准备）。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc14699a1 | 全局字节，进 Y 曲线 context `+0x120`；写引用在 0x358270/0x392d78/0x3cf404。 | 【主核】 | rea-full-m1-stage.md |
| 0xc14699b0 | 全局字，进 Y 曲线 context `+0x130`；写引用在 0x355b80/0x358214/0x358870。 | 【主核】 | rea-full-m1-stage.md |
| 0xc146f35c | 作为消息 ID 使用的字段（`0x352c38` 取值）。 | 【主核】（归属存疑） | monitor-ae-locate-2026-10-27.md |
| 0xc146f4d4 / 0xc146f4d8 | 发布的**取景曝光三量**（由 `0x362010` 从结果 `+0xc/+0x10` 发布；录像采集 `0x358544` 也写）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc146f4f8 / 0xc146f4fc / 0xc146f500 | `0x362010` 发布的其他结果字段；`0xc146f500` 实际取结果 `+0x20`（历史组第三项），**不是**当前组三量的 `+0x14`。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc146f5ac | 死区代码（`0x369d68–0x369e14`）写入的字段，该区在本版本不执行。 | 【子核】 | monitor-ae-locate-2026-10-27.md |
| 0xc1470010 | EV 差值计算的界限表。 | 【Unicorn 验证】 | native-math-and-queue-validation.md |
| 0xc14abf44 | 保存请求积分时间（`0x391fdc`）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14ac6f0 | 打包后的增益值（`0x3b9158` 存），后续拆传感器/ISP 两路。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc14ca473 | 待升级标志：`0x1247b4` 子命令 2 置 1，`0x10be58`/`0x10be80` 读取；清除时机未找到。 | 【子核】 | update-recovery-path-2026-10-27.md |
| 0xc14dbe8f / 0xc14dbe90 | `0x358d34` 之后被置零的字节。 | 【主核】 | exposure-decompile-review.md |
| 0xc14e1258 | 消息队列对象句柄（`0x26b4c`/`0x26e38` 初始化）。 | 【主核】 | native-math-and-queue-validation.md |
| 0xc150b5a4 | `0x40c84` 选 ISO/曝光状态时的输入值。 | 【主核】 | iso-callback-review-2026-10-26.md |
| 0xc150f9f4 | **M 档 EV 显示缓存**（十分之一 EV），`0x85d30` 访问器；4 处写调用 `0x86bb0/0x9174c/0x91b68/0x9b490`，`0x9173c` 从输入结构 `+0x50` 取有符号字节。 | 未标（称机器指令证据） | ev-metadata-source-review.md |
| 0xc1595420 | u32，被 `0x395c44`/`0x2423f0` 读取，与 `ctrl+0x30e` 比较（含义未定）。 | 未标 | exposure-decompile-review.md |
| 0xc159d68c | AE 调试参数结构：`+4` 为命令码（`0x2c308` 才通过门控），`+0x20` 起 17×4 字节参数区。 | 【指令核实】 | sd-log-gates-review.md |
| 0xc159d74c | s16，`0x36102c` 的输入标量（"输入减界限"公式的来源）。 | 【Unicorn 验证】 | native-math-and-queue-validation.md |
| 0xc159d7a0 | `0x362018` 装载的指针（AE 步进快照用），用途未详述。 | 【主核】 | monitor-ae-locate-2026-10-27.md |
| 0xc159eb30 / 0xc159eb38 | `ExposFixed` 调试包装器状态组（`0x394264`/`0x39427c` 写）。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc159eb3c / 0xc159eb40 | 同组被打印的字段。 | 【指令核实】 | exposure-apply-path-2026-10-27.md |
| 0xc1c00000–0xc1dfffff | `.log_save`：2 MiB RAM 区域（装载/节表记录，flags `0xc`），名字像日志区但未找到读取入口。 | 未标（B 级表项证据） | diagnostic-interface-investigation.md |
| 0x45545000 | 升级控制块（`r4`，字段 `[+0]`=LENGTH、`[+8]`=对齐长度）；**地址层归属不明**，不像 `.data`/RAM 表内地址。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x4554500c | 第二条升级通路重置的 RAM 缓冲指针。 | 【子核】 | update-recovery-path-2026-10-27.md |

---

## 3. MMIO 寄存器表

地址空间：MMIO `0x20000000–0x3fffffff`。凡由 IPL 访问的寄存器在"含义"里标 `[IPL]`，由主程序访问的标 `[主程序]`；两者都是物理地址，不做 `+0x22ffc000` 换算。

| 地址 | 含义 | 证据 | 来源报告 |
| --- | --- | --- | --- |
| 0x21c00014 | `[主程序]` 传感器传输接口的 16 位命令寄存器（`0x24467c` 写，打包命令如 `0x0702/0x0802/0x7502`）。 | 【指令核实】+【Unicorn 验证】 | exposure-apply-path-2026-10-27.md |
| 0x21c00018 | `[主程序]` 同接口的数据字节寄存器（`0x244680` 写）。 | 【指令核实】+【Unicorn 验证】 | exposure-apply-path-2026-10-27.md |
| 0x21801000 系列 | `[IPL]` Thumb 硬件初始化访问的寄存器组（`0x526`、`0x8d78`）。 | 未标（反汇编证据） | boot-decoder-capstone.md |
| 0x22000000 | `[IPL]` `|= 0x300` 的配置寄存器（`0x75c0`）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x22000300 | `[IPL]` 轮询区域，最多 0x80000 次，超时打印 `PSQ PWR Factor Wait Skip`。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x22000308 | `[IPL]` `==0` 是 BOOT 选择的第一个条件（`0x7588`）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x2200030c | `[IPL]` 开机原因寄存器：`([..] & ~0x80000) == 0x100000` 时配合进入 BOOT；`0x100000` 的具体枚举无证据。 | 【主核】+【推断】 | update-recovery-path-2026-10-27.md |
| 0x22000310 | `[IPL]` `&1 == 0` 是 `0x75c0` 的条件之一。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x22000314 | `[IPL]` `&0x1e == 0xa` 决定是否启动 BOOT；`[主程序]` `0x2fca3c` 读 bit2 并锁存（推断与电源键有关）。 | 【主核】/【子核+推断】 | update-recovery-path-2026-10-27.md |
| 0x23000000 | `[IPL]` IPL 数据/代码运行期映射基址（VA = 文件偏移 + 0x22ffc000，起点即 0x23000000）；`.ver_table` 65 字节从此拷出。 | 【指令核实】+【Unicorn 验证】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x30041000 | `[IPL]` BSS 清零 DMA 使用的地址，**不是** `0x30140000` 解码外设。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x300b2000 | `[IPL]` `0x8aa0` 访问的地址，像 NAND/DMA 初始化。 | 未标 | boot-decoder-capstone.md |
| 0x300f0310 / 0x300f0314 | `[主程序]` ISP 数字增益写入地址（四路同值，各钳到 65535）。 | 【指令核实】+【Unicorn 验证】 | exposure-apply-path-2026-10-27.md |
| 0x30115a00 / 0x30115b00 / 0x30115b14 / 0x30115b2c / 0x30115b80 / 0x30115bb0 / 0x30115e00 | `[主程序]` 被 `0x3d9294` 映射到配置后备位置的寄存器地址（映射到 `0x30210e00/e10/e20/e24/e48/e4c/e9c`）。 | 未标 | project-status.md（docs） |
| 0x30115a24 / 0x30115a2c | `[主程序]` 寄存器转储描述中的 `GAM_TOP GAMMA TABLE` 项。 | 未标 | display-entry-investigation.md |
| 0x30115bb0 | `[主程序]` 同描述中的 `PST_TOP Y_GAMMA`。 | 未标 | display-entry-investigation.md |
| 0x30140000 一带 | `[IPL]` **主程序硬件解码外设**基址；`0x10714–0x10770` 配置其周边与时钟。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x30140280 | `[IPL]` 解码完成状态寄存器，轮询 bit `0x4000`，**无超时**。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x301402c0 | `[IPL]` 解码寄存器基址（`0x107c4` 取）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x301402e4 / 0x301402e8 | `[IPL]` 明文长度的高/低部分（`0x10810–0x10824` 写）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x3014031c | `[IPL]` 写常量 `0xfee`（与 LZSS 候选初始环位置一致，属交叉证据）。 | 【指令核实】+【推断】 | repack-pipeline-2026-10-27.md |
| 0x30210020 + 0xf34/0xf38/0xf3c/0xf40 | `[主程序]` `0x41fa5c` 实际写入的地址组（**不是**已验证的 Gamma 写入口）。 | 【主核】 | project-status.md（docs） |
| 0x30210064 | `[主程序]` `[0x2ae454]` 处的基址字面量（命令区基址）。 | 未标 | project-status.md（docs） |
| 0x30210e4c + bank*0x30000 | `[主程序]` Y 曲线配置目标（bank 0/1，各 72 字节写入）。 | 【Unicorn 验证】 | native-y-curve-validation.md |
| 0x30210e9c | `[主程序]` `0x41fae4` 实际使用的配置地址。 | 【主核】 | project-status.md（docs） |
| 0x30210fd8 + 实例偏移 | `[主程序]` `0x420220` 打包写入的成像/LCD 配置地址（后续两字同写）。 | 未标 | display-entry-investigation.md |
| 0x30212bfc | `[主程序]` 另一命令区地址。 | 未标 | project-status.md（docs） |

---

## 4. 已被明确撤回或纠正的旧结论

| # | 旧结论（出处） | 纠正后的说法 | 来源报告 |
| --- | --- | --- | --- |
| 1 | "monitor/acquired 双状态 AE"是取景预览不跟随曝光的机制（`exposure-control-investigation.md` 的机制假设） | 机制假设撤回。`MONITOR MODE:`/`MONITOR MODE(ACQUIRED):` 是坏点统计按帧率模式的打印；`MONIT_REC_MODE=` 属 `RAW_MODE/FLASH_TEST` 调试回读块；`ACQLOOP AE`/`DEFOCUS AE` 打印 0/1 标志。但**独立的 MONIT AE 确实存在**（见第 3 行）。 | exposure-candidate-disassembly.md；monitor-ae-locate-2026-10-27.md（§5） |
| 2 | "Decode Error!" 会触发回退 BOOT（`update-recovery-path` 的宽泛描述） | 内层解码/段表错误打印 `Decode Error!` 后被吞掉，`0x8184` 无条件返回 0，`LoadData` 仍为 0，**不回退**；只有外层 `0x7ff8` 返回非零（如 PTBL 描述符查找失败返回 1）才走 FIRM→BOOT。坏压缩流不能靠 BOOT 兜底。 | repack-pipeline-2026-10-27.md（§6，明确声明优先于旧报告） |
| 3 | "取景亮度不随 M 档设定变化，原因必在 AE 之外"（`monitor-ae-locate` §8 推论） | 不成立：取景有**独立的 MONIT AE**（`0x362010` 步进）与独立状态 `0xc14707e0+0x38/+0x3c/+0x40`，由 `0x363c14` 等按测光与镜头状态重新分配时间/增益。原因在 AE 内部这条独立链，而不只是显示/ISP。 | exposure-apply-path-2026-10-27.md；exposure-preview-patch-2026-10-27.md |
| 4 | JSON 的 `EV` 不是"设定与测光之差"（`monitor-ae-locate` §6） | 该结论不能由 ISO100/200 都显示 5.0 得出（两者都可能超出显示上限）。EV 是带 ±5 限幅的曝光偏差显示；M 档快门实测使 EV 由 2.0→−3.3→−5.0→2.0。 | exposure-matrix-2026-10-27.md（"EV 旧结论纠正"）；exposure-preview-patch-2026-10-27.md |
| 5 | 升级器 `0x10f744` 的 `0xb000 − ceil(长度/0x20000)·0x100` 就是**无名首段**主程序的物理位置 | 该公式属于命名段 NPROG/NPG（段号 0）分派；官方首头不列 NPROG。无名首段实际走 `0x1100ac–0x1100dc → 0x10f644`，不能把公式当首段位置。 | repack-pipeline-2026-10-27.md（"与升级器长度公式的关系：必须修正旧推论"） |
| 6 | 升级器把"新旧 IPL 相同"判为错误（子代理读法） | 相同（返回非 0）时 `movne r4,#1` 直接返回成功、**不写**；只有不同才写。官方 3.1/3.2 的 IPL 逐字节相同，所以两版互刷不会重写 IPL。 | update-recovery-path-2026-10-27.md（§5b，"子代理把这一分支读成'相同被判为错误'，不采纳"） |
| 7 | `0x358c7c` 是 `SetMonit`（`BEF/AFT:SetMonit` 夹着的设置函数） | 它是接收结构体指针的通用参数应用函数；`BEF/AFT:SetMonit` 是函数内联数据、无可靠直接引用。真正与 monitor 显示链相关的是 `0x35894c`（`ADR 0x358980/0x358ab0`）。 | exposure-candidate-disassembly.md；exposure-decompile-review.md；monitor-ae-locate-2026-10-27.md（§9） |
| 8 | AE 结果不经 `0x2af604`，所以 AE 没有硬件写入（早期"施加路径未找到"的推论） | 施加路径确实存在且**不经过** `0x2af604`：时间走 `0x3ba548 → 0x21c00014/18`，增益走 `0x3bc684`/`0x429704 → 0x300f0310/314`。 | exposure-apply-path-2026-10-27.md；exposure-preview-patch-2026-10-27.md |
| 9 | 显示侧不读曝光量 → 取景亮度只能由相机端重算的曝光决定（暗示 ISP 无归一化） | Y 曲线族确实不读 `0xc146f4d4/4d8`，但这**不足以**证明 ISP 全部通路都无归一化；仍需运行 RAM/寄存器证据。 | monitor-ae-locate-2026-10-27.md（§4）；exposure-preview-patch-2026-10-27.md（第 8 条） |
| 10 | `0x36227c` 是带 `AFT:monit_ae` 标记的主 AE 循环 | `0x362288` 的 `ldr r1,[pc,#0x2e8]` 实际装载 `0x86258c` 数值表，是相邻字面量造成的假引用；`0x36227c` 形似诊断事件处理。`0x362010` 与 `monit_ae` 的关联仅为标签邻近，未被指令证明。 | exposure-candidate-disassembly.md；exposure-preview-patch-2026-10-27.md |
| 11 | `.text 0x35f488` 引用 `AE_DBG  TXT`、`.text 0xf218` 引用 `ESTEG.DBG` | 二者都是**字面量池字**；真正取用指令分别是 `0x35f3f0 ldr r1,[pc,#0x90]` 与 `0xee98 ldr r1,[pc,#0x378]`。 | sd-log-gates-review.md（"与旧记录的差异/更正"） |
| 12 | `0x41fa5c` 是 Gamma 写入口（子代理提议） | root 指令确认它写 `0x30210020+f34/f38/f3c/f40`；相邻 `0x41fae4` 用 `0x30210e9c`；Y 曲线写入是 `0x41ef2c → 0x30210e4c`。 | project-status.md（docs，"重要纠正"） |
| 13 | AE 回调表"在 .bss、静态为空"（子代理第一轮） | 漏看了 `0x36208c` 对 r4 的重新装载；表在 `.rodata 0x86253c`。 | monitor-ae-locate-2026-10-27.md（§2） |
| 14 | Y 曲线选择器"只调用 provider 表前两项 / rodata 当作未知 RAM" | `0x3bfe18` 递增并比较 7，path=1 从索引 1 到 6、其他从 0 到 6；`0x8742d2` 是已取得的 rodata。 | rea-full-m1-stage.md；native-curve-mode-validation.md |
| 15 | `0xf580`（IPL）是 memcpy/对齐拷贝循环 | Capstone 重解为 **strcmp**（逐字节比较后按字比较）；调用点 `0x7E34/0x7F64/0x7F88` 以 `cmp r0,#0` 判等。 | boot-decoder-capstone.md（§5） |
| 16 | 第一阶段"IPL 启动代码里存在 LZSS 解码循环"未定论（`boot-decoder-validation` 第一阶段） | 后续确定：`0x0–0x3FFF` 是 4 份相同启动块，无解码循环；解码由 `0x30140000` 外设完成，IPL 不解析 token。`0x5018` 前向逐字节拷贝助手**无调用者**，不能作为 overlap 语义证据。 | boot-decoder-capstone.md；repack-pipeline-2026-10-27.md（§4） |
| 17 | "PTBL 起始/长度按字节解释矛盾"（子代理） | 改为"单位未定"：与升级器的扇区计数分属不同地址层，未对齐。 | update-recovery-path-2026-10-27.md（§3、末尾） |
| 18 | `0x39b48c` 的 monitor 模式值可当作预览状态开关 | 只证明存在模式枚举与按值选标签的格式化代码；没找到写该模式值的函数、读它的取景调用点或状态迁移边。 | exposure-candidate-disassembly.md（§二） |
| 19 | `0x352c38` 把 AE 结果当 64 位曝光量每帧施加 | `ctrl+0x13c`/`+0x140` 在 AE 控制块里是两个独立字段，该 r4 很可能是另一个对象（如长曝光控制），**不能**据此认定 AE 结果由它施加。 | monitor-ae-locate-2026-10-27.md（§8） |
| 20 | `0x10be80` 是"开机检测待升级" | 仍只是推断（标志写入者未找到），未采纳为结论。 | update-recovery-path-2026-10-27.md（末尾） |
| 21 | USB 设备串 `ASDK00` 可能是内部存储 | 两个产品串 `YI ASDK00`(PID_012E)/`YI YI-M1`(PID_0001) 是同一序列号、同一容量、同一卷结构的同一张 SD 卡，即两套 USB 描述符。 | usb-storage-teardown-2026-10-26.md |
| 22 | `0x126dd0` 是与 `0x126d9c` 无关的另一函数（子代理） | `0x126e08 bne 0x126dd0` 使该分支从原入口可达；局部错误尾部证据仍成立，但不能据线性布局切割函数。 | iso-callback-review-2026-10-26.md |
| 23 | "普遍参数不保存"是已确认缺陷（用户初步判断） | 用户复测后撤回，不再作为确认缺陷或优先修复项。 | findings-2026-10-26.md；docs/research.md |
| 24 | 第三方报告"4K_24 已解锁" | 作者本人撤回：仅 HTTP 200 不代表格式生效。 | feature-feasibility-2026-10-26.md |
| 25 | 主程序"完全挂死"由 3.2 新增的断言/看门狗/内存耗尽检查导致 | 两版诊断字符串集合一致（`panic/watchdog/WDT/deadlock/stack overflow` 均为 0 条），Wi-Fi 区的 heap/AXI 串逐字节相同；既不支持也不排除任何具体假说。 | freeze-static-audit.md |

---

## 5. IPL 映像（另一映像，未混入以上各表）

IPL 是未压缩 131,072 字节分区（SHA-256 `3513946d…2dc4`）。下表地址均为 **IPL 文件偏移**；运行期 VA = 偏移 + `0x22ffc000`（如 `0x107ac` 执行在 `0x2300c7ac`）。

### 5.1 IPL 函数/代码区（按文件偏移升序）

| 偏移 | 名称 | 作用 | 证据等级 | 来源报告 |
| --- | --- | --- | --- | --- |
| 0x0000–0x3fff | `boot_block_x4` | 同一 4 KB 启动块的 4 份拷贝（0x0000/0x1000/0x2000/0x3000 完全相同）。 | 未标（反汇编证据） | boot-decoder-capstone.md |
| 0x0000 | `vector_table` | `e59ff018`×5 + `eafffffe`，异常向量目标在 0x20 起。 | 未标 | boot-decoder-capstone.md |
| 0x0040 | `clock_setup` | 读 `0xdbff`/`0x23000000` 后 `blx 0x526`。 | 未标 | boot-decoder-capstone.md |
| 0x00fc | `reset_entry` | `bl 0x130`（SDRAM 初始化）→ `0x100` `msr cpsr_c,#0xdf` → `bl 0x1ac` → `bl 0x24c/0x254` → `bl 0x40` → `b 0x114` 原地循环。 | 未标 | boot-decoder-capstone.md |
| 0x01ac–0x0248 | `bss_clear` | 按 0x100/0x20/4/1 分块清零 0x23c4 字节 @ `0x2300d320`；不是拷贝/解码。 | 未标 | boot-decoder-capstone.md |
| 0x0526 | `hw_init_thumb` | Thumb：访问 `0x21801000` 系列寄存器，`bl 0x3ea`。 | 未标 | boot-decoder-capstone.md |
| 0x4ff8 | `byte_copy_backward` | 后向逐字节拷贝助手；全镜像 BL/BLX 调用者为 0。 | 未标 | boot-decoder-capstone.md |
| 0x5018 | `byte_copy_forward` | 前向逐字节拷贝循环（`ldrb/strb` 交替、`bne 0x5018`）；若以 `src=out-distance` 调用自然支持 overlap，但**调用者为 0**。 | 未标 | boot-decoder-capstone.md |
| 0x5000–0x6000 | `arm_code_block` | 1024 条 ARM 指令（10 push/11 bl/12 bx）。 | 未标 | boot-decoder-capstone.md |
| 0x6000–0x66e8 / 0x7000–0x7920 / 0x8000–0x8258 | `arm_function_regions` | 若干 ARM 函数区（边界未完全递归展开）。 | 未标 | boot-decoder-capstone.md |
| 0x8a8c / 0x8aa0 | `nand_dma_init` | 访问 `0x300b2000`、`0x2300d45c`，像 NAND/DMA 初始化。 | 未标 | boot-decoder-capstone.md |
| 0x8d78 | `hw_pcie_init_thumb` | Thumb：`push {r4-r7,lr}`，访问 `0x21801000`、`0x2300f6da`。 | 未标 | boot-decoder-capstone.md |
| 0xf580 | `strcmp` | 逐字节比较后按字比较，返回字节差（**纠正：曾被称为 memcpy**）。 | 未标 | boot-decoder-capstone.md |
| 0xf668 | `string_buffer_func` | ARM 字符串/缓冲处理函数。 | 未标 | boot-decoder-capstone.md |
| 0x10000–0x10648 | `libgcc_routines` | `__udivsi3` 等 libgcc 例程。 | 未标 | boot-decoder-capstone.md |
| 0x10980–0x111a3 | `ipl_rodata` | 字符串/只读数据区（`0x12000` 之后全零）。 | 未标 | boot-decoder-capstone.md |
| 0x10ae0 / 0x110c8 / 0x110f4 | `ipl_msg_strings` | `LoadData[ %-20s ] not found `、`loading [%08lx:%8s] ...... `、`Decode Error!`；无静态直接 xref（加载器用 `0x2300d080` 起的 RAM 表）。 | 未标 | boot-decoder-validation.md；boot-decoder-capstone.md |
| 0x10a58 / 0x10b5c | `section_name_strings` | `.rodata`、`.ver_table`。 | 未标 | boot-decoder-validation.md |
| 0x111d0 | `ptbl_id_name_table` | PTBL 分区 id→名字表（17 个名字指针，按 `+0x22ffc000` 解析成功）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x4144 | `select_partition` | `bl 0x7834` 选择分区 id。 | 【主核】/【指令核实】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x4158 | `load_data_call` | `bl 0x7ff8` 装载所选分区。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x415c–0x4188 | `boot_fallback` | `cmp r0,#0 / beq`；失败且 id==`0x10000012`(FIRM) 时打印 "Instead, I'll load BOOT for you." 并改载 `0x10000010`(BOOT)。 | 【主核】+【Unicorn 验证】 | update-recovery-path-2026-10-27.md；repack-pipeline-2026-10-27.md |
| 0x41a8–0x41b4 | `invalid_firmware_path` | `bl 0x6740` 查 PTBL 描述符；失败打印 "Invalid Firmware?" 并返回 6（**不是**全面 CRC/签名校验）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x41d0 → 0x4b84 | `ver_table_copy` | 把 `0x23000000` 起 65 字节（`.ver_table`）复制到传入地址并返回 65；不是版本比较。 | 【指令核实】+【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x40cc | `outer_loader` | 外层加载：内部 `0x7c48=-1` 时只装一次 FIRM，无 BOOT 回退；只有外层返回 1 才出现 FIRM→BOOT 两次调用。 | 【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x4488–0x4494 / 0x449c | `read_ptbl` | 调介质描述符 `+0x18` 回调读 PTBL，随后 `→ 0x683c` 校验 `@PEI` 魔数与条目数 ≤32。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x4bd8 | `ptr_convert` | 高四位为 0 时加 `0x40000000`，已为 4 时保留，其余变 0。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x4c28–0x4cc4 | `record_walk` | 段表变长记录遍历：`+0`下一条、`+4`名字、`+8`地址、`+0xc`长度、`+0x10`标志、`+0x14`关联记录；`0x4d58` 最多比较 40 字节名字。 | 【指令核实】+【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x6740 | `ptbl_find_by_id` | 在 PTBL 中按分区 ID 查找，每项 24 字节；`0x67b8` 原样复制描述符；仅版本 `+4`==0 时转换起始/长度单位。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x683c | `check_pei_header` | 检查 `@PEI` 魔数与条目数。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x6ab4 / 0x6b28 / 0x6e08 | `timer_helpers` | 三个计时器函数（完整装载路径用例中被桩替换）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x702c | `printf_wrapper` | 打印（格式化到 `0x2300d32c`，再经 `0x6f88` 逐字符输出）。 | 【主核】（部分） | ipl-rea-provisional.md；repack-pipeline-2026-10-27.md |
| 0x7588 | `boot_cond1` | 仅当 `[0x22000308]==0` 且 `([0x2200030c] & ~0x80000)==0x100000` 时返回 1。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x75c0 | `boot_cond2` | 配置 `0x22000000 |= 0x300`，按 mask 0x1e 扫描输入，判断 `([0x22000314]&0x1e)==0xa` 且 `([0x22000310]&1)==0`。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x7834 | `partition_select` | 选择条件组合；满足两个条件返回 BOOT（`0x7904`），否则返回 FIRM（`0x790c`）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x793c | `find_picbase` | 分别尝试偏移 `0x1000`、`0x40` 寻找 `.picbase` 以确定段表链。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x79c0 | `load_rom_record` | 用 ROM 长度向上取整到 512 字节作为介质读取长度，并以关联目标记录的地址/长度设置解码输出。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7a10–0x7a28 | `rom_offset_calc` | 由 ROM 地址与 `.ROM.vector` 地址之差求起始介质位置。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7a38–0x7a90 | `decode_branch` | 对标志 `&0x30` 与源/目标长度判断；压缩分支从 `0x7a90` 起先读 0x800 字节到 `0x43000000`、调硬件、读其余内容、等完成。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7b08 → 0x107ac | `hw_decode_call` | 参数依次为模式、压缩输入地址、输出地址、**明文长度**。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7b50 → 0x108d0 | `hw_decode_wait_call` | 调用 `0x108d0` 等待并收尾。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7b64 | `bss_clear_dma` | 独立 BSS 清零 DMA（用 `0x30041000`，装载用例中被跳过）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7c48 | `load_segment_table` | 按名字查段表并装载；找不到必要表项返回 -1。 | 【指令核实】+【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x7cbc–0x7d34 | `find_secinfo` | 找 `.secinfo` 并用其长度决定还要读多少段表。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7d4c–0x7d78 | `find_rom_vector_text` | 找 `.ROM.vector`、`.ROM.text`。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7e44–0x7e70 | `rom_text_record_loop` | 从 `.ROM.text` 遍历到 `.codelimit`，每条调用 `0x79c0`。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x7ea8 | `select_79c0_by_name` | 按名字选择 `0x79c0`（使用 512 字节页、`0x43000000` 缓冲与 `0x107ac/0x108d0`）。 | 未标 | ipl-rea-provisional.md；boot-decoder-capstone.md |
| 0x7ff8 | `load_data` | 查询 `0x8000` 所归属函数：打印 loading、调用 `0x7ea8/0x7c48`，返回 -1 时打印 Decode Error。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x8000 | `outer_update_load` | 上层更新/加载函数，调用 `0x6740/0x67f4/0x702c/0x6ab4/0x6b28/0x6e08/0x7ea8/0x7c48/0x10028`。 | 【指令核实】 | boot-decoder-capstone.md |
| 0x8020 / 0x802c | `ptbl_descriptor_lookup` | 查 PTBL 描述符；失败返回 1（这才是外层回退的触发条件）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x8098–0x80a0 / 0x80fc | `firm_read_dispatch` | 读描述符 `+8` 为 1 时进入 `0x80fc → 0x7c48`。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x8104–0x8114 | `decode_error_report` | 检测 `0x7c48=-1`，打印 `Decode Error!` 并设 `r5=2`。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x814c–0x8188 | `load_return_zero` | `0x814c` 只用 r5 决定是否打印速度；`0x8184/0x8188` **无条件返回 0**（吞掉解码错误）。 | 【指令核实】+【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x832c / 0x837c–0x839c | `nand_callback_read` | NAND 回调；向 Thumb `0xd766` 传 `(0,0,2,目标地址)` 读 PTBL。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0xd766 | `nand_read_thumb` | 底层 Thumb NAND 读函数（物理 NAND/坏块/地址转换未仿真）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x10714–0x10770 | `hw_decode_config` | 配置 `0x30140000` 周边及相关时钟寄存器。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x107ac | `hw_decode_entry` | 解码入口：取寄存器基址、写源/目标地址与明文长度。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x107c4–0x10824 | `hw_decode_regs` | 基址 `0x301402c0`；源/目标减 `0x40000000` 后分别右移 3、19 位写地址寄存器；明文长度高低写 `0x301402e8/e4`。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x10834–0x1083c | `hw_decode_const` | 写常量 `0xfee` 到 `0x3014031c`，随后还有 `0/4/0x5000/3` 的配置。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x108b4–0x108c0 | `hw_decode_start` | 把 `模式|2` 写入控制寄存器。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x108d0–0x108e0 | `hw_decode_wait` | 轮询 `0x30140280` 的 `0x4000` 位完成，**无指令计数/时间上限**，完成后清状态并复位部分配置。 | 【指令核实】 | repack-pipeline-2026-10-27.md |

### 5.2 IPL 使用的 RAM（文件偏移换算后）

| 运行期地址 | 含义 | 证据 | 来源报告 |
| --- | --- | --- | --- |
| 0x22ffc000 起 | IPL 数据映射基址（VA = 文件偏移 + 0x22ffc000）。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x23000000 | IPL 代码/数据起点（`.ver_table` 复制源）。 | 【指令核实】 | repack-pipeline-2026-10-27.md |
| 0x2300cff4 | `0x793c` 取的段表项来源。 | 未标 | boot-decoder-capstone.md |
| 0x2300cb24 / 0x2300cb48 | `"Instead, I'll load BOOT for you."` / `"Invalid Firmware?"` 字符串。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x2300cfd8 | `"PSQ PWR Factor Wait Skip"` 超时打印串。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0x2300d080 | 名字表（3 项）起点，`0x7EA8` 从此取。 | 未标 | boot-decoder-capstone.md |
| 0x2300d0a4 | 被 `strcmp` 比较的 RAM 字符串之一。 | 未标 | boot-decoder-capstone.md |
| 0x2300d1a0 | 文件系统分发函数指针表。 | 未标 | boot-decoder-capstone.md |
| 0x2300d320 | `0x1ac` 清零的 0x23c4 字节 BSS 起点。 | 未标 | boot-decoder-capstone.md |
| 0x2300d32c | 格式化输出缓冲（`0x702c` 写入）。 | 未标 | ipl-rea-provisional.md |
| 0x2300d45c | `0x8aa0` 访问的 RAM 地址。 | 未标 | boot-decoder-capstone.md |
| 0x2300f6da | `0x8d78` 访问的 RAM 地址。 | 未标 | boot-decoder-capstone.md |
| 0x40000000 | 段头/表读取目标（10×512 字节）。 | 【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x40001400 / 0x40001800 | 后续两批读取目标。 | 【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x40002000 | 解码输出（`.text` 目标基址），硬件配置参数之一。 | 【指令核实】+【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0x43000000 / 0x43000800 | 压缩数据暂存与解码输入缓冲。 | 【指令核实】+【Unicorn 验证】 | repack-pipeline-2026-10-27.md |
| 0xc1e00000 | PTBL `USER` 分区装载地址。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0xc2000000 / 0xc2a00000 / 0xc2b00000 / 0xc2c00000 | PTBL `DATA0–3` 装载地址。 | 【主核】 | update-recovery-path-2026-10-27.md |
| 0xdffe0000 / 0xdffa0000 | PTBL `CAMDEF` / `CAMADJ` 装载地址。 | 【主核】 | update-recovery-path-2026-10-27.md |

### 5.3 PTBL 分区表（格式 `"@PEI"`、版本 1、13 条目，每条 6 字 `{id,?,?,装载地址,起始,长度}`）

| 分区 | id | 起始 | 长度 | 装载地址 | 证据 | 来源 |
| --- | --- | ---: | ---: | --- | --- | --- |
| BOOT | 0x10000010 | 0x200 | 0x400 | — | 【主核】 | update-recovery-path-2026-10-27.md |
| USER | 0x10000021 | 0x600 | 0x1000 | 0xc1e00000 | 【主核】 | update-recovery-path-2026-10-27.md |
| DEBUG | 0x10000022 | 0x1600 | 0x5000 | — | 【主核】 | update-recovery-path-2026-10-27.md |
| ARM926_1 / ARM926_2 / ARM9 | 0x10000101–103 | 0x6600 / 0x7600 / 0x8600 | 各 0x1000 | — | 【主核】 | update-recovery-path-2026-10-27.md |
| DATA0–3 | 0x10000200–203 | 0x9600 / 0xe600 / 0xee00 / 0xf600 | 0x5000 / 0x800×3 | 0xc2000000 / c2a00000 / c2b00000 / c2c00000 | 【主核】 | update-recovery-path-2026-10-27.md |
| CAMDEF | 0x10000013 | 0xfe00 | 0x200 | 0xdffe0000 | 【主核】 | update-recovery-path-2026-10-27.md |
| CAMADJ | 0x10000011 | 0x10000 | 0x200 | 0xdffa0000 | 【主核】 | update-recovery-path-2026-10-27.md |
| FIRM | 0x10000012 | 0x10200 | 0x23600 | — | 【主核】 | update-recovery-path-2026-10-27.md |
