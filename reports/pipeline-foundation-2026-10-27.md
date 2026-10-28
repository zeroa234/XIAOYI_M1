# 打包链基础核实与官方升级入口

日期：2026-10-27。只读离线核实：未生成或修改固件镜像，未向相机或 SD 卡写入。用户要求本阶段只做离线定位，暂不生成刷机镜像。

## 1. 容器校验：SUM 为段体字节简单累加

`scripts/check-container-and-decode.py` 读取官方 3.1-cn、3.2-cn `firmware.bin`（先核对固定 SHA-256），按每段 0x100 字节 ASCII 头的 `LENGTH=` 切分，计算段体字节和。两版共 8 段（主程序、ND1、IPL、PTBL）全部与头中 `SUM=` 相等，且各段恰好覆盖整个文件。结果见 `container-and-decode-check.json`。

这证明了文件头这一层的校验算法。**没有**证明升级器或 IPL 不做其他检查（版本比较、段内校验、分区写后校验等）；这些由后续定位核实。

## 2. LZSS 复制语义：统计上明确支持顺序复制

已有两种解码输出：上游工具的快照复制（`output/body-3-2-cn/*.decompressed`）与 ff7tools 的逐字节顺序复制（`output/reference-decoded/body-3-2-cn/*.mapped.candidate.bin`）。只在两者不同的字节上评分：

| 节 | 差异 | 快照复制 | 顺序复制 |
| --- | --- | ---: | ---: |
| .text | 2,979 个受影响的 4 字节字 | 85 个非法 ARM 字 | 13 个非法 ARM 字 |
| .rodata | 2,168 段位于 ASCII 上下文、14,404 字节 | 可打印率 80.8% | 97.0% |
| .data | 199 段位于 ASCII 上下文、728 字节 | 可打印率 83.4% | 100% |

典型样例：.text 0x96 处顺序复制得到连续 `mov r0,r0`（`a0e10000`）填充，0xd4 处得到重复的 `f053a0e8`（`stmia r0!,{r4-r7,ip,lr}`，展开的块拷贝），快照复制在同位置为乱码。顺序复制剩余的 13 个非法字可能是 .text 中的字面量数据，未逐个核对。

结论：顺序复制的输出在差异处一致地更像真实代码和文本，此前 REA/Ghidra 使用的参考解码可信度因此提高。**解码器本体仍未找到**：主程序第一个 4 KB 只有向量表（复位向量指向已解压的 .text 起点 0x2000）和若干 CPSR/拷贝/延时小函数，没有解压循环；解码可能在 IPL 中，也可能由硬件完成。今后若需重新编码，应只生成不含重叠匹配、不引用未写入环形缓冲槽位的流，使其在两种语义下解码结果相同。

## 3. 段表位置

主程序段 0 的第二个 4 KB（容器内偏移 0x1000）是段装载表，含 `.dtcm .picbase .vector .itcm .secinfo .hardware_imple .syscall .text .rodata .rodata_end` 及对应的 `.ROM.*` 记录。例如 `.ROM.text` 位于 0x10002000、长 0x2f910c（3,117,324，等于压缩负载长度），装载到 `.text` 0x2000、长 0x43d438；`.ROM.rodata` 0x102fb800、长 0x3eef74；`.ROM.data` 0x106ea800、长 0x1c819；`.data` 0xc09b0000、长 0x52e50。`reference-decode.py` 已按这些精确名称取长度。

## 4. 官方升级入口：升级器在主程序 UI 内

官方《使用 SD 卡升级相机固件说明》（`data/input/body-3-2-cn/`，渲染页面核对）：

1. 电量 >50%，`firmware.bin` 放 SD 卡根目录（V1.2-cn 之前放 `XIAOYI/`）。
2. 开机后在 Live View 页右滑进入 MENU SETTING，上滑到第三屏，点“固件信息”。
3. 在固件信息页**同时按 Q 键与 PLAYBACK 键**，进入出厂设置页。
4. 点“升级机身固件”并确认，约 12 秒后自动重启。升级期间禁止取电池、取卡、拔线、卸镜头、按键或关机。

因此官方升级依赖主程序正常启动到 UI。若改动后的主程序无法进入该页面，官方途径就不可用；恢复能力取决于 IPL 是否有备用分区或其他加载方式（IPL 中有 `FIRM2`、`Invalid Firmware?`、`Instead, I'll load BOOT for you.` 等字符串，含义待指令核实）。这是今后任何机身修改之前必须先回答的问题。

## 复现

```powershell
python -B scripts/check-container-and-decode.py
```

需要项目内 `temp/tool-deps` 中的 Capstone 以及 `output/` 下已有的两种解码输出。
