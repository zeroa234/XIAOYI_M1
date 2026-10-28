# 3.1 回退与恢复条件核实

日期：2026-10-26。只读离线调查，未操作相机。

已有官方 3.1-cn 原包不等于已经验证回退兼容性。当前没有执行 3.2-cn -> 3.1-cn，也没有找到可核实的原厂降级保证或失败恢复流程。不能把第三方下载站对“相机固件可回退”的通用模板文字当作 M1 的原厂说明。

用户后续明确补充“回退是可以的”，作为用户提供的操作信息接纳，主代理未亲自执行。用户要求以 3.2 为基础同时解决性能/稳定性和曝光预览、保留 3.2 的功能；因此 3.1 的角色是代码对照及恢复备用，不把降级作为最终交付。

已核实：

- 3.1-cn 来自官网历史下载页保留的链接，现仍可从原厂服务器通过 HTTPS 取回，来源和校验见 `recovered-3-1-source.json`。
- 3.1-cn 与 3.2-cn 包都标识 C59Y1 / M1CN；三项非程序分段 ND1、IPL、PTBL 逐字节相同，见 `version-comparison.json`。
- 官方包内文档说明的是 SD 卡升级流程；没有据此获得可在系统完全不能启动时使用的恢复步骤。
- 两版相同的 IPL 直接可读，字符串包含 `Invalid Firmware?`、`load error!`、`invalid partition table.`、`Instead, I'll load BOOT for you.`，还出现 `ARM926_1`、`ARM926_2`、`FIRM2` 等分区/载入标识。它们不证明存在面向用户的 SD/USB 恢复模式、自动 A/B 回退或无损重刷途径。

取证命令使用已有 ripgrep，从未压缩的 IPL 提取 ASCII；产物为 `output/ipl-strings.txt`，无需依赖实验性的主程序解压器。字符串是线索，未反汇编验证控制流，也没有通过硬件验证。

当前用户报告多种操作可能完全挂死，电源开关不响应、须拔电池恢复。暂停反复真机压力测试。后续若考虑回退，需要先确认升级程序对旧版的接受条件和可用恢复方式，不能把当前用户机身当作未知恢复条件下的改版验证机。

来源：

- https://www.xiaoyi.com/weidan_download.html
- https://web.archive.org/web/20180119102548id_/http://www.xiaoyi.com:80/weidan_download.html
- `data/input/body-3-2-cn/小蚁微单相机M1使用SD卡升级固件方法.pdf`
- `data/input/body-3-1-cn/小蚁微单相机M1使用SD卡升级固件方法.pdf`
- 已校验的 3.1/3.2 官方输入及对应未压缩 IPL 分段。
