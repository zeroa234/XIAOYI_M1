# 复现指南与第三方工具

在仓库根目录执行。Python 3.11+、Node.js、Git 为基础环境；Ghidra 适配按 Windows、Ghidra 12.2 / JDK 25 编写，ELF 包装还需要 Ubuntu WSL。没有验证完整工具链的跨平台运行。

## 合成数据测试

```powershell
python -B tests/test-liveview-metadata.py
python -B tests/test-repack.py TokenTests
```

上述测试使用合成数据或 mock，无需固件、第三方依赖或相机。`test-repack.py` 的 `OfficialTests` 需要官方输入，无固件时保留 `TokenTests` 参数。

## 原厂输入

自行取得官方固件并校验 README 中的 SHA-256，然后放置：

```text
data/input/body-3-2-cn/firmware.bin
data/input/body-3-1-cn/firmware.bin
```

输入清单见 [input-manifest.json](../reports/input-manifest.json)，3.1 历史来源见 [recovered-3-1-source.json](../reports/recovered-3-1-source.json)。历史地址不保证持续可用。

## 锁定上游实现与拆包

```powershell
New-Item -ItemType Directory -Force vendor,temp,logs | Out-Null
git clone https://github.com/protyposis/yi-mirrorless-firmware-tools.git vendor/yi-mirrorless-firmware-tools
git -C vendor/yi-mirrorless-firmware-tools checkout b90b96c124a3b076fa0283404e6595a4a40d20d0
Push-Location vendor/yi-mirrorless-firmware-tools
npm ci --ignore-scripts
Pop-Location

New-Item -ItemType Directory -Force vendor/ff7tools-reference | Out-Null
Invoke-WebRequest 'https://raw.githubusercontent.com/cebix/ff7tools/6bf1fbcec2c88c1856cffd4a371719b406fee654/ff7/lzss.py' -OutFile vendor/ff7tools-reference/lzss.py
Get-FileHash vendor/ff7tools-reference/lzss.py -Algorithm SHA256

node scripts/unpack.cjs 3.2-cn
node scripts/unpack.cjs 3.1-cn
python -B scripts/reference-decode.py
```

LZSS 文件哈希应为 `ee3b65e055231164d29ac53a67da1dd047c2e761b932c6a3efb27e6d7f102f84`，脚本会再次核对。上游固件工具的运行依赖是 `string@3.3.3`。解码与重压缩的局限见 [编解码调查](../reports/codec-investigation.md)。生成的候选映像用于分析。

## ARM 与 Ghidra 分析

```powershell
python -m pip install --target temp/tool-deps -r config/analysis-requirements.txt
python -B scripts/setup-analysis-tools.py
python -B scripts/analyze-candidate.py
```

安装脚本按 [来源和哈希](../reports/toolchain-sources.json) 下载便携工具到 `vendor/`，生成本机专用的 `reports/toolchain-installed.json`；该文件已排除提交。初始分析完成后，按 [代码地图流水线](code-map-pipeline.md) 导出函数、调用关系与代码分片。跨机器重新生成本机配置，不要复制别人的绝对路径。

## 可选：取景测试

```powershell
git clone https://github.com/bullbin/xiaoyi_m1_re_liveview.git vendor/yi-m1-liveview
git -C vendor/yi-m1-liveview checkout 52deda7d7ed390c2edc1a3d0c2383dc7cdf7c9ca
python -B tests/test-liveview-capture.py
python -B tests/test-exposure-probe.py
```

测试仅使用本机回环 HTTP/UDP。真实采集和参数探测会操作相机，先阅读 [采集说明](direct-liveview-capture.md) 与 [曝光实验](exposure-preview-probe.md)。

## 工具归属与验证范围

复用 Ghidra、Capstone、Unicorn、GNU binutils、pyelftools，以及上面固定版本的第三方实现。源码和报告说明自写适配、采集生命周期、元数据解析、实验装置、官方 token 受约束拼接和独立验证的范围。第三方源码不随仓库分发，使用时遵守上游许可。

公开整理时验证的是源码与合成数据测试，没有重新下载整套工具或重跑完整 Ghidra 分析，也没有开展新的相机实验。
