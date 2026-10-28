# REA WSL 安装与真实 ARM 分析验证

日期：2026-10-26。共用安装位于工作区 `extensions/mcp/rea`，由各 harness 单独登记，启动独立会话；Codex 和 Pi 已配置，未修改 Claude。

## 环境

REA 6.8.0、Linux Node 24.22.1、Temurin JDK 21.0.13+9、Ghidra 12.1.4；宿主为现有 Ubuntu WSL2 x64。Node、Java、Ghidra 的官方归档 SHA256 校验通过；npm 固定版本和完整性记录于安装目录 `package-lock.json`。原有 Windows Ghidra 12.2 和分析库保留。

MCP SDK 的 Windows→WSL 握手、229 个工具清单、只读会话查询均通过；Pi 原生 `mcp list --json` 确认 REA connected 且 errors 为空。Pi 子代理启动器显式保留 `builtin:mcp`，相关 11 项回归测试通过。旧的已运行服务需要重新连接后采用修改；在此之前可显式使用 `load_extensions: true`。

## 固件代码实测

用参考解码候选 `.text` 的原始字节范围 `[0x41e7d4,0x41fb80)` 制作仅供分析的 5036 字节片段，没有更改字节。片段 SHA256：`c437f905012d97ac7cc41000bc00dc069d418bad3e2c5827a3be5bab4f245a3f`。

REA CLI 使用 raw ARM 导入，映射基址 `0x41e7d4`，通过 `config/rea-smoke-seeds.tsv` 预置已知函数 `0x41ef2c`。实际返回：

- Ghidra 12.1.4 完成自动分析后返回函数 dossier。
- 函数范围 `0x41ef2c..0x41f013`，232 字节、58 条 ARM 指令，末尾 `0x41f010: bx lr`。
- 18 次 store；反编译的最后字段为 `puVar1[0x11] = param_1[0x21]`，与既有 Unicorn 原生配置打包验证一致。
- 输入片段哈希在分析后不变。

原始结果保存在忽略的 `output/rea-arm-smoke/function.json`。这验证安装和分析链路能实际处理已经核实的 M1 代码，不代表发现新修复。

## 已解决的环境差异

发布版 6.8.0 的 `REA_MCP_OUTPUT_SCHEMA_PROFILE` 只接受 full/off，主分支文档另提及 compact；启动器选用 off，服务端仍验证输出。

D 盘 DrvFS 不能绑定 Linux Unix socket。初次真实分析已完成导入，但 bridge 在绑定 socket 时失败。启动器选择较长的 D 盘 runtime 路径，采用原版 REA 已提供的短 socket 回退，仅 socket 临时位于 WSL `/tmp`，关闭时清理；重试成功。没有修改 REA 上游代码。

## 分析限制与下一步

原始 ARM 导入固定使用 `ARM:LE:32:v7`，本机候选代码是 ARMv5；片段不包含 `.rodata`、初始化 `.data` 及真实运行态 RAM。函数种子是调用方已知信息。不要从这个片段中推导完整间接调用关系、真实参数值或运行行为。

后续已用 GNU as/ld 构造仅供分析的多段 ELF，并由独立 pyelftools 验证 `.text/.rodata/.data` 原字节、原地址和 5 个 NOBITS 范围；见 `reports/analysis-elf-verification.json`。REA 已接受其为 ARM executable，尚未对完整 ELF 启动 Ghidra 自动分析或验证实际处理器语言。用户随后要求存档暂停，目标已关闭。恢复时从该处追查 Y 曲线的取景模式、曲线提供者及配置提交路径。没有性能修复、曝光预览补丁或刷机产物。
