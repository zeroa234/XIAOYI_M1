# 已验证的免拆机取景采集路线

日期：2026-10-26。本次已在用户机身完成直接 HTTP/UDP 通信；它提供参数与取景数据，不提供 CPU 负载、任务栈或崩溃转储。

## 连接方式

用户用安卓小蚁微单 App 完成初始配对/开启相机 Wi-Fi；电脑通过手机 USB 网络共享保留互联网连接，无线网卡单独接入相机 AP。手机不同时占用相机遥控会话。网络切换由用户完成，脚本不读取、保存或传递 Wi-Fi 密码。

PCAPdroid 的免 root 模式会代理部分流量，而且主要捕获手机主动建立的连接，不能保证获得相机主动推送的 UDP 取景。本项目没有实测其导致 M1 通信失败；当前使用直接-PC路线，**无需开启 PCAPdroid**。依据：[PCAPdroid 的抓包限制](https://emanuele-f.github.io/PCAPdroid/quick_start#14-packet-analysis)。

## 本地工具

`scripts/capture-liveview.py` 复用固定于 `52deda7d7ed390c2edc1a3d0c2383dc7cdf7c9ca` 的 [bullbin 原版 UDP 解码器](https://github.com/bullbin/xiaoyi_m1_re_liveview)。原文件不修改，运行时只注入有界套接字和项目输出位置；分包解码逻辑仍由上游代码执行。自写部分是采集生命周期、限制与原始数据归档，不是新的相机协议或曝光算法。

从项目目录执行：

```powershell
python -B scripts/capture-liveview.py --check
python -B scripts/capture-liveview.py --capture --seconds 3
```

默认采集10秒，可选1–15秒。真实网络操作必须在能访问宿主相机网络的执行环境运行；当前受限执行环境中的网络/PnP结果不能用于认定宿主没有无线设备。

只允许三个命令：`GetCameraStatus`、`RCStartRemoteCtl`、`RCStopRemoteCtl`。没有拍照、录像、调参、删除媒体或固件更新命令。若相机拒绝遥控或存在另一会话，不自动重试。

输出在 `output/live-captures/<UTC时间-随机标识>/`：

- `session.json`：状态/启停回复、退出与错误信息。
- `datagrams.zip`：原始 UDP 应用数据和接收时间清单；不是链路级 PCAP。
- `packet_*.jpg/.txt`：原版解码器认定完整有序的画面与参数头。
- `receiver.log`：接收器日志。

原始分包最多约32 MiB，额外有包数和时间上限；接收时在内存暂存原始数据，采集结束后归档，套接字接收缓冲请求4 MiB。结束时保持 UDP 接收并先请求退出遥控，再关闭接收器。异常退出也尝试有界清理，不关闭相机 AP，不改防火墙或网络配置。

## 验证与局限

`tests/test-liveview-capture.py` 在本机回环地址验证了完整帧、乱序包保留、时间退出、停止遥控时仍保留 UDP 监听、拒绝其他客户端时不停止其会话，以及拒绝固件命令。3项测试通过。测试的图像负载是合成协议样本，不是相机实测画质。

上游解码器会舍弃乱序/缺包的帧，因此保存的 JPEG 数量不是相机实际帧率。原始包保留用于后续重组核查。网络、电脑接收缓冲、文件写入和场景内容都能影响观察，不能把客户端采集改进当作机身性能优化。

首轮10秒采集保存4帧、结束请求超时；之后一次被动监听无新包，但 GetCameraStatus 正常回复。调整接收与退出顺序后的3秒采集保存13帧，三个命令均返回200。这不是单变量对照，不能证明首轮异常的根因。

## USB 存储的副作用

2026-10-26 实测：每次成功发出 `RCStartRemoteCtl` 后约 68 秒，相机的 USB 大容量存储会从主机消失（三次复现；静置不抓取 4 分 28 秒不发生；每 15 秒一条 `GetCameraStatus` 心跳不能推迟它）。取景链路不依赖 USB，掉线期间 `GetCameraStatus` 仍返回 200。掉线后不会自动恢复，需手动拔插。因此读卡应在抓取前完成，或改用读卡器，不要依赖抓取后的盘符。证据与限制见 `reports/usb-storage-teardown-2026-10-26.md`。

机身固件3.2-cn仍是用户确认，当前接口独立核实了12–40镜头1.1。没有进行任何受控曝光参数变化测试。图像和原始包保留在被Git忽略的本地输出目录。结果见 `reports/liveview-baseline-2026-10-26.json`。
