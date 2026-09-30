# NetScope

[English](README_EN.md) | 中文

一款便携的 Windows 网络设备发现工具，面向工业控制系统（ICS）和 PROFINET 现场环境。

## 功能特性

- **主动 ARP 扫描** — 四阶段子网扫描，CIDR 去重，ARP Probe 空闲地址探测，冒用冲突自动换址
- **被动监听** — 持续捕获 ARP、RARP、IPv4、LLDP 流量，自动建立 IP-MAC 映射表
- **PROFINET DCP** — 通过 DCP Identify/Set/Get 协议发现、配置、恢复出厂 PROFINET 设备
- **设备改址** — 一键加入设备子网（Join Subnet）或手动改 IP/掩码/网关/DNS，支持 Restore 恢复
- **热插拔监控** — 基于 `NotifyIpInterfaceChange` 实时检测网卡 Up/Down/移除/插入（无轮询）
- **厂商识别** — OUI（MA-L/MA-M/MA-S）和 PNO 厂商 ID 查询，支持外置 TSV 覆盖
- **系统托盘** — 最小化驻留托盘；插网线时自动弹出主窗口

## 快速开始

1. 从 [Releases](../../releases) 下载 `NetScope.exe`
2. 右键 → **以管理员身份运行**
3. 若未安装 Npcap，软件会弹窗提示安装
4. 从下拉列表选择一张物理网卡
5. 选择 **Passive**（默认）或 **Active** 模式
6. 点击 **Start**

## 从源码构建

### 前置条件

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)（Windows x64）
- [Npcap SDK](https://npcap.com/)（构建时需要 wpcap.dll）

### 构建

```bash
cd src/NetScope
dotnet publish -c Release -r win-x64 --self-contained true -o publish
```

输出的 `NetScope.exe` 为单文件自包含程序（约 143 MB），可直接拷贝到任意 Windows x64 机器运行，无需安装。

## 项目结构

```
src/NetScope/
├── App.xaml / App.xaml.cs           — WPF 应用入口
├── MainWindow.xaml / .xaml.cs       — 主界面、托盘、徽章/状态管理
├── DCPDeviceDialog.cs               — PROFINET DCP 设备操作弹窗
├── NetScope.csproj                  — 项目文件（.NET 8, WPF, 自包含）
├── app.manifest                    — 管理员权限声明
├── icon.ico / icon.svg              — 应用图标
├── segments.txt                    — 阶段3自定义网段配置
├── Assets/
│   └── npcap-installer.exe          — 内置 Npcap 安装包
├── data/
│   ├── oui.tsv                     — OUI 厂商映射（53,964 条）
│   ├── man_id.tsv                  — PNO 厂商 ID 映射
│   ├── identify.tsv                — PROFINET DCP 设备识别提示
│   └── Man_ID_Table.xml            — PNO 原始厂商表（参考）
├── Interop/
│   ├── IpHlpApi.cs                 — IP Helper API P/Invoke（NotifyIpInterfaceChange）
│   └── PcapNative.cs               — wpcap.dll P/Invoke（pcap_open/send/loop）
├── Models/
│   ├── DcpDeviceEntry.cs           — PROFINET DCP 设备数据模型
│   ├── IpEntry.cs                  — IP-MAC 映射条目
│   ├── IpSource.cs                 — 来源类型枚举（ARP/IPv4/LLDP/Probe/DCP）
│   ├── MacAddress.cs               — MAC 地址值类型
│   └── MacRecord.cs                — MAC 聚合记录
└── Services/
    ├── ActiveArpScanner.cs         — ARP 请求/探测发送器（含冲突检测）
    ├── AdapterMonitor.cs           — 热插拔监控（Up/Down/移除/插入）
    ├── AdapterService.cs           — 物理网卡枚举
    ├── DcpService.cs                — PROFINET DCP Identify/Set/Get/复查
    ├── IpConfigService.cs           — IP/网关/DNS 配置（静态/DHCP）
    ├── MapperService.cs            — IP-MAC 映射表（MAC 主键，冲突检测）
    ├── NpcapManager.cs             — Npcap 检测与静默安装
    ├── OuiLookup.cs                — OUI 厂商查询（内嵌 + 外置 TSV）
    ├── PacketParser.cs             — ARP/RARP/IPv4/LLDP 报文解析
    ├── PassiveSniffer.cs           — 被动抓包线程（pcap_loop）
    ├── PnoVendorLookup.cs          — PNO 厂商 ID 查询
    ├── ReverseDnsService.cs        — 异步反向 DNS 解析
    └── ScanOrchestrator.cs         — 主动扫描四阶段状态机
```

## 主动扫描阶段

| 阶段 | 说明 |
|---|---|
| 1 | 扫描本网段（实际前缀），用本机真实 IP 发 ARP request |
| 1.5 | 若前缀 < /24，补扫本网段其余 /24 切片 |
| 2 | 从阶段 1/1.5 发现的 IP 衍生 /24 网段，扫描全局未扫过的段 |
| 3 | 读取 `segments.txt` 常用私有段，CIDR 去重后扫描；无文件回退内置 24 段 |

## PROFINET DCP

- **Identify**：连发 3 次多播 Identify 请求（FrameID 0xFEFE），收集应答约 1.5s
- **Set IP / Factory Reset**：差分比对，只下发变更块
- **复查确认**：收到 Set OK 后，每 1.5s 单播 Identify（最长 5 分钟），确认设备已应用新配置
- **FrameID**：Identify Req = 0xFEFE，Identify OK = 0xFEFF，Set = 0xFEFD
- **Block 对齐**：2 字节对齐（奇数长度 → +1 padding）

## 状态徽章

| 徽章 | 颜色 | 含义 |
|---|---|---|
| Idle | 灰 | 初始 / 模式切换后 |
| Scanning | 蓝 | 主动扫描运行中 |
| Listening | 蓝 | 被动监听运行中 |
| Identifying | 蓝 | DCP Identify 进行中 |
| Verifying | 蓝 | DCP 复查确认中 |
| Paused | 黄 | 任务暂停 |
| Completed | 绿 | 任务正常完成 |
| Stopped | 灰 | 任务被用户或拔线停止 |
| Error | 红 | 发生错误 |

## 配置文件

| 文件 | 位置 | 说明 |
|---|---|---|
| `oui.tsv` | exe 同目录（可选） | 覆盖内嵌 OUI 厂商数据 |
| `man_id.tsv` | exe 同目录（可选） | 覆盖内嵌 PNO 厂商数据 |
| `segments.txt` | exe 同目录 | 阶段 3 自定义网段列表（每行一个 CIDR） |

若未找到外置 TSV 文件，自动使用内嵌资源。

## 运行要求

- Windows 10/11 x64
- Npcap（首次运行未安装时自动提示安装）
- 管理员权限（原始套接字访问需要）
- .NET 8 运行时已内嵌（自包含）

## 许可证

MIT — 可自由使用、Fork 和修改。

## 联系方式

ming.tec@foxmail.com
