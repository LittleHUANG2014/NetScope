# NetScope

English | [中文](README.md)

A portable Windows network discovery tool for industrial control systems (ICS) and PROFINET environments.

## Features

- **Active ARP Scan** — Multi-stage subnet scanning with CIDR-based deduplication, ARP Probe for free-address detection, and sender-spoof conflict resolution
- **Passive Listen** — Continuous capture of ARP, RARP, IPv4, and LLDP traffic to build IP-MAC mapping tables
- **PROFINET DCP** — Discover, configure, and factory-reset PROFINET devices via DCP Identify / Set / Get protocols
- **Device Access** — On-the-fly IP reconfiguration (join device subnet, manual set/restore) without leaving the tool
- **Hot-Plug Monitoring** — Real-time detection of adapter up/down/remove/insert via `NotifyIpInterfaceChange` (no polling)
- **Vendor Identification** — OUI (MA-L/MA-M/MA-S) and PNO Manufacturer ID lookup with external TSV override support
- **System Tray** — Minimize to tray; auto-restore on link-up events

## Screenshots

| Main Window | DCP Device Dialog |
|---|---|
| ![Main Window](src/NetScope/icon.svg) | DCP Set IP / Factory Reset dialog |

## Quick Start

1. Download `NetScope.exe` from [Releases](../../releases)
2. Right-click → **Run as administrator**
3. If Npcap is not installed, the tool will prompt you to install it first
4. Select a physical adapter from the dropdown
5. Choose **Passive** (default) or **Active** mode
6. Click **Start**

## Build from Source

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (Windows x64)
- [Npcap SDK](https://npcap.com/) (wpcap.dll must be available at build time)

### Build

```bash
cd src/NetScope
dotnet publish -c Release -r win-x64 --self-contained true -o publish
```

The output `NetScope.exe` is a single-file self-contained executable (~143 MB) that can be copied to any Windows x64 machine without installation.

## Architecture

```
src/NetScope/
├── App.xaml / App.xaml.cs           — WPF application entry
├── MainWindow.xaml / .xaml.cs       — UI, tray, badge/status management
├── DCPDeviceDialog.cs               — PROFINET DCP device operation dialog
├── NetScope.csproj                  — Project file (.NET 8, WPF, self-contained)
├── app.manifest                    — Requires administrator privilege
├── icon.ico / icon.svg              — Application icon
├── segments.txt                    — Custom subnet list for Stage 3 scan
├── Assets/
│   └── npcap-installer.exe          — Bundled Npcap installer
├── data/
│   ├── oui.tsv                     — OUI vendor mapping (53,964 entries)
│   ├── man_id.tsv                  — PNO manufacturer ID mapping
│   ├── identify.tsv                — PROFINET DCP device identification hints
│   └── Man_ID_Table.xml            — Raw PNO manufacturer table (reference)
├── Interop/
│   ├── IpHlpApi.cs                 — P/Invoke for IP Helper API (NotifyIpInterfaceChange)
│   └── PcapNative.cs               — P/Invoke for wpcap.dll (pcap_open/send/loop)
├── Models/
│   ├── DcpDeviceEntry.cs           — PROFINET DCP device data model
│   ├── IpEntry.cs                  — IP-MAC mapping entry
│   ├── IpSource.cs                 — Source type enum (ARP/IPv4/LLDP/Probe/DCP)
│   ├── MacAddress.cs               — MAC address value type
│   └── MacRecord.cs                — MAC aggregation record
└── Services/
    ├── ActiveArpScanner.cs         — ARP request/probe sender with conflict detection
    ├── AdapterMonitor.cs           — Hot-plug monitoring (up/down/remove/insert)
    ├── AdapterService.cs           — Physical adapter enumeration
    ├── DcpService.cs                — PROFINET DCP Identify/Set/Get/Re-verify
    ├── IpConfigService.cs           — IP/gateway/DNS configuration (static/DHCP)
    ├── MapperService.cs            — IP-MAC mapping table (MAC-keyed, conflict detection)
    ├── NpcapManager.cs             — Npcap detection and silent install
    ├── OuiLookup.cs                — OUI vendor lookup (embedded + external TSV)
    ├── PacketParser.cs             — ARP/RARP/IPv4/LLDP packet parser
    ├── PassiveSniffer.cs           — Passive capture thread (pcap_loop)
    ├── PnoVendorLookup.cs          — PNO manufacturer ID lookup
    ├── ReverseDnsService.cs        — Async reverse DNS resolver
    └── ScanOrchestrator.cs         — Active scan 4-stage state machine
```

## Scan Stages (Active Mode)

| Stage | Description |
|---|---|
| 1 | Scan the local subnet (actual prefix) using real IP as sender |
| 1.5 | If prefix < /24, sweep remaining /24 slices of the local subnet |
| 2 | Discover new /24 segments from Stage 1/1.5 results; scan unseen segments |
| 3 | Read `segments.txt` for common private ranges; CIDR-deduplicate against global scanned set |

## PROFINET DCP

- **Identify**: Send 3 multicast Identify requests (FrameID 0xFEFE), collect responses for ~1.5s
- **Set IP / Factory Reset**: Differential block comparison; only changed blocks are sent
- **Re-verification**: After Set OK, periodic unicast Identify (every 1.5s, up to 5 min) confirms the device applied changes
- **Frame IDs**: Identify Req = 0xFEFE, Identify OK = 0xFEFF, Set = 0xFEFD
- **Block alignment**: 2-byte aligned (odd length → +1 padding)

## Status Badges

| Badge | Color | Meaning |
|---|---|---|
| Idle | Gray | Initial / after mode switch |
| Scanning | Blue | Active scan running |
| Listening | Blue | Passive listen running |
| Identifying | Blue | DCP Identify in progress |
| Verifying | Blue | DCP re-verification in progress |
| Paused | Yellow | Task paused |
| Completed | Green | Task finished successfully |
| Stopped | Gray | Task stopped by user or link-down |
| Error | Red | Error occurred |

## Configuration Files

| File | Location | Description |
|---|---|---|
| `oui.tsv` | exe directory (optional) | Override embedded OUI vendor data |
| `man_id.tsv` | exe directory (optional) | Override embedded PNO manufacturer data |
| `segments.txt` | exe directory | Custom subnet list for Stage 3 (one CIDR per line) |

If external TSV files are not found, embedded resources are used automatically.

## Requirements

- Windows 10/11 x64
- Npcap (auto-installed on first run if missing)
- Administrator privileges (required for raw socket access)
- .NET 8 runtime is bundled (self-contained)

## License

MIT — free to use, fork, and modify.

## Contact

ming.tec@foxmail.com
