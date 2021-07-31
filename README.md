# Sniffer

**Sniffer** is a tool to capture tcp/udp packages on Windows. It has been tested on Windows 10.

It supports:
- Configure Windows firewall automaticly.
- Capture packets individually on each network adapter.
- Save and read packets.

Dependency:
* You should install [Npcap 1.50](https://nmap.org/npcap) first.
* This project use SDK [WTL 10.0](https://www.nuget.org/packages/wtl)(MS-PL).


Flags:
* SYN: 建立连接
* FIN: 关闭连接
* ACK: 应答
* PSH: 应答有DATA
* RST: 连接重置
* URG: 有紧急数据
* CWR: 网络有阻塞

![avatar](/sniffer1.png)
