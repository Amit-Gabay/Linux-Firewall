# 🐧 Linux kernel stateful firewall 🧱

## Description

A stateful Linux firewall which is implemented as a kernel module.
Assisted by 3 userspace proxy servers:
* FTP
* SMTP
* HTTP

As part of the firewall's protection, I've implemented the following systems:
* IPS (Intrusion Prevention System) for blocking HTTP exploits to the vulnerability: Pie-Register 3.7.1.4 RCE
* DLP system (Data Prevention System) which inspects HTTP / SMTP traffic, detects C source code and prevent its leakage.

## Implementation

### Kernel Side

A kernel module which intercepts network traffic, inspects each packet and determine its verdict using the following guidelines:
In general case:
* checks in the rules table wheter the packet is allowed or not. The rules table works as an allow-list which means - each packet which doesn't match any valid rule, being dropped.
* Blocks any xmas packets.

If it's an TCP packet:
* Makes sure the packet is part of a valid TCP connection (by maintaining a TCP connections table, using TCP state machine).
* For HTTP / FTP / SMTP packets, redirects the packet to the corresponding userspace proxy server for deeper inspection and an appropriate verdict.

### Userspace Side

Consists of:
* Firewall control panel.
* SMTP, HTTP, FTP proxy servers.

Each proxy server above, inspects and determines whether to ACCEPT or DROP packets of its particular protocol.

## Usage

First, compile and install the kernel module:
```
$ cd ./module/
$ make						
$ insmod firewall.ko
```

Then, compile the firewall control panel:
```
$ cd ../user/				
$ make						
```

In order to load rules into the firewall's rules table:
```
$ ./firewall_control load_rules rules.txt
```

In order to run each proxy server (e.g. HTTP proxy):
```
$ cd ../http/
$ sudo python http_proxy.py
```

