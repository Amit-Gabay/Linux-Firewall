# 🐧 Linux kernel stateful firewall 🧱

## Description

A stateful Linux network firewall which is implemented as a kernel module.
Performs DPI (Deep Packet Inspection).
Assisted by 3 userspace proxy servers:
* FTP
* SMTP
* HTTP

As part of the firewall's protection, I've implemented the following systems:
* IPS 🔎 (Intrusion Prevention System) for blocking HTTP exploits to the vulnerability: Pie-Register 3.7.1.4 RCE.
* DLP 💧 (Data Leak Prevention) system which inspects HTTP / SMTP traffic, detects C source code and prevent its leakage.

## Implementation

### Kernel Side

A kernel module which intercepts network traffic, inspects each packet and determine its verdict using the following guidelines:

In general case:
* Checks in the rules table whether the packet is allowed or not. The rules table works as an allow-list which means - each packet which doesn't match any valid rule, being dropped.
* Blocks any xmas packets 🎅🏽.

For TCP packets:
* Makes sure the packet is part of a valid TCP connection (by maintaining a TCP connections table, using TCP state machine).
* For HTTP / FTP / SMTP packets, redirects the packet to the corresponding userspace proxy server for deeper inspection and an appropriate verdict.

### Userspace Side

Consists of:
* Firewall control panel.
* SMTP, HTTP, FTP proxy servers.

Each of the proxy servers above, inspects and determines whether to ACCEPT or DROP packets of its particular protocol.

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
$ ./firewall_control load_rules <rules-file>
```

In order to run each proxy server (e.g. HTTP proxy):
```
$ cd ../http/
$ sudo python http_proxy.py
```

## Rules file format

Each packet is being checked against the rules table by rules arrangement in the rules file,
from top to bottom - which means higher rules are more generic.
The rules table of the firewall is a .txt file, when each line is in the following format:
```
<rule name> <direction> <src subnet> <dst subnet> <protocol> <src ports> <dst ports> <ACK bit> <accept / drop>
```

Rules file example:
```
loopback any 127.0.0.1/8 127.0.0.1/8 any any any any accept
GW_attack any any 10.0.2.15/32 any any any any drop
spoof1 in 10.0.1.1/24 any any any any any drop
spoof2 out 10.0.2.2/24 any any any any any drop
telnet1 out 10.0.1.1/24 any TCP >1023 23 any accept
telnet2 in any 10.0.1.1/24 TCP 23 >1023 yes accept
default any any any any any any any drop
```
