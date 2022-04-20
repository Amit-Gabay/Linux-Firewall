# Description

A stateful Linux firewall based on kernel module. consists of firewall kernel module aside to 3 userspace proxy servers (FTP, HTTP, SMTP).
In addition, I've implemented an IPS (Intrusion Prevetion System) for HTTP traffic as an protection to the Pie-Reigster 3.7.1.4 RCE vulnerability.
The firewall includes a DLP system (Data Leak Prevention) for HTTP / SMTP traffic, in order to detect and prevent leakage of C source code.


## Idea

### Kernel Side

A kernel module which intercepts network traffic, inspects each packet and determine its verdict using the following guidelines:
* Generally, checks in the rules table wheter the packet is allowed or not. The rules table works as an allow-list which means - each packet which doesn't match any valid rule, being dropped.
* If it's an TCP packet:
** Firstly, makes sure the packet is part of a valid TCP connection (by maintaining a TCP connections table, using TCP state machine).
** For HTTP / FTP / SMTP packets, redirects the packet to the corresponding userspace proxy server for deeper inspection and an appropriate verdict.
* Blocks any xmas packets.

### Userspace side


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

