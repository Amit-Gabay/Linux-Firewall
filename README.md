# Description

A stateful Linux firewall based on kernel module. consists of firewall kernel module aside to 3 userspace proxy servers (FTP, HTTP, SMTP).
In addition, I've implemented an IPS (Intrusion Prevetion System) for HTTP traffic as an protection to the Pie-Reigster 3.7.1.4 RCE vulnerability.
The firewall includes a DLP system (Data Leak Prevention) for HTTP / SMTP traffic, in order to detect and prevent leakage of C source code.


## Idea

Kernel side-    Added a few modifications in order to intercept SMTP traffic into the SMTP proxy.

Userspace side- In the userspace side, I've added a proxy server at "smtp/smtp_proxy.py", with a DLP (Data Leak Prevention) system;
		Added a DLP & IPS systems to the HTTP proxy also.


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

