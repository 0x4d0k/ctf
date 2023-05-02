---
layout: post
title: "HackMyVM - VideoClub"
date: 2022-04-02 15:47:00 +0100
categories: hmv
---

## Scan &Enumeration #nmap 

```
nmap -sV -sC -p- 192.168.1.82
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-02 21:33 WEST
Nmap scan report for 192.168.1.82
Host is up (0.00026s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 96:9f:0e:b8:03:40:88:96:8b:b1:bf:58:ac:ff:d5:3a (RSA)
|   256 f2:38:ff:38:44:1b:7a:5d:3d:0c:bb:cd:c3:93:55:45 (ECDSA)
|_  256 35:c2:e8:90:61:0d:19:7b:01:f0:b5:2a:d1:c6:27:ad (ED25519)
3377/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: MARGARITA VIDEO-CLUB
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.24 seconds
```

### Gobuster

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.82:3377 -x php,txt,html,zip
```

```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.82:3377
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html,zip
[+] Timeout:                 10s
===============================================================
2022/04/02 21:34:12 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 320] [--> http://192.168.1.82:3377/images/]
/index.html           (Status: 200) [Size: 3318]                                      
/videos               (Status: 301) [Size: 320] [--> http://192.168.1.82:3377/videos/]
/manual               (Status: 301) [Size: 320] [--> http://192.168.1.82:3377/manual/]
/robots.txt           (Status: 200) [Size: 4268]                                      
/server-status        (Status: 403) [Size: 279]                                       
                                                                                      
===============================================================
2022/04/02 21:39:47 Finished
===============================================================
```

http://192.168.1.82:3377/robots.txt

```
                 _\@)_       ___
                  /`\      .' -,'-.__,@ Welcome to the video club Margarita
                 /        |     `).-'
               _/       _\V^V^V^V/_
              | /\     .=// ^.^ \\=.
              /\ /     .'/| ._. |\'.
             / /-`.       _\___/_
              |/\/\   _@->`   _  `<-@._
                \  \.'  @-'`\( `'-,@   '-.
                 \      ,    @    , _.-   `\
                  \   .'|    :    |` /'. _.'
                   `"`   \   :    / /`\_|  @
                   @_  _.'`""""""`'-\_\.--;`
                   `-.`      /,     `, .-'
                   _.@--; .-'| '. ;-._;@
             jgs .'     @' _.'.  `@  \
                |     _.-'`    '-.    \
                 '-._  `-._n_     )   |
                     `'-._ ) `-,.'   /
                          u-'--;`@ .'
                               |  /
                              ,\ /,
                              )\.'/
                             /   (
                             \_.. '._.@ ShellDredd Society
                                 `-.-'


                                  ,;;;;;;,
                                ,;;;'""`;;\
                              ,;;;/  .'`',;\
                            ,;;;;/   |    \|_
                           /;;;;;    \    / .\
                         ,;;;;;;|     '.  \/_/
                        /;;;;;;;|       \
             _,.---._  /;;;;;;;;|        ;   _.---.,_
           .;;/      `.;;;;;;;;;|         ;'      \;;,
         .;;;/         `;;;;;;;;;.._    .'         \;;;.
        /;;;;|          _;-"`       `"-;_          |;;;;\
       |;;;;;|.---.   .'  __.-"```"-.__  '.   .---.|;;;;;|
       |;;;;;|     `\/  .'/__\     /__\'.  \/`     |;;;;;|
       |;;;;;|       |_/ //  \\   //  \\ \_|       |;;;;;|
       |;;;;;|       |/ |/    || ||    \| \|       |;;;;;|
        \;;;;|    __ || _  .-.\| |/.-.  _ || __    |;;;;/
         \jgs|   / _\|/ = /_o_\   /_o_\ = \|/_ \   |;;;/
          \;;/   |`.-     `   `   `   `     -.`|   \;;/
         _|;'    \ |    _     _   _     _    | /    ';|_
        / .\      \\_  ( '--'(     )'--' )  _//      /. \
        \/_/       \_/|  /_   |   |   _\  |\_/       \_\/
                      | /|\\  \   /  //|\ |
                      |  | \'._'-'_.'/ |  |
                      |  ;  '-.```.-'  ;  |
                      |   \    ```    /   |
    __                ;    '.-"""""-.'    ;                __
   /\ \_         __..--\     `-----'     /--..__         _/ /\
   \_'/\`''---''`..;;;;.'.__,       ,__.',;;;;..`''---''`/\'_/
        '-.__'';;;;;;;;;;;,,'._   _.',,;;;;;;;;;;;''__.-'
             ``''--; ;;;;;;;;..`"`..;;;;;;;; ;--''``   _
        .-.       /,;;;;;;;';;;;;;;;;';;;;;;;,\    _.-' `\
      .'  /_     /,;;;;;;'/| ;;;;;;; |\';;;;;;,\  `\     '-'|
     /      )   /,;;;;;',' | ;;;;;;; | ',';;;;;,\   \   .'-./
     `'-..-'   /,;;;;','   | ;;;;;;; |   ',';;;;,\   `"`
              | ;;;','     | ;;;;;;; |  ,  ', ;;;'|
             _\__.-'  .-.  ; ;;;;;;; ;  |'-. '-.__/_
            / .\     (   )  \';;;;;'/   |   |    /. \
            \/_/   (`     `) \';;;'/    '-._|    \_\/
                    '-/ \-'   '._.'         `
                      """      /.`\
                               \|_/

####################################################################################################################
EJ5do3xtqTuyVTWyp3DtMzyfoKZtLJ5xVUAypzyyplOiMvO0nTHtqzyxMJ8tL2k1LvOgLKWaLKWcqTRfVUEbMFObnJExMJ4tp2yxMFOiMvOwnJ5yoJRh
####################################################################################################################

...



â•¦ â•¦â•”â•â•—â•”â•â•—â•¦â•”â•â•”â•¦â•—â•¦ â•¦â•¦  â•¦â•”â•¦â•—
â• â•â•£â• â•â•£â•‘  â• â•©â•—â•‘â•‘â•‘â•šâ•¦â•â•šâ•—â•”â•â•‘â•‘â•‘
â•© â•©â•© â•©â•šâ•â•â•© â•©â•© â•© â•©  â•šâ• â•© â•©
  list-defaulters.txt
```

http://192.168.1.82:3377/list-defaulters.txt

```
   ||====================================================================||
   ||//$\\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\//$\\||
   ||(100)=============== | HAPPY BIRTHDAY HACKMYVM |================(100)||
   ||\\$//        ~         '------========--------'                \\$//||
   ||<< /        / \              // ____ \\                         \ >>||
   ||>>|  HMV   // \\            // ///..) \\         L38036133B   12 |<<||
   ||<<|        \\ //           || <||  >\  ||                        |>>||
   ||>>|         \ /            ||  $$ --/  ||      One Hundred VM    |<<||
||====================================================================||>||
||//$\\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\//$\\||<||
||(100)=================| HACK ANIVERSARY FAMILY |================(100)||>||
||\\$//        ~         '------========--------'                \\$//||\||
||<< /        / \              // ____ \\                         \ >>||)||
||>>|  100   // \\            // ///..) \\         L38036133B   12 |<<||/||
||<<|        \\ //           || <||  >\  ||                        |>>||=||
||>>|         \ /            ||  $$ --/  ||        One Hundred     |<<||
||<<|      HACKMYVM          *\\  |\_/  //* series                 |>>||
||>>|                         *\\/___\_//* 2020-2021               |<<||
||<<\                    _________/SML\___________                 />>||
||//$\                 ~|UNITED STATES OF CTF GAME|~              /$\\||
||(100)================ THE POWER OF THE COMMUNITY ==============(100)||
||\\$//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\\$//||
||====================================================================||

k3v1n
sn4k3
d4t4s3c
g4t3s
st4llm4n
t1m
exif
tool
n0n4m3
sofia
lacashita
c4r4c0n0
sml
a1t0rmenta
frodo
f1ynn
nolose
r1tm4tica
l0w
steg
hide
fresh
neo
aquaman
w0nderw0m4n


### POSTDATA ###

THANKS FOR THE PLATFORM AND THE MACHINES MY DEAR SML
THANKS TO ALL CREATORS FOR THE CONTINUOUS FUN, LEARNING AND PASSION OPENLY SHARED.
GOOD H4CKTING
```

