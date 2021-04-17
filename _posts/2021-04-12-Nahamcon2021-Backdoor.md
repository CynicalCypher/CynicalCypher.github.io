---
title:     "NahamCon 2021 - Backdoor"
tags: [NahamCon2021,Linux,Easy]
layout: post
categories: CTF-Writeups
---


# Introduction
"Backdoor" was the fourth challenge down the Orion path in NahamCon 2021. Please excuse the lack of a precise challenge description as I am making this some time after the CTF and don't remember what it was nor can I find it anywhere. The gist of it was that there was some firmware that the company was worried had a backdoor password in it and we are asked to find out if that was true. We are provided with a file, `firmware.tar` that we are to look into.

# Initial setup
We can extract the tar with `tar xvf firmware.tar` which gives us two files, a readme.md and firmware.bin. Let's see what is in the readme:

![](/images/CTFs/NahamCon2021/Backdoor/readme.png)

So we are not looking for an actual flag here, we are looking for a password which we will turn into a flag. Good to know. Now what do we do with the firmware file? I'll be honest this was my first attempt at dissecting firmware and I had only unlocked this challenge about 30 minutes before the CTF was ending so I didn't really have time to look into it, but since the firmware was a .bin file the first thing that came to my mind was binwalk. Let's run that and see what happens.

`binwalk -e firmware.bin`
![](/images/CTFs/NahamCon2021/Backdoor/extract.png)

Looks like we have some stuff to sift through. Navigating into the squashfs-root folder brings up what looks like a mostly normal linux system which was a pleasant surprise.

![](/images/CTFs/NahamCon2021/Backdoor/squashfs_dir.png)

# Digging in

Playing HackTheBox has conditioned me to check /home and /root first, but /home doesn't exist and /root is empty. Remembering that we are looking for a looking for a password I figured we should check to see if /etc/passwd and/or /etc/shadow existed. They did!

![](/images/CTFs/NahamCon2021/Backdoor/passwd_shadow.png)

So we see that an admin account exists but we don't have any passwords here. Continuing to look around /etc I noticed the OS release which I thought might hold some useful information on what we were dealing with.

![](/images/CTFs/NahamCon2021/Backdoor/os_release.png)

So this firmware is OpenWrt firmware, cool! While I have never personally used it I know OpenWrt is firmware used on routers. 

# Finding the hash

I started checking Google to see if I could find any other possible spots where OpenWrt might store passwords and came up short. Since I was rapidly running out of time I decided that looking through the files I had was a better idea then searching Google.

What I ended up doing was checking directories with `find .` and looking for files that looks interesting. Eventually I ended up in /etc/config and ran a `cat *` and saw the hash. Looking at these files now I missed something incredibly obvious that would have let me solve this in seconds. Let's look back at the root directory listing:

![](/images/CTFs/NahamCon2021/Backdoor/squashfs_dir.png)

Notice anything about the modified dates? Why was /etc the only one with a more recent modified date? Let's see what was modified in /etc:

![](/images/CTFs/NahamCon2021/Backdoor/etc_dir.png)

Well look at that, passwd/shadow were modified on the 4th as well as the config directory. Let's check what was modified in the config directory:

![](/images/CTFs/NahamCon2021/Backdoor/config_dir.png)

So two files were modified on the 4th, firewall and rpcd. Firewall is zero bytes so that probably isn't what we are looking for, but rpcd has some data. Let's see what it has:

![](/images/CTFs/NahamCon2021/Backdoor/rpcd.png)

There it is, a password hash.

# Cracking the hash

I figured since I had a hash and not a password that I would need to crack it. I've done enough hash cracking to know that this is mode 500 in hashcat but if you needed a hand to figure that out there are a few options. I generally pull up the `hashcat example_hashes` webpage and compare what I have to what is listed there. Another way is to use hashid which is built into kali. Hashid actually has a `-m` flag that will give you the hashcat mode to use to crack it which is super handy.

![](/images/CTFs/NahamCon2021/Backdoor/hashid.png)

Now it's off to our host machine to make use of the GPU and throw rockyou.txt at it. As stated above we can use hashmode 500, attack mode 0 for a dictionary attack, and specify the hash file and wordlist.

`hashcat.exe -a 0 -m 500 backdoor.txt rockyou.txt`

![](/images/CTFs/NahamCon2021/Backdoor/hashcat.png)

And after a whole two second wait we have our password which turns out to be `1212312121`

# The flag

All that's left is to follow the instructions in the readme file to turn this password into our flag.

`echo -n '1212312121' | md5sum`

That's it. Our flag is:
`flag{c3f3494b9ad07e1ae58c5442826fed29}`

Boom.


# References

- [example_hashes [hashcat wiki]](https://hashcat.net/wiki/doku.php?id=example_hashes)