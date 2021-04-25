---
title:     "How to overly complicate your homelab pentesting setup"
tags: [Homelab,Cisco,pfSense,VMware,FreeNAS]
layout: post
categories: Homelab
---

# Introduction

Grab your favorite beverage and get comfortable because we are going on a journey. On this journey I will show you how I overcomplicated my homelab/pentesting setup to segregate it from my normal network while still retaining the functionality I wanted. I had a few reasons for wanting to do this. My main concern was that since I was getting into information security I might at some point run into some malicious files. At the moment I'm mostly focusing on penetration testing however if I ever dive into malware analysis (or even exploited myself by mistake... we are learning after all) the idea of accidentally cryptolocking my NAS, or otherwise deleting all of my data did not sound pleasant. Of course I have snapshots turned on so rolling back all of my data should be simple, but I'd rather not have to find out. Another reason was for fun. Some people would probably consider this their version of hell but I am obviously not one of those people. It also ended up being a great learning experience. 

My homelab probably rivals most small/medium business setups but hey we all need a hobby... The good news is that with the hardware and software I'm running being geared more towards enterprise use I was able to make everything work in the end. Here is a quick diagram of the relevant parts:

![](/images/homelab/complicated/network_diagram.png)

## Goals

The more I dug into what I wanted to do the more complicated it became. I wanted to create a new VLAN on my network specifically for my lab environment. The first issue is that I run Kali in a virtual machine on my main desktop PC. How do you have a virtual machine on one network and your host machine on a different network? I also needed to have some sort of DHCP server setup on this new VLAN for Vulnhub and other test machines but I did not want those machines to have Internet access or access to the rest of my network. On the other hand my Kali machine needed Internet access.

What about access to my NAS? I like running Kali in a VM because I have the ability to take snapshots (not that I ever do... *makes note to start*) so if something goes horribly wrong I can just go back to a previous snapshot. Realistically I end up starting fresh with the latest image on Offensive Security but that's besides the point. When I am working on a machine on HackTheBox I have a folder created that has all of my scan information, exploits, and any other files relevant to the box. Instead of keeping these in /root/Documents/boxnamehere I wanted to keep them on my NAS, that way if I ever needed to roll back a snapshot or start with a fresh image I wouldn't be losing all of my work. 

I also have a laptop for when I feel like doing some hacking from the couch. If all of my files are on a VM on my main PC I wouldn't be able to access them from my laptop. One last reason is to keep larger files there. Rockyou.txt is only 133MB which is no big deal to keep on the virtual machine. The crackstation wordlist is 14.6GB which starts chewing up space quickly. And say I wanted a copy of the old 1.4 billion breached usernames/passwords that is 40+GB... yeah I don't need that on a virtual machine.

As I already mentioned though I did not want Kali accessing my main storage dataset in case something went wrong. That means I needed a new dataset with specific permissions for my Kali machine.

So with all of that said I had a few goals I was trying to accomplish:
- Create a completely new VLAN segregated from the rest of my network
- Create a brand new storage dataset only accessible to the new VLAN
- Allow my Kali machine access to the Internet and new storage dataset
- Block any other vulnerable / test machines from accessing the Internet 

## Before we start

A quick note before we begin this journey. When I decided to do this write-up I could have looked at what I had already setup however I decided to recreate this environment completely from scratch. I figured I might miss some things if I didn't do this fresh from start to end. To make sure everything was new I decided to use an old spare PC to install VMware on. I don't think there are any continuity issues with my screenshots but I was bouncing around between two computers while doing this so if you come across any that would be why. 

# Networking setup

First things first we are going to have to create a new VLAN for this environment. For me that means I have a switch and pfSense to configure. We'll start with pfSense.

## pfSense

Growing up my family always had the normal consumer routers. I'm pretty sure that old Linksys WRT54G is kicking around somewhere now that I think about it... Anyway as I'm sure everyone else did as well we went through quite a few of them over the years. It wasn't always because we wanted an upgrade, a number of them actually failed. "Let me restart the router" became a saying that happened much too frequently. I knew that when the choice became mine I wanted something more stable. I also knew a server rack was in my future so I figured a rack-mount server was the way to go. During my research I kept seeing the Dell R210 II and pfSense combo pop up and that is ultimately where I ended up. Since the router is really a core function and not something I ever want going down unless I am updating it, I did not want to mess with virtualizing it. pfSense was the first OS I tried and I saw no reason to switch however I hear OPNsense is pretty good as well. Perhaps one day I'll test it out.

### Creating the interface / VLAN

We start by selecting `Interfaces > Assignments` at the top of the screen. Now we can click on `VLANs` and select add at the bottom.

![](/images/homelab/complicated/add_vlan.png)

To start we must select the `Parent Interface` which is cxgb0 for me. I'm going to create VLAN 99 so I'll set that as the `VLAN Tag`. I'm not using any prioritization so I'll leave `VLAN Priority` alone. Now we just need a nice `Description`. Let's call this `TheIsland` since this VLAN will be alone by itself. As you can see in my previous screenshot, my official VLAN is called 'Lab' because I'm boring and it's easy to tell what it is by looking at it. Click save and we should see this VLAN in our list.

![](/images/homelab/complicated/vlan_options.png)

Now that we have the VLAN created we must create the interface for this VLAN. Going back to the `Interface Assignments` page we see "Available network ports:" and an add button. Here we select the interface where this new VLAN will reside which should match the parent interface we selected before. After pressing add a new optional interface will be created. Once this optional interface is created it is important that we select the `Network port` and make it the new VLAN we just created.

![](/images/homelab/complicated/network_port.png)

Once that is done we can click on the interface name (OPT8 in my case) and set some more options. Obviously we want to check `Enable interface` otherwise this interface will be useless. We can set the `Description` to "TheIsland" to match our VLAN name. Next we will set the `IPv4 Configuration Type` to "Static IPv4". This opens up the `Static IPv4 Configuration` options below. My IP address scheme is 172.30.VLAN.0/24 so I'm going to set this as "172.30.99.1 /24". While a /24 is complete overkill I'm lazy and there really is no reason not to do it. 

![](/images/homelab/complicated/opt8_options.png)

Click save and a message will pop up saying that the configuration has been changed and that the changes need to be applied. Click apply. Now that we are done creating the VLAN and setting up the interface we can move on to setting up the DHCP server.

### DHCP server

Time to get the DHCP server going. This will make life much easier when it comes to bringing up vulnerable targets such as Vulnhub machines, or if we wanted to do something like build an active directory lab. DHCP can be setup under `Services > DHCP Server` and then selecting the appropriate VLAN. Check `Enable` and now we need to specify a range. I like to leave a few IP addresses open in the beginning of the network, but since this is a /24 let's give it a nice big pool. I'm going with `172.30.99.20 - 172.30.99.250`. I'm also going to specify my two DNS servers below.

![](/images/homelab/complicated/dhcp_server.png)

Click save and we are good to go. Since we will need firewall rules to allow our Kali host access to where it needs to go I'm going to assign that IP statically when we get into Kali. Speaking of firewall rules, let's get those in place.

### Firewall rules

Firewall rules can be accessed from `Firewall > Rules` (shocking, I know) and again selecting the appropriate VLAN. pfSense has a default deny rule so technically we will need to add the rules for traffic we want to allow. This issue here is that as far as I know you need a 'allow Kali to any' rule to allow Internet access. We could just add allow rules to specific ports (80,443,etc) but it is much easier to just give it access to everything and have one block rule blocking it from the rest of our network. Conveniently we can block the whole `172.30.99.0/12` range and still have access to any other virtual machines we start on this VLAN since they will be on the same VLAN and can talk directly without hitting the firewall.

At this point I'm going to choose `172.30.99.5` to use for our Kali machine and make the rules accordingly. We are going to create rules to allow access to our DNS severs (port 53 tcp/udp), access to our storage, block access to the rest of our network, and allow Kali access to everything else. When everything is done it should look like this:

![](/images/homelab/complicated/firewall_rules.png)

Make sure to click save and apply when finished. I could have made the block rule specific to the Kali machine since that will be the only one with an allow to any, but I don't see the harm in making the source any since I don't want anything on this VLAN touching the rest of my network. It is also very important to note that when traffic is being routed it will start at the top of this list and work it's way down until a match is found. That means the order of these rules is very important. If the allow to any was at the top the block rule would never be reached. Conversely if the block rule was at the top we wouldn't have access to anything we made rules for since everything would match the block rule.

## Cisco setup

Now it's time to configure the Cisco switch. I'm obviously using a trunk since all of my VLANs are on the same interface in pfSense so I'll need to add this VLAN to the trunk on the Cisco end. Once we are logged into the switch we can create and configure the VLAN with the following:

```
en
conf t
vlan 99
name TheIsland
exit
interface vlan 99
ip address 172.30.99.2 255.255.255.0
exit
exit
```
With a `show vlan` we can make sure that the VLAN was actually created.

![](/images/homelab/complicated/create_vlan.png)

Now we have to add the VLAN to the trunk.

```
conf t
interface tenGigabitEthernet 1/1/1
switchport trunk allowed vlan add 99
exit
exit
```
The "add" is very important to have in the last command, otherwise you end up overwriting the already set VLANs. I used CBTNuggets when studying for my CCNA and I remember Jeremy Cioara giving an example of taking down a network from forgetting "add" in that command. That lesson stuck with me and I haven't forgotten it yet and hopefully I wont ever.

We can do a `show run | sec 1/1/1` which will pull out the section with 1/1/1 (which is my uplink to pfSense) from the running config to make sure that the VLAN is in place.

![](/images/homelab/complicated/int111.png)

Looks good. Now at some point our Kali machine needs to be connected to this switch, so let's configure a port while we are here.

```
conf t
interface gigabitEthernet 1/0/11
switchport mode access
switchport access vlan 99
spanning-tree portfast
exit
exit
```
That will set the port as an access port on VLAN 99 and 'spanning-tree portfast' will bring the port online faster. There will only be one machine connected to this port so no need to worry about loops. We can run the same command as before (changing the section to reflect our new interface) to see how our config looks.

![](/images/homelab/complicated/int1011.png)

My 3750X is a PoE switch so I set all of the ports with "power inline never" which is why that other line is there. I don't accidentally need power going to devices not looking for it so I set power options per port when I need to. Otherwise we should be good to go, we just have to `wr` or write memory to save the config.


## Host machine setup

It's time to setup our host machine. I asked a question in the introduction about how you have have a host machine on one network and a virtual machine on another network which I am finally going to answer, but first a note about software. Generally I run VMware Workstation Player however I have used the trial of Workstation Pro. I mention this because it will be important soon. As far as hardware, the last few computers I have built have all had dual NICs on the motherboards and it's time to put that second NIC to use. This isn't as easy as plugging in the cable though. Once the cable is plugged in Windows pulls an IP from our DHCP server (hey that's working!) and adds another route to it's routing table.

![](/images/homelab/complicated/windows_route.png)

The problem is that Windows sees these connections as equals, however our new connection isn't allowed to go anywhere. So sometimes our traffic tries to go to our new VLAN and just dies which isn't great. Thankfully VMware installs bridge drivers so we can actually just disable IPv4 and IPv6 in Windows for this adapter. If we go into the adapter settings, find the proper adapter for this new connection, right click and go to properties, all we need to do is uncheck the boxes for IPv4 and IPv6.

![](/images/homelab/complicated/disable_ip.png)

With that out of the way Windows removes the route and we never have to worry about it again! Next we have to setup VMware to use this connection. I brought up Workstation Pro earlier because for some reason the virtual network editor is not included with Workstation Player. Now that isn't the end of the world as we can still have our virtual machine network settings bridged to our new adapter, however I prefer to use the virtual network editor to create a new VMnet and have that set to bridge to the adapter. This also allows me to delete the two network adapters that VMware adds for NAT and host only. ***NOTE*** If you delete those adapters you will lose the ability to use NAT and host only!

To do this easily in VMware Player, edit the virtual machine settings, click `Network Adapter`, click `bridged`, then select the adapter you want to bridge to. This would be the adapter that goes to our new VLAN and has IPv4/IPv6 disabled. This will need to be done for every virtual machine we run.

![](/images/homelab/complicated/player_bridged.png)

To do this with the virtual network editor you either need Workstation Pro installed, or you just need to drop a copy of `vmnetcfg` into your VMware Player folder. In virtual network editor we need to click `Change Settings` to allow administrator access. From here I like to delete all of the existing networks and start fresh. Note what I said above about losing some functionality when doing this. Next we can click `Add Network` and select a VMnet. I like to match this to the VLAN so in this case I'll use '9' since 99 isn't an option. Just like before set the mode to bridged and select the proper adapter.

![](/images/homelab/complicated/vmnetcfg_bridged.png)

Now just like before we still need to set the Network Adapter on every virtual machine we run, but instead of choosing bridged we chose our custom VMnet.

![](/images/homelab/complicated/custom_vmnet.png)

### Kali setup

As much as I love the command line I'm going to set our static IP in the GUI. At the top of the screen right click on the network icon and click `edit connections`. Select the connection (Wired connection 1 in my case) and click the edit button at the bottom.

![](/images/homelab/complicated/network_connections.png)

Now click on `IPv4 Settings`. Change the method to manual and click add. We need to fill in the IP address, Netmask, and Gateway. After that is done we can add our DNS servers at the bottom. 

![](/images/homelab/complicated/network_config.png)

Hit save when finished. At this point we should have a fully functional Kali machine, on it's own VLAN, that is not able to access anything on our network except our DNS servers and our storage server. Phew. On to the final piece.

# Storage setup

I spent quite a bit of time trying to figure out what I wanted to do for a NAS. The only thing I knew was that I had issues with bit rot in the past and that I wanted something with ZFS to combat that. FreeNAS (now TrueNAS) definitely isn't perfect but it works for me. There are many options out there and no one solution is best for everyone. If you are trying to figure out what to run, figure out what features you are looking for and see what fits best.

## Adding the kali user

The first thing we are going to do is create the 'kali' user. Since the default account for Kali is 'kali' we need to replicate that here. Click on `Accounts > Users` and click add in the top right. Enter the Full Name / Username of 'kali' and enter a password for the kali account. We'll let this create a new group as well. Click save.

![](/images/homelab/complicated/kali_user.png)

We see that the user has been created. If we click on groups we see that the 'kali' group was also created and we can check the members to see that the user 'kali' was automatically added.

## Creating the dataset and setting permissions

Now we need to make a new dataset. Click on `storage > pools` which will bring up the list of pools. Click the three dots on the right and click `Add Dataset`.

![](/images/homelab/complicated/create_dataset.png)

I'm going to give it the name of `Island`. All of the other options are fine so click save. We see that a dataset has been created but now we need to edit the permissions. Click the three dots on the same line as the dataset and click `Edit Permissions`.

![](/images/homelab/complicated/edit_permissions.png)

We need to change the owner and group to `kali`. Make sure to check `Apply User` and `Apply Group` otherwise the permissions wont be saved. Once that is done click save.

![](/images/homelab/complicated/kali_permissions.png)

Finally we need to share this dataset. Click on `Sharing > Unix Shares (NFS)` and click add in the top right. Navigate to the new dataset, make sure `Enabled` is checked, and click save.

![](/images/homelab/complicated/storage_share.png)

## Configuring storage in Kali

First things first we will need `nfs-common` installed. I believe this comes with Kali now but if not grab it with `sudo apt install nfs-common`. Next we need a place to mount our storage. I like to keep this in the base so I'll create the folder `/storage` by doing the following:

```
sudo mkdir /storage
sudo chown kali:kali /storage
```
It is important kali owns this folder or we will not be able to write to it. Now we can add a line in `fstab` to make this storage mount automatically on startup.

`sudo vi /etc/fstab`

and add the following line at the bottom:

`172.30.15.15:/mnt/Shelf1/Island       /storage 	nfs 	defaults	0	0`

Note that the path is case sensitive. Now we can mount it with `sudo mount -a` but we aren't quite done yet. Running a `ls -la` shows us that the owner and group of this directory are '1004', not kali. 

![](/images/homelab/complicated/uid1004.png)

If you had good eyes you would have seen that when I created the user/group in FreeNAS the 'User ID' was 1004. In kali the default UID is 1000. We can fix this by modifying the UID and GID in Kali. The problem is that we cannot do this while logged in as kali, so let's become root with `sudo su` and set a password with `passwd`. Once that is done logout and log back in as root. You may need to reboot if you get an error about a process running as kali.

Once we are logged int with root we can change the GID and UID with the following commands:
```
usermod -u 1004 kali
groupmod -g 1004 kali
```

If you are actually following along make sure to change the UID/GID to whatever yours is on FreeNAS. Log out one more time and login as kali. Running a `ls -la /` should show /storage as being owned by kali:kali now. Let's see if we can write to it.

```
echo 'Hello World!' > /storage/test
cat /storage/test
```

![](/images/homelab/complicated/hello_world.png)

Success! 

Just to make sure we aren't writing on our local system, let's check FreeNAS.

![](/images/homelab/complicated/freenas_helloworld.png)

There you have it. We're finally done... or are we....

## Root squash

If you happen to look at any of my write-ups you will notice that I like to run as root. I know this isn't best practice but I do it anyway. The problem is that if we try to write to our newly mounted storage as root we get permission denied. This is because of something called 'root squash', where requests from root are remapped to look like the 'nobody' user who obviously doesn't have permissions to write to the storage. Thankfully there is a really easy fix for this in FreeNAS called maproot.

Back in FreeNAS we can go to `Sharing > Unix Shares (NFS)` and click on the three dots on the right side of our Island share and click edit. This should look familiar as we've been here before, but this time we are going to click on `ADVANCED MODE`. Now we can set a maproot user and a maproot group. This will make it so if a root user tries to access this share, it will change the permissions to match the user and group that we specify here. In our case, we want to make both of these `kali`. Do that and click save.

![](/images/homelab/complicated/maproot.png)

Let's head over to our Kali machine and see what happens.

![](/images/homelab/complicated/post_maproot.png)

=)

# Conclusion

You can get off 'Mr. Bones Wild Ride' now. We've finally made it to the end. It took me many hours to figure this out when I originally set it up, particularly the storage permissions and dealing with root squash. Recreating it was thankfully a much easier experience. Hopefully if you've stumbled across this that there is something in here that helps you out.