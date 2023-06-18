---
title:     "NahamCon 2023 - Warmups"
tags: [NahamCon2023,CTF,Easy]
layout: post
categories: CTF-Writeups
---


# Introduction
NahamCon2023 time! Here are write-ups for the warmups, sans the flags you needed to grab from the discord channels. Enjoy!

# Read The Rules
```
Author: @JohnHammond#6971
Please follow the rules for this CTF!
```
For those new to CTFs, there is usually an easy flag to start off with to get you into the correct mindset. This would be that flag. The rules page does show the flag format we are looking for however there is no flag visible directly on this page. Looking at the source code of the page however we can find the first flag in a comment!

![](/images/CTFs/NahamCon2023/Warmups/read_the_rules_flag.png)


# Ninety One
```
Author: @JohnHammond#6971
I found some more random gibberish text. Why are there so many of these?! (Don't answer that, I know why...)
@iH<,{|jbRH?L^VjGJH<vn3p7I,x~@1jyt>x?,!YAJr*08P
```
As the description says we have some random text that makes no sense. Looking at the title of this challenge gives us a big clue to what it may be though. As I've done a few CTFs before I have a site that I like to check first for things like this. If we head over to [dcode.fr](https://www.dcode.fr/cipher-identifier) and check out their cipher identifier we can get an easy win. The cipher identifier even has a spot for clues/keywords (so we can feed it the word flag since we know that should be the final outcome) although it isn't necessary in this case. Paste in the gibberish and hit analyze and the site comes back with Base91 Encoding as a high probability.

![](/images/CTFs/NahamCon2023/Warmups/91_identified.png)

Head over to the [Base91 page](https://www.dcode.fr/base-91-encoding), enter the gibberish, and hit decrypt for the flag.

![](/images/CTFs/NahamCon2023/Warmups/91_decrypted.png)

# tiny little fibers
```
Author: @JohnHammond#6971
Oh wow, it's another of everyone's favorite. But we like to try and turn the ordinary into extraordinary!
```
Ahh yes. Having been in the Discord channel the entire time I was working on the CTF I know a lot of people struggled with this one, myself included. Something I realized right off the bat with this challenge was the name. What is another name for tiny little fibers? Strings. With that said running `strings tiny-little-fibers | grep flag` gives us nothing at all. Then I thought about the name some more. Tiny. Strings by default will show anything that is four characters or more. What if there was some trickery going on where the flag was cut up smaller than four characters? `strings tiny-little-fibers -n 3 | grep fla` has no results. `strings tiny-little-fibers -n 2 | grep fl` has a few, so if we modify that to include the next line by adding `-A 1` or `strings tiny-little-fibers -n 2 | grep -A 1 fl` we will hopefully see 'ag' on the following line. Nope.

At this point I was thinking I needed to spell this out one character at a time and wondering how the heck I was going to find the flag. I started over thinking this and imagining I would have to script something, but it is much easier than that. There are two options I came up with (and yes I'm sure there are plenty more. Using something like sed would have worked too but I can never remember the syntax...)

## Sublime text with regular expressions
Going with the theory that we need to spell this out one character at a time we can dump the results to a file with `strings tiny-little-fibers -n 1 > tiny.txt`. Checking that with `wc -l tiny.txt` shows us we have 146124 lines so we will never find this by eye. What I ended up doing was loading this into sublime text and using find with regular expressions turned on. `\n` is a new line, so by searching for `f\nl` we start spelling flag one character at a time on each line. once we add `\na` we finally see the flag.

![](/images/CTFs/NahamCon2023/Warmups/tiny_sublime.png)

## CyberChef remove whitespace

Again we start off with `strings tiny-little-fibers -n 1 > tiny.txt` but this time we take the output of this file and bring it into CyberChef, either by copy paste or by importing the file. Now we can use the `Remove Whitespace` recipe to make one giant string of text which contains our flag.

![](/images/CTFs/NahamCon2023/Warmups/tiny_cyberchef.png)

# Regina
```
Author: @JohnHammond#6971
I have a tyrannosaurus rex plushie and I named it Regina! Here, you can talk to it :)
```
Another Discord favorite :). To me this was a Google challenge which didn't take me that long to find the answer. Upon login we are greeted with `/usr/local/bin/regina: REXX-Regina_3.9.4(MT) 5.00 25 Oct 2021 (64 bit)` so we know exactly what we are dealing with. The question is how on earth do we interact with this?

Heading off to Google I put in `"REXX-Regina_3.9.4"` which came back with a whopping three results. One of these [pages](https://sourceforge.net/p/regina-rexx/bugs/574/) was very interesting though.

![](/images/CTFs/NahamCon2023/Warmups/regina_bug.png)

Reading this I tried to put in the commands exactly as described in the post. There are a few things that stood out to me. One of these was that the command `'uname -a'` is a standard Linux command so I was assuming that if I got any output from this at all I could change it to whatever I wanted. The second was the `^D` which I instantly recognized as ctrl+d. Was that really the way to talk to this thing? It seems so.

![](/images/CTFs/NahamCon2023/Warmups/regina_first_try.png)

It even crashed how it did in the post. Time to start trying some stuff to see if we can get a flag. I quickly realized that all I needed was a command in quotes followed by a ctrl+d to get what I wanted. `'ls'` showed that there was a file 'flag.txt' so we are on the right path. Let's try `'cat flag.txt'` followed by ctrl+d.

![](/images/CTFs/NahamCon2023/Warmups/regina_flag.png)

I do want to note that when I tried this originally I specifically remember it crashing when any command had a period in it, ex: 'cat flag.txt'. I ended up solving this instead with a `'cat flag*'`.

# Fast Hands
```
Author: @JohnHammond#6971
You can capture the flag, but you gotta be fast!
```
Navigating to the page and clicking on the 'Capture The Flag' button I could see a popup appearing and disappearing quickly. Looking at the page source we see that clicking the button is opening `./capture_the_flag.html`.

![](/images/CTFs/NahamCon2023/Warmups/fast_hands_source.png)

Let's move to the command line and try to curl this page with `curl http://challenge.nahamcon.com:30668/capture_the_flag.html`

![](/images/CTFs/NahamCon2023/Warmups/fast_hands_flag.png)

Flag acquired.

# Glasses
```
Author: @JohnHammond#6971
Everything is blurry, I think I need glasses!
```
The web page is a simple site trying to sell some glasses. There is a blurred out section between the paragraphs which I immediately wanted to inspect. Right clicking is apparently a no no though.

![](/images/CTFs/NahamCon2023/Warmups/glasses_no_hacking.png)

The joke is after clicking OK my right click window popped up anyway. Having right clicked directly on the blurry text and selecting inspect I was instantly greeted with the flag, although some character cleanup is necessary.

![](/images/CTFs/NahamCon2023/Warmups/glasses_flag.png)

# Blobber
```
Author: @JohnHammond#6971
This file is really... weird...
```
Revisiting this I actually found another solution to what I did originally so I'll include both. To start off, the first thing I do when downloading random files is to see what they are using the file command.

![](/images/CTFs/NahamCon2023/Warmups/blobber_file.png)

So we now know we are working with an SQLite 3.x database file. Off to Google to look for an online database viewer: `SQLite database viewer online`

## sqliteviewer.app

The first link that shows up is [sqliteviewer.app](https://sqliteviewer.app/). We can open the file (making sure to set it to view all files since our file does not have an extension) and see we have a bunch of records. Now if you are a fool like me you typed 'flag' into the search fields and came up with nothing and moved to a different site. If you actually take the time to look through the records you find at row 238 there is a file in the data column.

![](/images/CTFs/NahamCon2023/Warmups/blobber_data_download.png)

After downloading it we again have a random file, so let's see what it is with the file command (specifying `./-blobber-238-data` since the filename starts with a '-')

![](/images/CTFs/NahamCon2023/Warmups/blobber_data_filetype.png)

Easy enough, its a bzip2 archive. Let's extract that with `bzip2 -d ./-blobber-238-data`. We are told that bzip2 can't guess the original name for the file but that's not an issue. Once again we can check what type of file we are dealing with with `file ./-blobber-238-data.out`. It's a PNG. Let's have a look with `display ./-blobber-238-data.out`

![](/images/CTFs/NahamCon2023/Warmups/blobber_png_flag.png)

## inloop.github.io

As I mentioned above I ended up going to the second link in my google search, [inloop.github.io](https://inloop.github.io/sqlite-viewer/). Since my search at the previous site did not turn up anything I decided to spend more time on this one, looking through everything. Once I got to page 8 (again row 238) I saw the string of numbers in the data column. 

![](/images/CTFs/NahamCon2023/Warmups/blobber_inloop.png)

I couldn't remember exactly what the string of numbers was but I turned to my old friend CyberChef to figure it out. After pasting in this huge string of numbers CyberChef was nice enough to put a little magic wand next to where it says output, telling me that the 'From Decimal' recipe will produce something for us. Clicking on the magic wand will load the recipe, and now the magic wand shows that a Bzip2 file is detected. Clicking the magic wand this time does not help as it loads the 'Detect file type' recipe, however searching the operations there is a 'Bzip2 Decompress' recipe we can load. The magic wand now tells us it will render a PNG. Click it one last time to reveal the flag.

![](/images/CTFs/NahamCon2023/Warmups/blobber_cyberchef_flag.png)