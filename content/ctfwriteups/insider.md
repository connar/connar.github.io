+++
title = "Insider - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

The goal of this challenge is to find artifacts that prove the suspect user leaked some flags to a forum that hosts stolen databases for sale.  So this is what we have to look for. Downloading the file, we are met with a zip file which contains the following:  

![alt text](/posts/writeups/ctflib/insider/insider1.png)

A google search about .aut files is enough to find out that a tool called Autopsy is needed to analyze this file (although the file autopsy.db implies this as well).  
Opening the challenge file in autopsy, we are met with the filesystem of the suspect user:  

![alt text](/posts/writeups/ctflib/insider/insider2.png)  

As it was stated earlier, we need to find proof of leaks to some stolen database marketplace. The way to go about solving this challenge is to make the critical thought on how could someone access such market. This is because, to leak information to a website, you must first visit it. One could think that the normal browsing history of the user would lead him to the answer but this is the wrong way to approach this problem. Online markets such as the one we are searching for is not accessible through normal browsers, but through a browser such as Tor.  

So now we have to search on where information about Tor browser is stored. In other words, we want to do a forensic investigation on Tor browser. It is not a prerequisite to know where to search, so we will use google to find the answer.  
Amongst some articles, a great presentation about Tor forensics suggests looking in the following path:  

![alt text](/posts/writeups/ctflib/insider/insider3.png)  

Navigating to these folders and enumerating a bit, we find a search query of the Tor Browser:  

![alt text](/posts/writeups/ctflib/insider/insider4.png)  

We see that a query for the infamous raid forums darknet market was made which contained the flag with some url encoding in it. We can use the online CyberChef tool to decode the flag:  

![alt text](/posts/writeups/ctflib/insider/insider5.png)  