+++
title = "Weak Legacy - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

Based on the description of the challenge, we need to decrypt some messages that seem to be encrypted.  
Pcap files can be viewed by a software named Wireshark. Downloading both the challenge file and the software, we can finally view it:

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy1.png)


We can see a lot of ICMP packets and some UDP packets as well. More specifically, we can see that a pattern is created, where every 13-16 ICMP packets, two UDP packets are being exchanged.
Moreover, all UDP packets contain only two hosts:
- 192.168.1.101
- 192.168.1.102

Usually, to view data exchanged over a packet, we have to click on one and look at the hexdump of the packet:  

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy2.png)

Inspecting all ICMP packets won’t lead us to anything useful. UDP packets on the other hand seem like they contain what we are looking for:  

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy3.png)

Using the “data” in the Wireshark filter bar, we get all the packets that contain data inside the packets. And as it turns out, all packets that contain data are UDP packets:  

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy4.png)

Until the packet No. 67 from the previous image, all messages are in plaintext format. The messages are:
1.	Hey Bob what's up:)
2.	Hey Alice:), not much. What about you?
3.	Well, i was actually trying this challenge called weak legacy at the CTFLIB platform and im kinda stuck. I was hopping for some help
4.	Of course. To be honest, i haven't really solved this myself but i got the flag from a friend. If you'd like, i can send it to you. But it would be safer for us to start encrypting our messages so that no one else gets the flag
5.	Yeah sure!
6.	DH64?
7.	Sounds fine, here you go 'p':15081801184129193989 , 'g':2, 'A':10108766542893374992
8.	B':3567237346515547599 . Let’s just XOR our messages with the key  

Then, the messages appear encrypted. But until this point, we have all the information needed to break the encryption scheme. We know: 
- Key exchange algorithm: Diffie-Hellman 64-bit (DH64).
- p = 15081801184129193989
- g = 2
- A = 10108766542893374992
- B = 3567237346515547599
- Message encryption: XOR operation with the shared secret  

So, we need to find the shared secret from Diffie-Hellman based on the variables that got exchanged and then simply XOR the encrypted messages with this key.  
To find the shared secret, we must first find either the private key a or b of Alice or Bob.  
Searching for vulnerabilities in DH64, we end up in the following stack exchange forum, which states: 

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy5.png)  

This post can be found at:  
- https://crypto.stackexchange.com/questions/99519/64-bit-key-size-diffie-hellman

Basically, with a small key such as the one we have found, discrete logarithm problem security is lost. So it means we can compute the discrete logarithm in one of the two public keys and find a private key of either Alice or Bob. Information on how to compute the discrete logarithm in python can be found at:  

- https://stackoverflow.com/questions/1832617/calculate-discrete-logarithm  

One way to solve the challenge is with the following code:  

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy6.png)  

This script takes the p, A, g, B variables and tries to calculate either private key a or private key b. After it finds one, it calculates the shared secret and returns it. It then makes a XOR operation on the encrypted message with the key found and returns the decrypted message.
Let’s see an example with the first encrypted message:  

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy7.png)  

We first take the hex value of the encrypted message and then paste it in the c variable of the script:  

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy8.png)  

Doing the same process for each message, we end up with the following decrypted conversation:  

![alt text](/posts/writeups/ctflib/weaklegacy/weaklegacy9.png)  

where we can spot the flag: CTFLIB{5m4ll_k3y5_n0_3ncryp710n}