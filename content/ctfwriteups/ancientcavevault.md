+++
title = "Ancient Cave Vault - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

This is a ‘secret password’ type of challenge, where we need to somehow reverse engineer the given executable and find the correct password:  

![alt text](/posts/writeups/pmdk/ancientcavevault/acv1.png)  

After the final wrong attempt, the executable closes:  

![alt text](/posts/writeups/pmdk/ancientcavevault/acv2.png)  

So how can we find the correct password for the executable? Well, we first need to review its code. If you run the ‘file’ command on the given file, you will find out that this is a Mono/.Net assembly, and if you search up with how to decompile (reverse) these type of programs/applications, a tool named DnSpy will come up which is a tool used for exactly that – decompile/debug .net executables.  

Having DnSpy installed in your system, simply drag and drop the .exe to it:  

![alt text](/posts/writeups/pmdk/ancientcavevault/acv3.png)  

Now, there are plenty of ways to go about solving this challenge. The easier way is to put a breakpoint at the line where it checks our input with the correct decrypted passphrase:  

![alt text](/posts/writeups/pmdk/ancientcavevault/acv4.png)  

Stepping over the breakpoint, we will see that the variable “value” now holds the decrypted passphrase:  

![alt text](/posts/writeups/pmdk/ancientcavevault/acv5.png)  

We can actually modify the “text” = “test” value to the real password in order to bypass the check and get the flag:  

![alt text](/posts/writeups/pmdk/ancientcavevault/acv6.png)  

Stepping over once again, we pass the if statement and get the decrypted flag:  

![alt text](/posts/writeups/pmdk/ancientcavevault/acv7.png)  

> "FLAG{y0u_unl0ck3d_7h3_f029073n_53c2375}"
We could also just rerun the program and provide the correct passphrase.

