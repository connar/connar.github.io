+++
title = "Showerpell - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++


In this challenge, we are given a pcap file. By observing the packets in the pcap, one is identified which appears to be transferring a file named "dnsexfil.ps1". Using the option File --> Export Objects --> HTTP in Wireshark, this file can be downloaded for further analysis. You can retrieve this packet from Wireshark by going to File --> Export Objects --> HTTP.  

![alt text](/posts/writeups/pmdk/showerpell/showerpell1.png)  

With the help of a text editor, we can open this powershell script and view its contents:  

![alt text](/posts/writeups/pmdk/showerpell/showerpell2.png)  


The file appears to contain encoded code.  
By observing the code, the following significant elements are identified:  
- At the end of the file, there is the string "i'e'x", which indicates how PowerShell commands are executed. This suggests that running the code will create an executable file.
- The malicious program to be created appears to decode a base64-encoded large string.
- The result of the decoding is decompressed using the deflateStream method.  

Following these steps, it is possible to retrieve the code that will be executed. For this purpose, the online tool CyberChef (https://gchq.github.io/CyberChef/) can be used.  

![alt text](/posts/writeups/pmdk/showerpell/showerpell3.png)  

The result is now in an unreadable format and can be saved into a file named "deobfuscated.ps1" for further analysis:  

![alt text](/posts/writeups/pmdk/showerpell/showerpell4.png)  

The code that emerges appears to decode from base64 and store a large string in a variable. Using CyberChef again, the decoding can be performed:  

![alt text](/posts/writeups/pmdk/showerpell/showerpell5.png)  

The result may not be as readable as the previous code; however, the first 2 bytes ```MZ``` indicate executable file headers. Therefore, it should be saved as a ```.exe``` file.  

Using the file command, you can retrieve basic information about the executable, such as it being a ```.NET``` file:  
```
┌──(connar㉿kali)-[~/showerpell]
└─$ file someExecutable.exe
someExecutable.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Since the executable is a .NET file, you can use the tool DNSPY to analyze its code:  

![alt text](/posts/writeups/pmdk/showerpell/showerpell6.png)  

Observing the code, the flag of the challenge is identified as a variable within the main function:  
```FLAG{y0u_h4v3_r34ch3d_7h3_d3p7h5_0f_4_r34l_w0rld_t00l_y0u_5h0uld_b3_pr0ud!}```  

In creating this challenge, tools used by malicious entities in the real world were leveraged.
