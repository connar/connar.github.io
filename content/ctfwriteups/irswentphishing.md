+++
title = "IRS went phishing - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

We are provided with a .pst file which is essentially an outlook email file. We can either view it with online tools such as goldfynch or with command line tools such as readpst.  

The goldfynch is the easier option so that’s what we are going to use:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs1.png)  

Opening the email, we view what seems to be a very sus message from presumably the IRS:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs2.png)  

An archive is provided to the victim with a password set to recover the form. Archives with a password are usually a technique threat actors use to avoid detection of their malicious documents,  since if the document had not been zipped with a password, gmail would not have allowed it to be sent. Anyway, let’s download and open it.
Using the provided password, we get a Microsoft word file:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs3.png)  

Make sure to disable your windows defender if it automatically deletes the file after extraction (if you use windows to solve this chall). I will be using kali for this one.  

The email implied that a form would be provided for the victim to fill and send to another goofie email, but we see just an image trying to convince the victim to enable macros (btw this image was taken by a real phishing campaign using irs) : 

![alt text](/posts/writeups/ctflib/irswentphishing/irs4.png)  

Let’s view the macros that will get executed after we click enable. You can do it with either the olevba suite or with just enabling the developer tab in word and view them manually.  

Running the command olevba [document], we get the following sus vba macros:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs5.png)  

We see that this script is inside an AutoOpen sub, which means this will be executed as soon as the enable macros has been clicked.  

Although we see some seemingly legitimate but unused variables (which is usually used to change the entropy of the file), there are some keypoints to notice here.  

First off, we see the line “tt = ThisDocument.BuiltInDocumentProperties("Content status").Value” which tries to get something from the document properties, specifically the content status value.  

Then, it takes this value and reverses it in the line “oinfer = StrReverse(tt)”.  

After that, we have a very sus line “jjfre = Chr(112) & Chr(111) & Chr(119) …” which creates a command with the Chr() method. Let’s run this line and see what is been created:  
```py
>>> jjfre = jjfre.replace("Chr", "chr").replace("&", "+")
>>> eval(jjfre)
'powershell.exe -WindowsStyle -ExecutionPolicy Bypass -Command'
```

I have not placed the whole command yet since we don’t know at this point what the content status value is that is being used in this command, but essentially a powershell command is being constructed.  

At the very end, we see that this powershell command is being executed in hidden mode with the line “CreateObject("WScript.Shell").Run jjfre, 0, False”.  

Let’s try and find what the content status value is that is being reversed and then used. You can either do it manually through the document info->properties->show all or by unzipping the document itself and observe its actual structure:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs6.png)  

Searching through the files, we eventually find in the DocumentSummaryInformation a very sus string:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs7.png)  

Reversing it, as the vba code implied, we get this clearer powershell obfuscated script:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs8.png)  

A good way in general to deobfuscate fast scripts like this is to just run it in an isolated vm/online powershell interpreters like tio.run.  

Using an isolated vm and disabling windows defender, we get this deobfuscated script:

![alt text](/posts/writeups/ctflib/irswentphishing/irs9.png)  

We see some replacement operations being done in some initial variables, so let’s mimic the operations:  

![alt text](/posts/writeups/ctflib/irswentphishing/irs10.png)  

Nice! So we see some urls that the script tries to reach and download and execute a dll hosted to one of them.  

Since there is nothing more to it, let’s observe the urls. They kinda look like b64 so if we try to decode the files that each url tries to get, we eventually get a hit on h[x][x]p://romancebrazil.com/gallery/9/Q1RGTElCezVuMzR8PHlfTTM3NGQ0NzR9/:  
```py
>>> from base64 import b64decode
>>> b64decode(b"Q1RGTElCezVuMzR9PHlfTTM3NGQ0NzR9")
b'CTFLIB{5n34}<y_M374d474}'
>>>
```

This is it for this one :)


