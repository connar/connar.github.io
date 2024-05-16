+++
title = "Hinting flags - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

Extracting the contents of the zip file, we are met with a "Win7x64.mem” file. This is a memory dump file and can be analyzed with various tools. One of the tools that can analyze these type of files is called Volatility. Let’s see how it is used:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags1.png)  

Volatility, based on the provided file, tries to match what type of system this dump was taken from. The first suggestion it makes is Win7SP1x64 which is basically Windows 7 – 64 bit.  

Now that we have a profile for our memory dump file, we have to locate the password hint inside the memory dump in order to analyze it. Google will help us in this task:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags2.png)  

Although the Microsoft community forum does not show the full path, it suggests to look at the SAM (Security Account Manager) hive:  
```
Sorry, I have no idea about the structure of the SAM file and where this information might be kept. Here are a couple of options:
- Use a search engine in an attempt to find discussions that deal with this subject.
- Take a copy of the SAM, then create a hint.Now take another copy and compare the two versions, using fc.exe /b.
```

This community forum can be found at:
- https://answers.microsoft.com/en-us/windows/forum/all/user-account-password-hint-registry-location/596030e0-6b72-46ef-97bf-fdc77b3632c9  

We will update our search based on the information found and look for the location of the password hint inside SAM:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags3.png)  

This question in the following Stackexchange forum not only tells us where to look, but how to decrypt – or rather decode – it:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags4.png)  

The post on the forum can be found at:
- https://security.stackexchange.com/questions/264896/is-there-a-way-to-get-windows-login-password-hint-from-sam-hive-with-volatility  

Going back to Volatility, we will query for the password hint based on the suggested path in the stackexchange forum:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags5.png)  

The option “printkey -K” will print the information in the specified path.
We see some Subkeys (imagine them as subfolders). These Subkeys are actually the users of the windows	machine written as codes instead of names.
The answer of the question in the stackexchange suggests to use the <userkey> after the “\Users” Subkey. Using the first user code as the <userkey>, we get:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags6.png)  

We don’t see any password hint. Repeating for the rest of the users, we get a match at the usercode “000003E9”:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags7.png)  

One way to recover the plaintext form of this (as the stackexchange answer suggested) is by the sample code provided in the answer. Another way is to make our own python script. But first, let’s understand a little bit more what this format we are looking at really is:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags8.png)  

So the password hint is basically stored as hex with pairs of zeros in between each value. 
To recover the plaintext format, we have to:  
- Remove dots:
```4300540046004C00490042007B003500...```
- Remove pairs of zeros:
```4354464C49427B35...```
- Convert from hex to bytes:
```py
flag = "4354464C49427B35305F6C306E365F7933375F35305F7733346B5F5F5F7D"
print(bytes.fromhex(flag).decode())
```

Running the above two-liner script, we get the flag:  
```
┌──(connar㉿kali)-[~/hintingflags]
└─$ python decryptingHint.py
CTFLIB{50_l0n6_y37_50_w34k___}
```

Another way is using the online tool “CyberChef”:  

![alt text](/posts/writeups/ctflib/hintingflags/hintingflags9.png)  