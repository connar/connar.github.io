+++
title = "Chinese Windows Updater - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

Upon opening the file, we are presented with a memory dump and a batch script. Initially, the batch script appears to have been obfuscated:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu1.png)  

Moreover, the memory dump alone does not yield any useful insights.  
Therefore, the initial approach is to utilize search engines, such as Google, to gain an understanding of the nature and potential purpose of the batch script:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu2.png)  

Upon conducting a search, we discover several posts that appear to be relevant to the challenge and could potentially guide us towards a solution.  
Of particular interest is the first post, which features a script that bears a striking resemblance to our own:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu3.png)  

This post states the following:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu4.png)  

For further reading, this post can be found at:
- https://superuser.com/questions/1676713/how-to-decode-contents-of-a-batch-file-with-chinese-characters
So let’s try to follow these steps and open the batch script in the hex editor HxD:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu5.png)  

And it worked. We now have a less obfuscated script of which we can make notice of some readable characters.  
Let’s copy the whole hex block to cyberchef and convert it to ascii:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu6.png)  

To continue on with the next level of deobfuscation, let’s copy the code to notepad (or any other text editor) in order to make some modifications if needed:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu7.png)  

We can spot some readable words such as cls, public and envPolisus.  
The remaining text appears to be concealed using a second stage of obfuscation, marked by the " %:~" symbols.  

We can refer to the earlier post we analyzed, which provides an example on how to deobfuscate code employing this technique.  
Notably, these symbols are frequently utilized in VBA syntax and CMD variables. In CMD or VBA, variables are created using the "set" command, and their contents can be retrieved by enclosing the variable name within percentage symbols ("%"):  
```
C:\Users\connar>set example="This is an example"

C:\Users\connar>%example%
'"This is an example"' is not recognized as an internal or external command,
operable program or batch file.
```

Additionally, the unusual ":~number, number" patterns that we observed earlier in the script serve to extract specific portions of a value that has been stored in a variable. For instance:  
```
C:\Users\connar>%example:~12,2%
'ex' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\connar>%example:~12,1%
'e' is not recognized as an internal or external command,
operable program or batch file.
```

To illustrate, consider the following examples:
- %example:~12%: This command counts 12 positions from the beginning of the "example" string, and then returns the remaining characters of the string, which is "example".
- %example:~12,2%: This command counts 12 positions from the start of the "example" string, returns the remaining characters of the string ("example"), and then extracts the first two characters, which are "ex".
- %example:~12,1%: This command counts 12 positions from the beginning of the "example" string, returns the remaining characters of the string ("example"), and then retrieves the first character, which is "e".
It appears that this technique is a form of obfuscation known as environment variable obfuscation, which constructs commands using letters stored in Windows environment variables. By utilizing this method, the obfuscated code can avoid detection, as it does not rely on known malicious commands in plain text. Instead, the commands are assembled during runtime.  

To deobfuscate the code, we can proceed line by line through the script and enter each line into the terminal using the "echo" command to observe its behavior:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu8.png)  

It's worth noting that the terminal treats uppercase and lowercase variables as equivalent. For example, "R" is the same as "r". Additionally, the "^" symbol needs to be escaped in the command.  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu9.png)  

We can see that the script checks if an environment variable called envPolisus is empty. If it is, it prints:  
```
C:\Users\connar>echo ec%r:~11,1%o Co%r:~13,1%ld no%r:~4,1% %r:~13,1%pda%r:~4,1%e yo%r:~13,1%r %r:~9,1%%r:~2,1%ndo%r:~9,1%%r:~8,1%
echo Could not update your windows
```

In the case where the environment variable exists, the script continues execution.  

If we wanted to run this script in an isolated environment, we could set this variable to something and this script would continue executing, so we could analyze it dynamically (for example with Wireshark to see if it tries to connect to somewhere).  
Continuing on:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu10.png)  

It tries to run a Powershell command which essentially gets the value of envPolisus variable, and then gets its SHA256 hash and stores it in a file.  
It then reads from this file and checks if the hash it read is equal to:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu11.png)  

If it is, it continues executing. If its not, it prints a message and stops.  

The "envPolisus" variable as we can see gets used a lot, and while we have its SHA256 hash, attempting to crack it with hashcat would likely be a dead end. However, we do have access to the memory dump that was provided to us.  

Although we may not have the "envPolisus" variable set on our own system, the system from which the memory dump was taken might. By using a tool like Volatility, we can attempt to locate this variable in the memory dump:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu12.png)  

And we get the first part of the flag!  
The sha256 sum of this string is really the hash displayed on the script:  
```py
>>> from hashlib import sha256
>>> part1 = b"CTFLIB{50m4l1_p12473_"
>>> sha256(part1).hexdigest()
'f590ad9a61d196447f3832ab3b3ba449e45b381aaf0bfa6de07d08f2d4de5a9a'
>>>
```

Continuing on with the analysis, we have:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu13.png)  

Basically, it uses this “lru” variable, which is automatically deobfuscated from our echo command, to download whatever is in this url and stores it in a file called windowsUpdater.ps1:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu14.png)  

Once the contents of the Pastebin post have been downloaded and stored in the "windowsUpdater.ps1" file, the script attempts to locate and execute this file, assuming that the download was successful:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu15.png)  

The script uses a loop to search for a corresponding file, and if it finds one, it saves the file name to a variable called "p" and executes it with Powershell. If everything has gone successfully, this is the end of the script. However, we still have not found the second part of the flag. Perhaps we can find it by visiting the Pastebin post mentioned in the script:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu16.png)  

Visiting the Pastebin post, we can see more Powershell code which thankfully is not so obfuscated this time.  
What catches our eyes is a weirdly big string that looks like base64 encoded. Copying it and decoding it in Cyberchef, we get:  

![alt text](/posts/writeups/ctflib/chinesewindowsupdater/cwu17.png)  

It tries to download even more files. The file it tries to download again looks like its base64 encoded. Trying to decode it we get the second part of the flag:  
```py
>>> from base64 import b64decode
>>> b64decode(b"MDZmdTVjNDcxMG5fMTVfcHIzNzd5X24zNDd9")
b'06fu5c4710n_15_pr377y_n347}'
```
