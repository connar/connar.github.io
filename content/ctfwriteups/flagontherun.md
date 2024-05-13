+++
title = "Insider - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++


Unzipping the provided file, we extract the following files:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun1.png)

This time we don’t have only a “.pcap” file but also a file named sslkeylog.log, which when opened does not make a lot of sense:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun2.png)  

So we will ignore this for now and open the provided “.pcap” file with Wireshark:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun3.png)  

This time, packets are not that clear as in the previous challenge. We have a lot more packets and many different protocols. To view all protocols detected by Wireshark, we can navigate to “Statistics  Protocol Hierarchy” and get the following information:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun4.png)  

Searching for HTTP requests, which in most cases reveal almost immediately fruitful information leads to a dead end:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun5.png)  

We turn back to the protocol hierarchy and we see that TLS is used about 21% from the total network traffic protocol types. Googling what TLS is, we find out that it is a protocol used for encrypting data before being sent over the internet.  

So, since we can’t see the full traffic because of the encryption, we ideally would like to decrypt it. Searching for how to decrypt TLS traffic in Wireshark we find the following:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun6.png)  

We remember that a log file is given to us, so it seems like we are in the right track. Reading the article, the following steps are suggested:   

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun7.png)  

Following the steps above and providing the sslkeylog.log as the (Pre)-Master-Secret log filename decrypts the traffic:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun8.png)  

We can finally start to see clear packets. Revisiting “http” requests though leads to the same packets we previously found. If we enumerate the whole decrypted “.pcap”, we will notice (just like in the previous image) that we indeed have some “GET” requests, but with HTTP2 protocol. HTTP2 is basically an HTTP variant that compresses data more:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun9.png)  

Filtering for “HTTP2” requests, we are met with the following packets:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun10.png)  

We can see a lot of GET requests, some POST requests and some responses.  
We can play with the filters and use one like the following for more organized results:  

![alt text](/posts/writeups/ctflib/flagontherun/flagontherun11.png)  

Here I used a specific filter for “GET” requests in HTTP2 protocol and also chose the destination to be the ip “104.20.67.143” since all the strange GET requests were send to this domain. Taking about domains, looking at one of the packets, we see that this destination ip is actually this domain:  
```json
> Header: :authority: pastebin.com
> Header: :scheme: https
> Header: :path: /79CbDmEE
```

Googling what “Pastebin.com” is makes the traffic we found even more suspicious. We will find out that it is a website that allows users to share plaintext  through public posts called "pastes". It is common for hackers to upload payloads or leaked information there to be able to reference them later on.  

Maybe a flag has been posted to one of the paths found in Wireshark?  
Since we have a lot of “GET /path” requests, instead of navigating manually to each one, we are going to create a python script to automate this process.  

I ended up with the following: 
```py
import pyshark
import requests
import re

cap = pyshark.FileCapture("patterns.pcapng",display_filter='(http2.header.value=="GET") and (http2.header.value contains pastebin) and (http2.header.name.length > 18)')
pkts = [p for p in cap]

for packet in pkts:
	path = packet.http2.stream.split(',')[-1][5:]
	url = "https://pastebin.com"+str(path)
	r = requests.get(url)
	if "CTFLIB" in r.text:
		print("path which has the flag is : "+str(path))
		match = re.search(r'[\w]+{[\w]+}', r.text)

        '''
		the above match translates to : [anystring]{[anystring]}
		basically any string that is followed by '{', then contains any string that is followed by '}'
        '''

		print(match.group(0))
		break
```

Breakdown of the code:
- Import pyshark library. This library is mimicking Wireshark into a script. By doing this, we can read “.pcap” files and use filters to minimize the results as we saw previously. Here, I used a different filter than the previous one only to showcase a different approach.
- This script reads the “.pcap” file with the given filter and loops through each packet. 
- It then tries to extract all /[paths] from the GET requests we saw.
- After it finds the path, it constructs a url with the domain we found (Pastebin) and the path we extracted.
- It makes a request to the constructed url and uses regular expression to see if the response contains a string that matches the flag format of the challenge. If it does, it prints the flag as well as the path it was found at.  

Running the code, we get the flag:
```
┌──(connar㉿kali)-[~/blog/black_eye_tool]
└─$ python pysharkfilter.py
path which has the flag is : /mGzAUAg2
CTFLIB{fl4g_1n_6u6l1c_51gh7}
```

