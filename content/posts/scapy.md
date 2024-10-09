+++
title = "scapy for pcap parsing"
draft = false
tags = ["pcap","scapy"]
categories = ["Forensics"]
ShowToc = true
author = ["connar"]
+++

## Intro
In this post we will explore the scapy library in python and its features when it comes to analyzing pcap files. In general, scapy library can be used for both red team (sniffing traffic) and blue team operations (analyzing pcap files). We will stick to the second one for this post.  

I learned about scapy back when I started playing CTF challenges and was trying to solve a challenge where data had been exfiltrated through the ICMP protocol (we will see that challenge later). The idea in that challenge was that data was exfiltrated from the victim machine through ping requests - byte by byte. As you can tell, it was really difficult to manually reconstruct the exfiltrated data as this would mean copying and pasting the corresponding data from each packet. This is not really practical if you have a big pcap file.  

Then, I came across a video of 0xdf (I have learned so many stuff from him) where he used the scapy library for the same challenge to reconstruct the exfilled packet easy and simple (and quickly too!). I was really amazed by scapy's functionality and soon after it became my go-to tool for analyzing pcap files and specifically for C2 traffic. 

Through this post we will see a general approach of how to translate what you see in Wireshark (i.e. the fields of a packet) to scapy's syntax. For example, we can see in Wireshark's GUI an IP address of some packet, but how can we get it through a python script using scapy?

After we briefly explain the logic and methodology on how to find the fields you are interested in, we will see some practical examples such as some CTF challenges where scapy comes useful - including the exfil chall I mentioned in the start.

## HTTP traffic analysis
To begin with, we will start analyzing a PoC pcap taken from wireshark.org which is just a simple http traffic pcap file. You can find the pcap file [here](https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap).  

Let's open it in Wireshark first to get a view of what we are dealing with and what to expect:  

![http pcap](/posts/scapy/http_pcap.png)  

We see that the total number of packets is 43. Let's see how to find that with scapy!

### Getting the number of packets
In order to get the number of packets, we first of all need to read the pcap file:
```python
from scapy.all import *

# Use rdpcap to read the pcap data
pcap = rdpcap("./http.cap")
```

Then, we could either print the lenght of the pcap variable (which is a list) in python, but I will show a trick that will be useful in finding any field of interest. The trick is to **run the script in interactive mode** in order to have access to the variables. It will become really handy in finding what properties each variable (i.e. each packet) has: 
```python
└─$ python -i parser.py
>>> pcap
<http.cap: TCP:41 UDP:2 ICMP:0 Other:0>
>>> len(pcap)
43
>>>
```

We indeed observe that our script finds the same number of packets as the wireshark shows. We always need to validate that our packets match to avoid parsing errors in future case scenarios.  

### Getting the checksum value of a packet

Let's try comparing a field of the first packet of Wireshark with the first packet that our script parses. For this purpose, we will try getting the checksum value:  

![checksum](/posts/scapy/http_checksum.png)  

The question is, how do we find the correct syntax to get this field? Here is where the interactive mode comes handy:  
```python
└─$ python -i parser.py
>>> first_packet = pcap[0]
>>> first_packet
<Ether  dst=fe:ff:20:00:01:00 src=00:00:01:00:00:00 type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=48 id=3905 flags=DF frag=0 ttl=128 proto=tcp chksum=0x91eb src=145.254.160.237 dst=65.208.228.223 |<TCP  sport=3372 dport=http seq=951057939 ack=0 dataofs=7 reserved=0 flags=S window=8760 chksum=0xc30c urgptr=0 options=[('MSS', 1460), ('NOP', None), ('NOP', None), ('SAckOK', b'')] |>>>
>>> 
>>> dir(first_packet)
['_PickleType', '__all_slots__', '__bool__', '__bytes__', '__class__', '__class_getitem__', '__contains__', '__deepcopy__', '__delattr__', '__delitem__', '__dict__', '__dir__', '__div__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getitem__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__iterlen__', '__le__', '__len__', '__lt__', '__module__', '__mul__', '__ne__', '__new__', '__nonzero__', '__orig_bases__', '__parameters__', '__rdiv__', '__reduce__', '__reduce_ex__', '__repr__', '__rmul__', '__rtruediv__', '__setattr__', '__setitem__', '__setstate__', '__signature__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', '__truediv__', '__weakref__', '_answered', '_command', '_defrag_pos', '_do_summary', '_is_protocol', '_name', '_overload_fields', '_pkt', '_raw_packet_cache_field_value', '_resolve_alias', '_show_or_dump', '_superdir', 'add_parent', 'add_payload', 'add_underlayer', 'aliastypes', 'answers', 'build', 'build_done', 'build_padding', 'build_ps', 'canvas_dump', 'class_default_fields', 'class_default_fields_ref', 'class_dont_cache', 'class_fieldtype', 'class_packetfields', 'clear_cache', 'clone_with', 'command', 'comment', 'copy', 'copy_field_value', 'copy_fields_dict', 'decode_payload_as', 'default_fields', 'default_payload_class', 'delfieldval', 'deprecated_fields', 'direction', 'dispatch_hook', 'display', 'dissect', 'dissection_done', 'do_build', 'do_build_payload', 'do_build_ps', 'do_dissect', 'do_dissect_payload', 'do_init_cached_fields', 'do_init_fields', 'dst', 'explicit', 'extract_padding', 'fields', 'fields_desc', 'fieldtype', 'firstlayer', 'fragment', 'from_hexcap', 'get_field', 'getfield_and_val', 'getfieldval', 'getlayer', 'guess_payload_class', 'hashret', 'haslayer', 'hide_defaults', 'init_fields', 'iterpayloads', 'json', 'lastlayer', 'layers', 'lower_bonds', 'match_subclass', 'mysummary', 'name', 'original', 'overload_fields', 'overloaded_fields', 'packetfields', 'parent', 'payload', 'payload_guess', 'pdfdump', 'post_build', 'post_dissect', 'post_dissection', 'post_transforms', 'pre_dissect', 'prepare_cached_fields', 'psdump', 'raw_packet_cache', 'raw_packet_cache_fields', 'remove_parent', 'remove_payload', 'remove_underlayer', 'route', 'self_build', 'sent_time', 'setfieldval', 'show', 'show2', 'show_indent', 'show_summary', 'sniffed_on', 'sprintf', 'src', 'stop_dissection_after', 'summary', 'svgdump', 'time', 'type', 'underlayer', 'upper_bonds', 'wirelen']
>>> 
>>> 
>>> first_packet.show()
###[ Ethernet ]###
  dst       = fe:ff:20:00:01:00
  src       = 00:00:01:00:00:00
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 48
     id        = 3905
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0x91eb
     src       = 145.254.160.237
     dst       = 65.208.228.223
     \options   \
###[ TCP ]###
        sport     = 3372
        dport     = http
        seq       = 951057939
        ack       = 0
        dataofs   = 7
        reserved  = 0
        flags     = S
        window    = 8760
        chksum    = 0xc30c
        urgptr    = 0
        options   = [('MSS', 1460), ('NOP', None), ('NOP', None), ('SAckOK', b'')]
>>>
```
By using the interactive mode, we have access to the variables of the script. For example, we read the pcap file into a variable named ```pcap```. Now we access the first value of this variable which is the first packet and store it in ```first_packet```. Now, by using ```dir``` we can see the various fields it contains. One note here is that ```dir``` has nothing to do with scapy. It is a python keyword to find what methods are supported by your object.

The ```dir``` keyword outputted the supported methods of our object - the first packet. One of its supported methods is the ```show()``` method. By using this method, we get back detailed information about all the supported layers of the packet but also the fields within each layer.  

Another nice way to see what available attributes a packet has is by using the tab-completion that will output available attributes of a packet:  
```sh
>>> first_packet.
Display all 104 possibilities? (y or n)
first_packet.add_parent(               first_packet.comment                   first_packet.do_dissect_payload(       first_packet.haslayer(                 first_packet.pdfdump(                  first_packet.show2(
first_packet.add_payload(              first_packet.copy()                    first_packet.do_init_cached_fields()   first_packet.hide_defaults()           first_packet.post_build(               first_packet.show_indent
first_packet.add_underlayer(           first_packet.copy_field_value(         first_packet.do_init_fields(           first_packet.init_fields()             first_packet.post_dissect(             first_packet.show_summary
first_packet.aliastypes                first_packet.copy_fields_dict(         first_packet.dst                       first_packet.iterpayloads()            first_packet.post_dissection(          first_packet.sniffed_on
first_packet.answers(                  first_packet.decode_payload_as(        first_packet.explicit                  first_packet.json()                    first_packet.post_transforms           first_packet.sprintf(
first_packet.build()                   first_packet.default_fields            first_packet.extract_padding(          first_packet.lastlayer(                first_packet.pre_dissect(              first_packet.src
first_packet.build_done(               first_packet.default_payload_class(    first_packet.fields                    first_packet.layers()                  first_packet.prepare_cached_fields(    first_packet.stop_dissection_after
first_packet.build_padding()           first_packet.delfieldval(              first_packet.fields_desc               first_packet.lower_bonds()             first_packet.psdump(                   first_packet.summary(
first_packet.build_ps(                 first_packet.deprecated_fields         first_packet.fieldtype                 first_packet.match_subclass            first_packet.raw_packet_cache          first_packet.svgdump(
first_packet.canvas_dump(              first_packet.direction                 first_packet.firstlayer()              first_packet.mysummary()               first_packet.raw_packet_cache_fields   first_packet.time
first_packet.class_default_fields      first_packet.dispatch_hook(            first_packet.fragment(                 first_packet.name                      first_packet.remove_parent(            first_packet.type
first_packet.class_default_fields_ref  first_packet.display(                  first_packet.from_hexcap()             first_packet.original                  first_packet.remove_payload()          first_packet.underlayer
first_packet.class_dont_cache          first_packet.dissect(                  first_packet.get_field(                first_packet.overload_fields           first_packet.remove_underlayer(        first_packet.upper_bonds()
first_packet.class_fieldtype           first_packet.dissection_done(          first_packet.getfield_and_val(         first_packet.overloaded_fields         first_packet.route()                   first_packet.wirelen
first_packet.class_packetfields        first_packet.do_build()                first_packet.getfieldval(              first_packet.packetfields              first_packet.self_build()              
first_packet.clear_cache()             first_packet.do_build_payload()        first_packet.getlayer(                 first_packet.parent                    first_packet.sent_time                 
first_packet.clone_with(               first_packet.do_build_ps()             first_packet.guess_payload_class(      first_packet.payload                   first_packet.setfieldval(              
first_packet.command()                 first_packet.do_dissect(               first_packet.hashret()                 first_packet.payload_guess             first_packet.show(                     
>>> first_packet.
```

Now, recall we want to get the chksum value of that packet (and compare it with the image above). We notice that the ```chksum=0xc30c``` exists in the TCP layer. But what is the correct syntax?  

Well, to get the fields that exist in a layer, we always start by using the name of the layer as the key - as if it was a list:  
```python
>>> first_packet.show()
###[ Ethernet ]###
  dst       = fe:ff:20:00:01:00
  src       = 00:00:01:00:00:00
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 48
     id        = 3905
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0x91eb
     src       = 145.254.160.237
     dst       = 65.208.228.223
     \options   \
###[ TCP ]###
        sport     = 3372
        dport     = http
        seq       = 951057939
        ack       = 0
        dataofs   = 7
        reserved  = 0
        flags     = S
        window    = 8760
        chksum    = 0xc30c
        urgptr    = 0
        options   = [('MSS', 1460), ('NOP', None), ('NOP', None), ('SAckOK', b'')]
```
We see that the chksum field exists inside the ```TCP``` layer. Imagine the packets as a tree struct. In order to get a field, we need to first visit its parent.  
Since the chksum exists inside ```TCP```, let's get the ```TCP``` layer first:  
```python
>>> first_packet[TCP]
<TCP  sport=3372 dport=http seq=951057939 ack=0 dataofs=7 reserved=0 flags=S window=8760 chksum=0xc30c urgptr=0 options=[('MSS', 1460), ('NOP', None), ('NOP', None), ('SAckOK', b'')] |>
```
If we again are not sure what info we want, we can use the ```dir``` keyword once again and see the available options:  
```>> dir(first_packet[TCP])
['_PickleType', '__all_slots__', '__bool__', '__bytes__', '__class__', '__class_getitem__', '__contains__', '__deepcopy__', '__delattr__', '__delitem__', '__dict__', '__dir__', '__div__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getitem__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__iterlen__', '__le__', '__len__', '__lt__', '__module__', '__mul__', '__ne__', '__new__', '__nonzero__', '__orig_bases__', '__parameters__', '__rdiv__', '__reduce__', '__reduce_ex__', '__repr__', '__rmul__', '__rtruediv__', '__setattr__', '__setitem__', '__setstate__', '__signature__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', '__truediv__', '__weakref__', '_answered', '_command', '_do_summary', '_is_protocol', '_name', '_overload_fields', '_pkt', '_raw_packet_cache_field_value', '_resolve_alias', '_show_or_dump', '_superdir', 'ack', 'add_parent', 'add_payload', 'add_underlayer', 'aliastypes', 'answers', 'build', 'build_done', 'build_padding', 'build_ps', 'canvas_dump', 'chksum', 'class_default_fields', 'class_default_fields_ref', 'class_dont_cache', 'class_fieldtype', 'class_packetfields', 'clear_cache', 'clone_with', 'command', 'comment', 'copy', 'copy_field_value', 'copy_fields_dict', 'dataofs', 'decode_payload_as', 'default_fields', 'default_payload_class', 'delfieldval', 'deprecated_fields', 'direction', 'display', 'dissect', 'dissection_done', 'do_build', 'do_build_payload', 'do_build_ps', 'do_dissect', 'do_dissect_payload', 'do_init_cached_fields', 'do_init_fields', 'dport', 'explicit', 'extract_padding', 'fields', 'fields_desc', 'fieldtype', 'firstlayer', 'flags', 'fragment', 'from_hexcap', 'get_field', 'getfield_and_val', 'getfieldval', 'getlayer', 'guess_payload_class', 'hashret', 'haslayer', 'hide_defaults', 'init_fields', 'iterpayloads', 'json', 'lastlayer', 'layers', 'lower_bonds', 'match_subclass', 'mysummary', 'name', 'options', 'original', 'overload_fields', 'overloaded_fields', 'packetfields', 'parent', 'payload', 'payload_guess', 'pdfdump', 'post_build', 'post_dissect', 'post_dissection', 'post_transforms', 'pre_dissect', 'prepare_cached_fields', 'psdump', 'raw_packet_cache', 'raw_packet_cache_fields', 'remove_parent', 'remove_payload', 'remove_underlayer', 'reserved', 'route', 'self_build', 'sent_time', 'seq', 'setfieldval', 'show', 'show2', 'show_indent', 'show_summary', 'sniffed_on', 'sport', 'sprintf', 'stop_dissection_after', 'summary', 'svgdump', 'time', 'underlayer', 'upper_bonds', 'urgptr', 'window', 'wirelen']
```

We are interested in the chksum value, so let's use a ```dot``` and then the name of the field to get it:
```python
>>> first_packet[TCP].chksum
49932
>>> hex(_)
'0xc30c'
>>>
```

Now that we know how to get the value, we could tranfer this to our script and get this field for each packet (assuming we would need that for a purpose - as we will later see in another example):  
```python
from scapy.all import *

pcap = rdpcap("./http.cap")

for i, p in enumerate(pcap):
    # Check if TCP layer is present in the current packet with the haslayer(layer) method
	if p.haslayer(TCP):
		print(f"Packet No.{i} has chksum = {hex(p[TCP].chksum)}")
```
and the output is:
```python
└─$ python parser.py
Packet No.0 has chksum = 0xc30c
Packet No.1 has chksum = 0x5bdc
Packet No.2 has chksum = 0x7964
Packet No.3 has chksum = 0xa958
Packet No.4 has chksum = 0x8421
Packet No.5 has chksum = 0x2b0a
...
...
```



## Examples  
Let's see some relevant examples where we would need to get the same field from each packet.

### Example 1: Exfiltration via port number - NIXU Challenge
This is a very nice challenge to showcase examples where we might need to get a specific field from all packets. In the ```ports``` challenge from ```the nixu challenge``` this is exactly what's going on: Data have been exfiltrated through the destination port number.  

Opening the file in Wireshark we can observe straight away that the ports look kinda odd (and when I say odd, I mean that they are inside the ascii range):  

![ports wireshark](/posts/scapy/ports_wireshark.png)  

The solution to this CTF challenge is to get each port number and convert the decimal to the ascii representation, which will output the flag. But obviously we don't want to do this manually and get each number by hand, so scapy will come handly since it will extract each port number and decode it for us. We saw earlier that by using the ```.show()``` method on a packet, we get various fields that the current packet contains. One of them was a field named ```dport``` which is basically the destination port. We could again evaluate this claim by running the script in interactive mode and finding the correct field ourselfs:
```python
└─$ python -i port_message.py
>>> first_packet = pcap[0]
>>> first_packet.dport
81
>>>
```

Now that we found what member is the appropriate one to get the port number back, let's develop a script to get every destination port from each packet and convert it to it's ascii equivalent:
```python
from scapy.all import *

pkts = rdpcap('ports.pcap')

ports = [chr(p.dport) for p in pkts]

print("".join(ports))
```

Running the script outputs:
```python
└─$ python port_message.py
QVZLSHtmbHpvYnlmX25hcV9haHpvcmVmX25lcl9zaGFfZ2JfY3lubF9qdmd1fQ==
```
which is a base64 string and if we decode it we will get the flag. Now imagine doing this by hand...

### Example 2: Exfiltration via ICMP ping
In this example we are going to go over an old HTB challenge (that has been retired) and I was super lucky to have kept it in my VM.  

In that challenge, there was an ICMP exfiltration going on that exfiltrated a compressed archive. The goal was to recontruct the exfilled data part by part and get the final compressed file.  

Obviously, this would be a really time consuming task to do it manually for each packet and thus this challenge is another good example of how powerful and useful scapy can be. Let's begin!  

Opening the pcap file and using the ```icmp``` filter, we are met with the following packets:  

![oldest trick1](/posts/scapy/oldest_trick1.png)  

We see straight away that the first ICMP packet is of echo type request and it contains the ```PK``` headers - headers that zip archives have, so probably a zip file got exfiltrated.  
Also, if we have a look at the second icmp packet which is of type reply, we will see that the same data that were in the request packet are being returned:  

![oldest trick2](/posts/scapy/oldest_trick2.png)  

So, things to take away from here:  
- We are interested only in ```icmp echo request``` type of packets.
- We are probably expecting a zip file reconstruction from these packets.  

We can start creating our scapy script and play around with the interactive mode to find the appropriate commands to reconstruct the zip:  
```python
from scapy.all import *

pcap = rdpcap("./older_trick.pcap")

icmp = [p for p in pcap if p.haslayer(ICMP)]
```
Here, I used knowledge from the previous example where we were checking if a packet had a TCP layer. Now we are interested only for packets with ICMP layer, so that is why we want to store only such packets.  

Using the interactive mode to observe the layers and attributes of the packets, we verify that the icmp request and icmp response packets contain the same data:  

![oldest trick3](/posts/scapy/oldest_trick3.png)  

If we see again the layers, we notiec an attribute called ```type```, where in the request packets it has always value 8, while on the response packets it has always 0:  

![oldest trick4](/posts/scapy/oldest_trick4.png)  

Since we are interested in the request packets (the ones with type value 8), we update our script as such to read only these packets:  

```python
from scapy.all import *

pcap = rdpcap("./older_trick.pcap")

icmp = [p for p in pcap if p.haslayer(ICMP) and p[ICMP].type == 8]
```

Now, turning back to the interactive mode, we can verify that we only have request type packets and we can notice an interesting pattern:  
```python
└─$ python -i reconstruct_zip.py
>>> icmp[0].load
b'(\xecu`\x00\x00\x00\x00\xb7\xae\x04\x00\x00\x00\x00\x00PK\x03\x04\x14\x00\x00\x00\x00\x00r\x9e\x8dRe\x9bPK\x03\x04\x14\x00\x00\x00\x00\x00r\x9e\x8dRe\x9bPK\x03\x04\x14\x00\x00\x00'
>>> icmp[1].load
b'(\xecu`\x00\x00\x00\x00\xea\xd1\x04\x00\x00\x00\x00\x00Lk\x18\x00\x00\x00\x18\x00\x00\x00\x10\x00\x00\x00fiLk\x18\x00\x00\x00\x18\x00\x00\x00\x10\x00\x00\x00fiLk\x18\x00\x00\x00\x18\x00'
>>> icmp[2].load
b'(\xecu`\x00\x00\x00\x00\x99\xe8\x04\x00\x00\x00\x00\x00ni/addons.json{"ni/addons.json{"ni/addon'
>>> icmp[3].load
b'(\xecu`\x00\x00\x00\x00\xca\xfb\x04\x00\x00\x00\x00\x00schema":6,"addonschema":6,"addonschema":'
>>> icmp[4].load
b'(\xecu`\x00\x00\x00\x00(\x18\x05\x00\x00\x00\x00\x00s":[]}PK\x03\x04\x14\x00\x00\x00\x08\x00s":[]}PK\x03\x04\x14\x00\x00\x00\x08\x00s":[]}PK'
>>> icmp[5].load
b'(\xecu`\x00\x00\x00\x00m3\x05\x00\x00\x00\x00\x00\x1d\xa3\x8dR\xec\x0f\xbb\xb6\xd0\x08\x00\x00g\n\x00\x00\x1d\xa3\x8dR\xec\x0f\xbb\xb6\xd0\x08\x00\x00g\n\x00\x00\x1d\xa3\x8dR\xec\x0f\xbb\xb6'
>>> 
>>> 
>>> icmp[0].load.index(b"PK")
16
>>> icmp[2].load.index(b"ni/addons")
16
>>> icmp[3].load.index(b"schema")
16
```

The pattern is that all interesting words (the ones that do not look like random bytes) start at index 16 of each packet and then they just repeat.  
To avoid the repetition of the data and get only the first occurance of them, we simply need to go to one packet and count how many bytes there are until the re-occurance of them:  
```python
└─$ python -i reconstruct_zip.py
>>> icmp[0].load
b'(\xecu`\x00\x00\x00\x00\xb7\xae\x04\x00\x00\x00\x00\x00PK\x03\x04\x14\x00\x00\x00\x00\x00r\x9e\x8dRe\x9bPK\x03\x04\x14\x00\x00\x00\x00\x00r\x9e\x8dRe\x9bPK\x03\x04\x14\x00\x00\x00'
>>> len(b"PK\x03\x04\x14\x00\x00\x00\x00\x00r\x9e\x8dRe\x9b")
16
>>> icmp[0].load[16:32]
b'PK\x03\x04\x14\x00\x00\x00\x00\x00r\x9e\x8dRe\x9b'
>>>
```

So the exfiltrated data from each packet start at index 16 and stop at index 32. These observations should be enough to reconstruct the exfiltrated zip archive. Let's turn back to our python script to complete it:  
```python
from scapy.all import *

pcap = rdpcap("./older_trick.pcap")

icmp = [p for p in pcap if p.haslayer(ICMP) and p[ICMP].type == 8]

exfiltrated_data = b""
for p in icmp:
	exfiltrated_data += p.load[16:32]


with open("exfiltrated_data.zip", "wb") as f:
	f.write(exfiltrated_data)
```

Running our script, we indeed get back the reconstructed zip file:  

![oldest trick5](/posts/scapy/oldest_trick5.png)  


## Summary
There are so many attributes that a packet has that it would be such an extensive post to go through all of them. The goal of this post was to simply show how can someone play around with scapy and python's interactive mode in order to easily identify the attribute of interest.  

I hope this post was of some use and that you learned something:)