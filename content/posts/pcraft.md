+++
title = "Exploring the pCraft tool"
date = 2024-03-11T20:03:02+02:00
draft = false
tags = ["pcraft", "pcap", "yaml", "ami"]
categories = ["Network-traffic"]
ShowToc = true
author = ["connar"]
+++

<style>
	fieldset {
		background: url('/img/test.gif') no-repeat center center;
		background-size: cover;
		border: 1px solid #ccc;
		padding: 10px;
		position: relative;
		z-index: 2;
		color: #dcdcdc;
		font-weight: 500;
	}
</style>

## What is the pCraft tool
pCraft is a tool used to generate pcaps based on a scenario written in an ami file. The generated pcap file can then be used for the testing of rules etc.



## Installation
To install the tool, you can either clone it from its github repo:
-   https://github.com/DevoInc/pCraft

or by using docker.  
I had some issues when running the tool from the github repo (dependency errors with the pyami module), so I went with the docker option instead, which is what I will demonstrate.  

In summary, we need to run the following commands:

```json
{
  "1) systemctl start docker":"Starts docker",
  "2) sudo docker pull sightingdb/pcraft":"Pulls the docker image of the tool",
  "3) docker run --name pcraft -d sightingdb/pcraft":"Runs the tool",
  "4) docker ps -a":"Finds the ID of the docker process running the tool",
  "5) docker exec -it {ID} bash":"Executes the container in bash (meaning we get a shell inside the docker container)"
}
```

After that, we should be inside the docker container and run the tool without any errors:
```sh
builder@4079f88d957d:~/pcraft$ ls
'#hello.ami#'   ami                   dns.ami    parsuricata   pyami.cpython-38-x86_64-linux-gnu.so   setup.py
 LICENSE        amigraph.py           dns.pcap   pcraft        requirements.txt                       tests
 README.md      build-pluginsdoc.py   doc        pcrafter      samples                                tools
builder@4079f88d957d:~/pcraft$ ./pcrafter
Syntax: ./pcrafter script.ami output.pcap
```

## script.ami
The .ami file contains actions that will be triggered and displayed inside the generated .pcap file. These actions can contain anything you see on a network traffic, like DNS queries, data being transfered, TCP handshakes etc.  

### Example of an ami file
An example of a .ami file is the following:  
```ami
ami_version 1

$victimip = "192.168.0.55"
$fakebankip = "185.199.108.153"

action DnsRequest {
        $ip-src = $victimip
        $ip-dst = $fakebankip
        $domain = "mikrosoft.com"
        exec DNSConnection
}

action PostData {
        exec HTTPConnection
        $method = "POST"
        $client-content-type = "application/x-www-form-urlencoded"
        $client-content = "login=Alfred.Wallace@example.com&password=qwerty1234"
}
```
This will basically trigger a DNS request and the resolved domain will be "mikrosoft.com" (you could set up a rule to detect such names later as we will see).  
Afterwards, we specify that a PostData action will take place which basically transfers some data - and specifically some user credentials.  

### Generating a pcap file based on an ami scenario
Let's see that in action:
```sh
builder@4079f88d957d:~/pcraft$ ./pcrafter dns.ami dns.pcap
All plugins loaded!
Opening Script File dns.ami
Executing action DnsRequest using DNSConnection

Executing action PostData using HTTPConnection

HTTP Method:POST
builder@4079f88d957d:~/pcraft$
```
We copy over to our localhost the  dns.pcap to view it in wireshark and then open it:
```sh
┌──(connar㉿kali)-[~/blog/pcraft_tool]
└─$ docker cp 4079f88d957d:/home/builder/pcraft/dns.pcap .
└─$ wireshark dns.pcap&
```
The result is the following pcap:  
```sh
└─$ tshark -r dns.pcap
    1 Mar 16, 2024 21:30:18.468122000 EET 192.168.0.55 → 1.1.1.1      DNS 73 Standard query 0x0000 A mikrosoft.com
    2 Mar 16, 2024 21:30:18.468536000 EET      1.1.1.1 → 192.168.0.55 DNS 102 Standard query response 0x0000 A mikrosoft.com A 185.199.108.153
    3 Mar 16, 2024 21:30:18.469148000 EET 192.168.0.55 → 185.199.108.153 TCP 54 9279 → 80 [SYN] Seq=0 Win=8192 Len=0
    4 Mar 16, 2024 21:30:18.469714000 EET 185.199.108.153 → 192.168.0.55 TCP 54 80 → 9279 [SYN, ACK] Seq=0 Ack=0 Win=8192 Len=0
    5 Mar 16, 2024 21:30:18.470133000 EET 192.168.0.55 → 185.199.108.153 TCP 54 9279 → 80 [ACK] Seq=1 Ack=0 Win=8192 Len=0
    6 Mar 16, 2024 21:30:18.470577000 EET 192.168.0.55 → 185.199.108.153 HTTP 311 POST / HTTP/1.1  (application/x-www-form-urlencoded)
    7 Mar 16, 2024 21:30:18.471097000 EET 192.168.0.55 → 185.199.108.153 TCP 54 80 → 9279 [ACK] Seq=1 Ack=1 Win=8192 Len=0
    8 Mar 16, 2024 21:30:18.471399000 EET 185.199.108.153 → 192.168.0.55 HTTP 268 HTTP/1.1 200 OK  (text/html)
```

Opening it in Wireshark, we get the following:  
![First ami dns](/posts/pcraft_imgs/wireshark_dns1.png)


<fieldset class="fieldset-wrapper">
	<center><legend><b>Note</b></legend></center><br>
	<p><b>We can remove this <i> &lt;html&gt;&lt;body&gt;Hello, you!&lt;/body&gt;&lt;/html&gt; </i> by going to <strong>pCraft/build/lib/pcraft/plugins/HTTPConnection.py</strong> or generally modifying it to our liking.</b></p>
</fieldset> 


## Testing suricata rules on custom pcap
As I mentioned earlier, pcraft is a great tool at making your own pcaps and testing rules upon them.  In this part of the post, we are going to follow up on the example of the *Red Team Village (see references)* and create our own suricata rule, ami file and then generate a pcap and use tcpreplay to test if our rule is successful upon the generated custom network file.

### Create the ami file (newsuricata.ami)
The ami file we will use is the following:
```ami
ami_version 1

action TriggerSuricata {
	exec Suricata
	$ip-src = "172.17.0.2"
	$ip-dst = "185.199.108.153"
	$rule = """alert dns any any -> any any (msg:"DNS Query GrayHat"; dns_query; content:"grayhat"; nocase; sid:20200809; rev:1;)"""
}
```


<fieldset class="fieldset-wrapper">
	<center><legend><b>Note</b></legend></center><br>
	<p><b>We see that we exec Suricata. This file contains a domain called "GrayHat" as we will later see, so it uses this name as the $domain variable.</b></p>
</fieldset> 


### Create the Suricata rule (mydns.rule)
The Suricata rule is a very simple one:
```suricata
alert dns any any -> any any (msg:"DNS Query Grayhat"; dns_query; content:"grayhat"; nocase; sid:20201020; rev:1;)
```

It basically listens on all interfaces to find a dns query that contains the domain name "Grayhat".

### Testing our rule
Now that we have both the ami and the rule files ready, let's generate the pcap file like we've seen previously:
```sh
builder@4079f88d957d:~/pcraft$ ./pcrafter newsuricata.ami new.pcap
```
The generated pcap is just a pcap that makes dns queries for the domain "Grayhat":
```sh
builder@4079f88d957d:~/pcraft$ tshark -r new.pcap 
    1   0.000000   172.17.0.2 ? 1.1.1.1      DNS 67 Standard query 0x0000 A grayhat
    2   0.000409      1.1.1.1 ? 172.17.0.2   DNS 90 Standard query response 0x0000 A grayhat A 185.199.108.153
```

Now that we have a successfully generated pcap, let's set up a listener with suricata (note that you must run the following as root user):
```sh
root@4079f88d957d:/home/builder/pcraft# suricata -S mydns.rule -i eth0
    17/3/2024 -- 15:22:28 - <Notice> - This is Suricata version 5.0.3 RELEASE running in SYSTEM mode
    17/3/2024 -- 15:22:28 - <Warning> - [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to set feature via ioctl for 'eth0': Operation not permitted (1)                                                                                
    17/3/2024 -- 15:22:28 - <Warning> - [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to set feature via ioctl for 'eth0': Operation not permitted (1)                                                                                
    17/3/2024 -- 15:22:28 - <Warning> - [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to set feature via ioctl for 'eth0': Operation not permitted (1)                                                                                
    17/3/2024 -- 15:22:28 - <Notice> - all 5 packet processing threads, 4 management threads initialized, engine started
```


Then, we can just use tcpreplay with our previously generated pcap to replicate the traffic:
```sh
builder@4079f88d957d:~/pcraft$ tcpreplay -i eth0 new.pcap 
Warning in interface.c:get_interface_list() line 93:
May need to run as root to get access to all network interfaces.

Fatal Error in sendpacket.c:sendpacket_open() line 544:
 failed to open device eth0: socket: Operation not permitted
builder@4079f88d957d:~/pcraft$ sudo tcpreplay -i eth0 new.pcap 
Actual: 2 packets (157 bytes) sent in 0.000455 seconds
Rated: 345054.9 Bps, 2.76 Mbps, 4395.60 pps
Flows: 2 flows, 4395.60 fps, 2 flow packets, 0 non-flow
Statistics for network device: eth0
        Successful packets:        2
        Failed packets:            0
        Truncated packets:         0
        Retried packets (ENOBUFS): 0
        Retried packets (EAGAIN):  0
```

Now, moment of truth! Let's see what has been written on /var/log/suricata/fast.log which basically contains alerts that get triggered based on matching suricata rules.  
```sh
root@4079f88d957d:/home/builder/pcraft# cat /var/log/suricata/fast.log 
03/17/2024-15:23:28.882746  [**] [1:20201020:1] DNS Query Grayhat [**] [Classification: (null)] [Priority: 3] {UDP} 172.17.0.2:4096 -> 1.1.1.1:53
```

Aaaaaand we got a successful alert! Isn't this great?  
pCraft seems like a great tool to play around and dive deeper into rules and custom traffic. I will definitely use this tool for training and maybe I'll come back in the future with an extensive senario to take a look together.  

Until next time everyone!

**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://isc.sans.edu/diary/Generating+PCAP+Files+from+YAML/25464">Sans Technology Institute: <i>Generating PCAP Files from YAML</i></a></li>
        <li> [2] <a href="https://github.com/DevoInc/pCraft">github: <i>pCraft repo</i></a></li>
        <li> [3] <a href="https://www.youtube.com/watch?v=uAwEmcq2604">Red Team Village: <i>Attacking Networks with pCraft</i></a></li>
    </ul>
</blockquote>