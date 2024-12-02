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
    "Age": "23"
}

```
<style>
.glitch-wrapper {
   width: 100%;
   height: 100%;
   display: flex;
   align-items: center;
   justify-content: center;
   text-align: center;
}

.glitch {
   position: relative;
   font-size: 120%;
   letter-spacing: 1px;
   z-index: 1;
}

.glitch:before,
.glitch:after {
   display: block;
   content: attr(data-text);
   position: absolute;
   top: 0;
   left: 0;
   opacity: 0.8;
}

.glitch:before {
   animation: glitch-it 0.8s cubic-bezier(0.25, 0.46, 0.45, 0.94) both infinite;
   color: #00FFFF;
   z-index: -1;
}

.glitch:after {
   animation: glitch-it 0.8s cubic-bezier(0.25, 0.46, 0.45, 0.94) reverse both infinite;
   color: #FF00FF;
   z-index: -2;
}

tr {
  color: #a072b7;
}

@keyframes glitch-it {
   0% {
      transform: translate(0);
   }
   20% {
      transform: translate(-0.6px, 0.6px);
   }
   40% {
      transform: translate(-0.6px, -0.6px);
   }
   60% {
      transform: translate(0.6px, 0.6px);
   }
   80% {
      transform: translate(0.6px, -0.6px);
   }
   to {
      transform: translate(0);
   }
}
</style>

<div class="glitch-wrapper">
  <h2><div class="glitch" data-text="whoami" style="color: #46473e;">whoami</div></h2>
</div>

<div style="text-align: center;">
  <div class="glitch-wrapper">
    <table style="margin: auto; width: 100%; table-layout: fixed;">
        <tr>
          <!-- First column with 20% width -->
          <td style="width: 20%; text-align: center;">
            <center><img src="/img/alien-typing-on-computer.png" style="width: 80%; height: 80%;"></center>
          </td>
          <!-- Second column with 80% width -->
          <td style="width: 80%;">
            <div class="glitch" data-text="Hi! Im connar. Im 23 and I am learning various cybersecurity topics and experimenting with different random tools I stumble upon.">Hi! Im connar. Im 23 and I am learning various cybersecurity topics and experimenting with different random tools I stumble upon.</div>
          </td>
        </tr>
        <tr>
          <td style="width: 20%; text-align: center;">
            <center><img src="/img/cat-wizard-typing-on-a-computer.png" style="width: 80%; height: 80%;"></center>
          </td>
          <td style="width: 80%;">
            <div class="glitch" data-text="I am mainly into malware stuff (analysis and dev) but also into forensics. To be honest, I am no expert, but I am trying to apply the Feynman's technique which helps me a lot to memorize and better understand the stuff I am learning (thus, this blog).">I am mainly into malware stuff (analysis and dev) but also into forensics. To be honest, I am no expert, but I am trying to apply the Feynman's technique which helps me a lot to memorize and better understand the stuff I am learning (thus, this blog).</div>
          </td>
        </tr>
        <tr>
          <td style="width: 20%; text-align: center;">
            <center><img src="/img/hacker-with-computer.png" style="width: 80%; height: 80%;"></center>
          </td>
          <td style="width: 80%;">
            <div class="glitch" data-text="I also really like making CTF challenges, some of which you are going to see here in this blog:)">I also really like making CTF challenges, some of which you are going to see here in this blog:)</div>
          </td>
        </tr>
        <tr>
          <td style="width: 20%; text-align: center;">
            <center><img src="/img/wizard-typing-on-a-computer.png" style="width: 80%; height: 80%;"></center>
          </td>
          <td style="width: 80%;">
            <div class="glitch" data-text="This is basically a journal into my journey into cybersecurity, keeping track of what I have learned and stuff that may seem useful to any of you that are reading it. Obviously, my posts and things I read from other authors and just try to try them myself, so credits go to them:)">This is basically a journal into my journey into cybersecurity, keeping track of what I have learned and stuff that may seem useful to any of you that are reading it. Obviously, my posts and things I read from other authors and just try to try them myself, so credits go to them:)</div> 
          </td>
        </tr>
        <tr>
          <td style="width: 20%; text-align: center;">
            <center><img src="/img/hacker-typing-on-a-computer.png" style="width: 80%; height: 80%;"></center>
          </td>
          <td style="width: 80%;">
            <div class="glitch" data-text="That's a wrap I think. Hope you stick around, have fun:)">That's a wrap I think. Hope you stick around, have fun:)</div>
          </td>
        </tr>
    </table>
  </div>
</div>

