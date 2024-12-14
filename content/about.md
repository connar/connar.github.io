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

  /* Apply the background GIF only to the outer fieldset */
  fieldset[name="outerfieldset"] {
    background: url('/img/codegif.gif') no-repeat center center;
    background-size: cover;
    border: 1px solid #ccc;
    padding: 10px;
    position: relative;
    z-index: 2;
    color: #dcdcdc;
    font-weight: 500;
    text-align: center;
  }

  legend {
    background: black; /* Match the background to make the line stop */
    color: #dcdcdc; /* Light text color */
    padding: 5px 10px; /* Space inside the legend box */
    border-radius: 5px; /* Optional: rounded edges */
    display: inline-block; /* Prevent legend from stretching */
    position: relative;
  }


  label {
    display: flex; 
    align-items: center; /* Align the checkbox, emoji, and text */
    gap: 8px; /* Space between elements */
  }

  img {
    width: 20px; /* Set fixed size for emoji */
    height: 20px;
  }

  /* Reusable class for the semi-transparent background */
  .background-box {
    background: rgba(0, 0, 0, 0.8); /* Semi-transparent black */
    color: #dcdcdc; /* Light text color */
    padding: 5px; /* Padding for spacing */
    border-radius: 5px; /* Rounded corners */
    display: inline-block; /* Inline block for wrapping around content */
  }

  /* Base style for inner fieldsets (hidden by default) */
  fieldset[name="note1"],
  fieldset[name="note2"],
  fieldset[name="note3"],
  fieldset[name="note4"],
  fieldset[name="note5"] {
    background: rgba(0, 0, 0, 0.6);
    border: 1px solid #dcdcdc;
    padding: 10px;
    margin-top: 10px;
    border-radius: 5px;
    color: #dcdcdc;
    position: relative;
    z-index: 3;

    /* Hide by default with opacity and height */
    opacity: 0;
    max-height: 0;
    overflow: hidden;
    transition: all 0.5s ease; /* Smooth transition */
  }

  /* Show inner fieldsets */
  fieldset[name="note1"].visible,
  fieldset[name="note2"].visible,
  fieldset[name="note3"].visible,
  fieldset[name="note4"].visible,
  fieldset[name="note5"].visible {
    opacity: 1;
    max-height: 500px; /* Adjust max height based on content size */
    overflow: visible;
  }
</style>


<fieldset name="outerfieldset">
    <legend><label style="display: flex; align-items: center; gap: 8px;">
      <input type="checkbox" name="club" onchange="toggleFieldsets(this)">
      <img src="/img/cat-wizard-typing-on-a-computer.png" style="width: 8%; height: 8%;">
      <span>purpose of the blog</span>
    </label></legend>

  <fieldset name="note1">
    <legend>
      <label class="background-box">
        <input type="radio" checked name="clubtype" onchange="form.note1.disabled = !checked">
        Note 1
      </label>
    </legend>
    <p>Hi! Im connar. Im 23 and I am learning various cybersecurity topics and experimenting with different random tools I stumble upon.</p>
  </fieldset>

  <fieldset name="note2" disabled>
    <legend>
      <label class="background-box">
        <input type="radio" name="clubtype" onchange="form.note2.disabled = !checked">
        Note 2
      </label>
    </legend>
    <p>I am mainly into malware stuff (analysis and dev) but also into forensics. To be honest, I am no expert, but I am trying to apply the Feynman's technique which helps me a lot to memorize and better understand the stuff I am learning (thus, this blog).</p>
  </fieldset>

  <fieldset name="note3" disabled>
    <legend>
      <label class="background-box">
        <input type="radio" name="clubtype" onchange="form.note3.disabled = !checked">
        Note 3
      </label>
    </legend>
    <p>I also really like making CTF challenges, some of which you are going to see here in this blog:)</p>
  </fieldset>

  <fieldset name="note4" disabled>
    <legend>
      <label class="background-box">
        <input type="radio" name="clubtype" onchange="form.note4.disabled = !checked">
        Note 4
      </label>
    </legend>
    <p>This is basically a journal into my journey into cybersecurity, keeping track of what I have learned and stuff that may seem useful to any of you that are reading it. Obviously, my posts and things I read from other authors and just try to try them myself, so credits go to them:)</p>
  </fieldset>

  <fieldset name="note5" disabled>
    <legend>
      <label class="background-box">
        <input type="radio" name="clubtype" onchange="form.note5.disabled = !checked">
        Note 5
      </label>
    </legend>
    <p>That's a wrap I think. Hope you stick around, have fun:)</p>
  </fieldset>

</fieldset>

<script>
  function toggleFieldsets(checkbox) {
    // Select all the inner fieldsets by their name attributes
    const notes = [
      ...document.getElementsByName('note1'),
      ...document.getElementsByName('note2'),
      ...document.getElementsByName('note3'),
      ...document.getElementsByName('note4'),
      ...document.getElementsByName('note5'),
    ];

    // Add or remove the 'visible' class for smooth transitions
    if (checkbox.checked) {
      notes.forEach(fieldset => fieldset.classList.add('visible'));
    } else {
      notes.forEach(fieldset => fieldset.classList.remove('visible'));
    }
  }
</script>

