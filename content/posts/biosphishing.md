+++
title = "Bios screen as a phishing technique"
draft = false
tags = ["bios"]
categories = ["Phishing"]
ShowToc = true
author = ["connar"]
+++

*Disclaimer: The research, attack chain concept, and logic presented in this post are my own. The HTML, CSS, and JavaScript used to build the  PoC template were developed with the help of Gemini.*

## Browser-to-BIOS Phishing Attack
### What is the Simulated TDR / BIOS Attack
If we look back at how browser-based phishing has evolved over the years, we can clearly see the tactics changing from basic web popups to actual user manipulation. There were old techniques from scam support centers to more modern techniques such as Clickfix, but overall here is a quick timeline of what these attacks looked like:
- **2015-2019**: Tech Support Scams (Fake BSODs). These were the web pages that went fullscreen, looped a warning siren audio, and displayed a fake Windows Blue Screen of Death, telling you to call a fake support number or scan a qr code.  


<div align="center">
  <img src="/posts/biosphishing/bsod.png" alt="bsod-image">
</div>


- **2020-2022**: Fake Updates. Groups like [SocGholish](https://attack.mitre.org/software/S1124/) started pushing fake Chrome or Firefox update pages. If you clicked download, it dropped a malicious .js file to your machine.  

<div align="center">
  <img src="/posts/biosphishing/socghost.png" alt="socghost-image">
</div>


- **2023-Present**: The "ClickFix" Era. Also known as ClearFake. I actually became a target (but not a victim) of this one recently. I got a notification about a security vulnerability on one of my GitHub repos. The link took me to a fake "GitHub Scanner" page. A popup appeared, but it didn't ask me to download a file. Instead, it told me to press Win + R, paste a PowerShell command into the Run dialog, and hit enter. 

<div align="center">
  <img src="/posts/biosphishing/clickfix.png" alt="clickfix-image">
</div>

More modern Clickfix variants led to BSOD screens, so we see some variants use combination of old and new techniques to create more custom attacks. The only "problem" with the clickfix variants though is you have to convince a user to open their terminal and paste random code, which I see as a huge behavioral leap. After all, it has become rather popular so it's not that people can fall that easy for the Win+R captcha scheme.

### Making My Own Technique
I kept seeing these new ClickFix variants and modernized fake BSODs popping up online, but I didn't see anyone trying to simulate a firmware or BIOS-level phishing technique. So, I thought of making my own.

I wanted to see if I could completely remove the command-line copying part of ClickFix (like some [clickfix variants](https://www.cloudsek.com/blog/threat-actors-lure-victims-into-downloading-hta-files-using-clickfix-to-spread-epsilon-red-ransomware)), and instead trick the user into thinking their computer's hardware crashed. If they think their hardware is failing, they are much more likely to just download and run a "driver patch" to fix it - or perhaps not, but I thought of trying to create my own technique either way.

### How it works
Basically, the concept of this technique is to emulate a Windows [GPU Timeout Detection and Recovery (TDR)](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/timeout-detection-and-recovery) event. In a real Windows system, if your graphics card hangs for 2 seconds (the timeout), the screen goes black for a second while the OS tries to restart the driver (the recovery). If it fails, you get a BSOD.

I decided to mimic this exact 2-second freeze and blackout, but instead of throwing a BSOD, I drop the user into a fake AMIBIOS screen.

> **Limitation**: *Right now, this PoC is built to only trigger if the user is using Microsoft Edge. If they use another browser, it will not work. I have a detection based on UA, since every browser handles specific parts of the chain differently and thus this is not a universal phishing solution. I still need to create specific code per browser, thus I have a "kill switch" if the browser is not Microsoft Edge - for now at least.*

#### 1. The Trigger & The 2-Second Freeze
The attack starts when the user clicks a button on our phishing page. I used a GDPR "Accept Cookies" button for the PoC - *we could of course have a random popup show with a close button or any other type of way to make the user click on it*. Clicking the button requests fullscreen mode.

The trick is that when browsers go fullscreen, they show a message at the top saying "Press ESC to exit full screen". Ideally I wanted to remove this, but didn't find a way to do so, so I had to make the user not notice it for the span of ~2 seconds (until it disappears). To do so, the moment they click the button, my javascript freezes the page and locks the mouse cursor as a "pointer" hand for 2 seconds to make the user think the website is just lagging, and around the same time I make a popup appear that displays the fake "Page Unresponsive" wait/kill dialog. By that time, the original popup (ESC) has disappeared. It is kind of a gamble of whether the user will pay attention to the ESC popup or the browser kill/wait dialog.

<div align="center">
  <img src="/posts/biosphishing/killwait.png" alt="killwait-image">
</div>

> **Limitation**: *Chrome works fine technically for this sequence, but the visual style of Chrome's native "Page Unresponsive" popup is slightly different from Edge's. To keep the PoC realistic, I hardcoded the CSS to match Edge and restricted the attack strictly to Edge users.*

#### 2. Getting the Real GPU
Since we are simulating a GPU timeout, we want to have realistic data to display to our victim. Ideally, we would like to have the GPU info of the user's machine.  

So, before the crash happens, the script runs a quick WebGL check to find out what graphics card the user actually has:
```js
const gl = canvas.getContext('webgl');
const ext = gl.getExtension('WEBGL_debug_renderer_info');
const gpuString = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
```

This gives us the string of the user's GPU (like "NVIDIA GeForce RTX 4090" or "Intel Iris Xe"). We save this so we can show it in the BIOS screen later to make it look legitimate.

#### 3. The TDR Blackout & BIOS Screen
When the user clicks "Kill Pages" on the fake unresponsive popup, the screen goes completely black for 1.2 seconds using CSS. This mimics the Windows TDR driver reset where the monitor momentarily loses signal.

When the screen turns back on, the user is inside a fullscreen AMIBIOS menu. 

> **Limitation**: *The AMIBIOS is the template I chose to use. Unfortunately, if the user has an MSI laptop for example, the bios screen should not be AMIBIOS, which will make it look suspicious. I could not find a way to discover via the phishing page of what kind of laptop the user has in order to have more templates to display based on user's system.*

The mouse is hidden using `cursor: none`, and the keys are locked using the [navigator.keyboard.lock()](https://developer.mozilla.org/en-US/docs/Web/API/Keyboard/lock) API so they can only use the Arrow keys and Enter. In the menu, they see their actual GPU model next to a red error saying `HALTED - MISSING DRIVER`.

#### 4. Payload and Startup Folder
The fake BIOS tells the user to press `Enter` to download a recovery patch. A fake DOS progress bar appears, and the browser drops a `recovery.vbs` file (you can name it however you like).

<div align="center">
  <img src="/posts/biosphishing/bios_instructions_screen.png" alt="bios_instructions_screen-image">
</div>

The user clicks it. The script runs silently in the background (no terminal pops up). It sends a ping to my local Python C2 server, which updates the browser screen to say "Patch Applied - Please Restart".

<div align="center">
  <img src="/posts/biosphishing/recovery_vbs.png" alt="recovery_vbs-image">
</div>

To get persistence without needing admin privileges, the VBScript writes a simple script into the user's Startup folder:
`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\update_success.vbs`

When the user manually restarts their PC, the payload executes. For this PoC, it just pops up a Windows message box saying "Update successful".


### Final PoC
Running the PoC in a windows VM, the victim visits a page (could be hijacked, sent as a link etc), and presses accept cookies:  

![](/posts/biosphishing/finalpoc.gif)

> *Other techniques could be used to deliver the "update" in a way to bypass MOTW or Smartscreen warnings.*

After the victim restarts the machine, we can see code execution happening via the Startup folder:

![](/posts/biosphishing/after_restart.gif)

This could be used to drop malware, achieve persistance etc. 