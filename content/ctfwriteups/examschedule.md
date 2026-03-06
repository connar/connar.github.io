+++
title = "exams schedule - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

## exams schedule writeup
This challenge provides us with an .xll file, which is basically a file used by excel as a plugin to add more functionalities, such as the one of code execution.
Thus, the .xll file must contain some code.

Running the command `file excel-εξεταστική.xll`, we might get a message saying `No such file or directory` because of the file name. Renaming it to any other name, for example `exceladdin`, we see it is a `PE32+ executable (DLL) (GUI) x86-64, for MS Windows`.

Searching more about this filetype (`xll`), we will find out it can be created by either C/C++ or with C#. In the case of C#, the analysis is much more simple as we can use tools such as ILSPy for its decompilation. Let's assume it is written in C# since this is a moer common case for xll files.

For the code retrieval we can do it either by using `pedump` ([see here how](https://connar.github.io/posts/weaponizing-xll-files/#reversing-samples-to-get-payloads)) or via a tool named `exceldna-unpack`. We will follow the second approach since its more direct.

### Step 1
We can download the tool from the releases of the following project:
- https://github.com/augustoproiete/exceldna-unpack

Since the tool needs version .NET 5, if we dont have it installed, we can install it from [here](https://aka.ms/dotnet-core-applaunch?framework=Microsoft.NETCore.App&framework_version=5.0.0&arch=x64&rid=win-x64).

### Step 2
After installing it, we run the following command on the sample:
`exceldna-unpack.exe --xllFile=exceladdin.xll`

The result is a folder with the resources of that file:
```
λ exceldna-unpack.exe --xllFile=exceladdin.xll
Excel-DNA Unpack Tool, version 2.1.0+60b3d6031babfd276f540b95f9fb298c18342a00

Analyzing exceladdin.xll . . . OK

Extracting EXCELDNA.MANAGEDHOST.dll (ASSEMBLY) . . . OK
Extracting CRACK-SOLUTION.dll (ASSEMBLY_LZMA) . . . OK
Extracting EXCELDNA.INTEGRATION.dll (ASSEMBLY_LZMA) . . . OK
Extracting EXCELDNA.LOADER.dll (ASSEMBLY_LZMA) . . . OK
Extracting __MAIN__.dna (DNA) . . . OK
```

The name `CRACK-SOLUTION.dll` seems very sus, so running the command `file` to see what filetype it is, we find the following:
```
λ file CRACK-SOLUTION.dll
CRACK-SOLUTION.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Window
```

So we are now in position to load it to ILSPy to see its code!

### Step 3
Opening the file inside ILSPy, we see it stores a huge b64 string as a zip, it then opens it and runs the file `rigged.bat` that exists inside that zip file.

![alt text](/posts/writeups/pmdk/examschedule/image2.png)  

Let's store the b64 bytes as a zip (after we decode them) and see what is inside the file `rigged.bat`:

![alt text](/posts/writeups/pmdk/examschedule/image.png)  

After we download the file as a zip and open it, we will see lots of files, where if we search what these files are, we will find out they are related to xmrig - a cryptominer for xmr.  
Opening the `rigged.bat`, we see it contains a weird string that seems like b64. Decoding it, we get the flag:

![alt text](/posts/writeups/pmdk/examschedule/image3.png)  

