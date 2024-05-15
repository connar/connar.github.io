+++
title = "Another malicious doc - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

Upon decompressing the provided file, we were presented with a Word document. Opening it, we are presented with the following:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd1.png)  

Avoiding to click on “Enable Content”, we navigate to the panel where the macro code exists and see the following seemingly obfuscated VBA code:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd2.png)  

One way we can deobfuscate this is utilizing the ChatGPT AI service:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd3.png)  

Just by asking ChatGPT to deobfuscate the code, we are provided with a much more clear version of the found macros.  
Unfortunately, this will end up being a dead end and will give us no leads whatsoever about finding the flag.	
In cases like this, we should turn to tools such as “olevba”, which is a tool that automates the analysis of seemingly malicious docs and provides the artifacts found. The tool is simply run by executing the following command:
- olevba [document_name]

and can be found at:  
- https://github.com/decalage2/oletools/wiki/olevba

Running it, we get the following output:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd4.png)  

This is the code we previously found manually. At the end of the output though, we get the following summary table:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd5.png)  

The most interesting line here is the last one which refers to something called VBA stomping. Also, we get some extra output regarding the VBA stomping:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd6.png)  

But this will not lead to anywhere, since the olevba tool itself refers to VBA detection being in an experimental stage. Searching further on what VBA stomping is, we get the following references:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd7.png)  

So the results makes a reference on something called p-code. Continuing our search on how to analyze p-code of a document, we find references to the following tools:  
- https://github.com/Big5-sec/pcode2code
- https://github.com/bontchev/pcodedmp

We can download and use the first tool like:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd8.png)  

which dumped the p-code into res.txt file. Let’s open and see what is inside this file:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd9.png)  

Everytime we have to do with obfuscated code, we start with what we can reverse. We see a bunch of chr() and XOR operations which are reversable. So we will start by recovering the strings that these operators generate. We will create a python script that will compute these chr() operations and print us the result:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd10.png)  

We made some modifications to match python syntax, such as:  
- removing the space character
- replacing the “&” with “+” in order to concatenate strings
- replacing  “Xor” with “^” to make XOR operations 
- replacing capital ‘C’ to lowercase ‘c’ since pythons chr() function uses a lowercase ‘c’.  

Then, we used eval() to run the commands stored in the string. The result we end up with is “System.Security.Cryptography.ToBase64Transform”. Doing this operation for the rest of the code, we end up with:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd11.png)  

We also spot some mathematical operations, which again are easily reversable:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd12.png)  

From the resulted code, we spot that the function vwvwdew() is first executed, which calls a function called yocce(), giving it a string parameter. This function initializes some variables and objects. One of the objects it initializes is:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd13.png)  

So onixhh object is basically a System.Security.Cryptography.RijndaelManaged object. Googling what that is we find that it is an AES predecessor algorithm:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd14.png)  

So we can rename this object to AES instead. We then see that a call is being made to ltrcd function with the string we
originally passed as argument to yocce() function. Let’s see what this function does:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd15.png)  

So this function takes the string that was passed as argument and base64 decodes it. Then it gets the resulted bytes and returns them in the yocce() function. Then, yocce() function takes the resulted base64 decoded string and encrypts it:

![alt text](/posts/writeups/ctflib/anothermaldoc/amd16.png)  

It then calls frjwlq() function with the resulted encrypted string as argument:  

![alt text](/posts/writeups/ctflib/anothermaldoc/amd17.png)  

where it is base64 encoded again and returned.
So we can safely assume that the original base64 encoded string that was passed as argument originally was a base64 encoded string. Since this VBA script is trivial, there is no much more to it. Trying to decode the original base64 string that was passed early on in the code, we get the flag:  
```py
>>> from base64 import b64decode
>>> b64decode(b"Q1RGTElCe2M0MjNmdWxsXzBmXzdoM19wLWMwZDMhIX0=")
b'CTFLIB{c423full_0f_7h3_p-c0d3!!}'
>>>
```



