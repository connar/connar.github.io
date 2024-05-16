+++
title = "captcha 4 humans - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

For this challenge you would normally fire up a docker instance that unfortunately you can't have access at the time, but the py script that runs on the server is provided to you in case you need to run it locally. Now, onto the chall!  


The concept of this challenge is about rainbow table attacks. The user is given the 5 first characters of an md5 hash of a random hex string. The goal is to compute all possible md5 hashes and construct a dictionary with key being the 5-characters start of the hash and value being the original string. Basically, this challenge’s code is its solution.

### Exploitation  
Connecting with netcat to the challenge,we get the following:  
```
┌──(aastro㉿kali)-[~/ecsc/ctflib/challenge]
└─$ nc protons.ddns.net 50769
Enter a string in hex whose md5 hash starts with: "00713"
```

Since it asks for a string whose hash begins with ‘xxxxx’.length  5 and since it says the string is in hex, we come to the conclusion that all possible combinations are finite, meaning we can compute all possible combinations and match the correct one. All possible combinations are 16^5 = 1.048.576 .This is because we want to compute all possible combinations to get the correct first 5 characters of the hash, and since we are talking about hex, every character can be from 0 – F.  

Now to the solution.  

We know how many combinations we need to calculate. So we need to make a loop which computes a new md5 hash combination of a random hex string each time. These hex strings are unique each time. In every loop, we store the first 5 characters as a key to a dictionary and the corresponding value to that key will be the original string from which these 5 characters came from. We need to make it this way so when the challenge asks for the beginning of a hashed string, we will simply pass to our script the start of the hash that is given, and we will get back the corresponding string.  

Let’s see the script:  
- Lines 2.3 : We import the necessary libraries.
- Line 4 : We create our dictionary.
- Line 5 : We start the loop. We want the loop to run until the length of the dictionary reaches the value of fffff (which is the value we calculated before) so we get all the possible combinations.
- Line 6 : From the documentation

![alt text](/posts/writeups/ctflib/captcha4humans/captcha1.png)  

This way we start calculating the hex values.  

- Line 7,8 : We initialize a variable that will be used for hashing, and we pass it the hex value we just calculated.
- Line 9 : We then take the first 5 characters of the hashed string and pass them to a variable that will be used as a key.
- Line 10 : We create a key-value pair in our dictionary with key being the previous 5 characters from the hashed value and value being the original string before being hashed.
- Lines 11,12,13,14 : These are used to find the corresponding value of the key given.  

So lets run the challenge and our script :  

![alt text](/posts/writeups/ctflib/captcha4humans/captcha2.png)  

In the left, we have the challenge running, and in the right we have our script. Passing the start of the hashed string to our script, we get the corresponding string to this hashed start. So, we turn back to the challenge and pass the string that we got from our script, which is the correct one so we get the flag:  

![alt text](/posts/writeups/ctflib/captcha4humans/captcha3.png)  