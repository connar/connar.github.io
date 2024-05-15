+++
title = "Sloppy Encryptor - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

# This is a writeup for the sloppy encryptor challenge

We are given an encrypted file containing unreadable text and the file used to produce it.

```
The encrypted text is: jkfdhlhfggkdekgkjfgkkgehhjjeflefgekiifehmmifdjigeldedleghhlejgeefehdeeffdkefefhkmiffkiefemeedemkmmehiidegjefefgfeefejfiifdmhlfdlidfifefieii
```

```py
'''
The file that created it is:
'''

from random import randint as rint
from secret_stuff import FLAG

def encrypt(FLAG):
    return "".join([str(ord(c))+str(rint(126, 254)) for c in FLAG])

def toBytes(enc):
    return "".join([chr(int(enc[i])+100) for i in range(len(enc))])

with open("./flag.enc","w") as f:
    enc = encrypt(FLAG)
    enc_ = toBytes(enc)
    f.write(enc_)

```

### Text encryption process

We can distinguish that the original code that encrypted the text performs the following steps:  
1. Takes each character of the plaintext and converts it to the corresponding ASCII number.  
2. Converts this ASCII number from integer type to string type.  
3. Adds a random number in the range [126, 254]. That is, let p be the initial number of the plaintext and r be the random number in [126, 254]. Then c = 'p' + 'r' = 'pr' the corresponding encrypted character.  

The above encryption method does nothing more than insert random numbers between each character of the original text.  

Afterwards, the modified text undergoes further modification with the function toBytes(), where this function does the following:  
1. Takes each number of the modified text and adds 100 to it. That is, let i be the corresponding number of the i-th letter of the modified text. Then i' = i + 100.  
2. Takes the corresponding representation of this number in character.  
3. Joins the result characters into a single string and returns it.  

### Decrypting the encrypted thext process  
A first step for decrypting the encrypted text is to subtract 100 from each character. This is desirable because during the encryption process, the number 100 was added to each character.  

```py
'''
We open the encrypted text and subtract the number 100 from each decimal representation of each character.
'''

with open("../flag.enc","r") as f:
    enc = f.read()

flag_enc = "".join([str(ord(i)-100) for i in enc])
print(flag_enc)
```

The result of the above process is as follows:
```
> python decryptor.py
702187616365133711791231715224295148531981082374821411215311217812125395148511801101269924050170121140112149552194815950192125143
```

Since we know that the flag format is FLAG{} and we know that the encryption algorithm adds random numbers between each character in the range [126, 254], we can easily distinguish some letters. Let's look at the first 10 digits of the previous result:  
```
7021876163
--> 70 was the first character.
Then a three-digit random number was added between it and the 2nd character.
--> 218 is the random number added between them.
Then follows the next character of the original text.
--> 76
Then follows the next random number.
--> 163
...

If we take the representation of the numbers corresponding to the first 2 characters of the original text, we will see that:  
1) chr(70) --> 'F'  
2) chr(76) --> 'L'  
It kinda reminds us of the flag format ('FLAG').  
```

The process is very simple for recovering the original text and can be automated. One way to do this is the following program, but everyone can create their own:  

```py
def getNum(start, end, flag):
    flag = "".join(flag)
    return flag[start:end]

with open("../flag.enc","r") as f:
    enc = f.read()

flag_enc = "".join([str(ord(i) - 100) for i in enc])

flag_dec = []
start = 0
end = 3
flag_enc = list(flag_enc)
while flag_enc:
    enc = getNum(start, end, flag_enc)

    if int(enc) > 0xff:
        end = 2
        continue

    if int(enc) < 126:
        flag_dec.append(int(enc))
        flag_enc = list(flag_enc)
        del flag_enc[start: end]
        end = 3
    else:
        del flag_enc[start: end]
    
print("".join([chr(i) for i in flag_dec]))
```

Running the script, we get the flag:  
```
> python decryptor.py
FLAG{4_5l0ppy_3nc2yp702}
```
