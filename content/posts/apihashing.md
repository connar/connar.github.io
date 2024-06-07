+++
title = "Exploring PEB struct and its fields"
date = 2024-06-06T20:03:02+02:00
draft = false
tags = ["API Hashing","Windows API"]
categories = ["Windows","Malware"]
ShowToc = true
author = ["connar","r4sti"]
+++

## Intro
As mentioned in the <b><i>Exploring PEB struct and its fields</i></b> post, we will now see how to to use a technique known as API Hashing. API hashing is a technique used in malware to identify API functions by their hash value from their names or other attributes. This hash value can then be used instead of the function names or other attributes to enumerate, rehash, compare and use functions based on the hash value. This way, direct calls by function names is avoided and thus leads to fewer detection rates.  

## How it works
A hash function is applied to the API function name. For example, a simple hash function might take the string ```CreateFileA``` and produce a hash value such as ```0xA1B2C3D4```.

## Runtime Resolution
When the program runs, it will compare the hash values of available API functions with the precomputed hash values. When a match is found, the corresponding function is called, thus avoiding the direct call (hardcoded use) of the name. 


In the following code that will be showcased, we will break down how to find all the functions inside a given DLL and loop through them until we get a hit for a hash value comparison. The hash we will be comparing with will be that of the MessageBoxA, and when the match will be found, we will call this function.


## Code
We will explain one part at a time, slowly building up the code that will execute a MessageBoxA function without using the direct name.

### Checking for DLL argument
The executable will take as argument the DLL that we want the MessageBoxA function from, and specifically the user32.dll. So our code starts by checking if an argument has been given and if so, it stores it in a variable:
```c
int main(int argc, wchar_t* argv[])
{
    if (argc != 2) {
        wprintf(L"Usage: %s <target_dll_name>\n", argv[0]);
        return 1;
    }
    // Get the DLL passed as argument, for example user32.dll
    wchar_t* targetDllName = argv[1];

    /* -- more -- */
}
```

### Loading the DLL in memory
After the Dll argument has been given, we check with ```GetModuleHandleA``` if the DLL is already loaded in memory. If not, ```GetModuleHandleA``` will have returned NULL and so we will use ```LoadLibraryA``` to load this DLL in memory:
```c
int main(int argc, wchar_t* argv[])
{
    if (argc != 2) {
        wprintf(L"Usage: %s <target_dll_name>\n", argv[0]);
        return 1;
    }
    // Get the DLL passed as argument, for example user32.dll
    wchar_t* targetDllName = argv[1];

    // Get a handle for this dll
    HMODULE hModule_of_arg_dll = GetModuleHandleA((LPCSTR)targetDllName);

    // If it is not loaded in memory, load it now
    if (hModule_of_arg_dll == NULL) {
        hModule_of_arg_dll = LoadLibraryA(targetDllName);
    }
}
```
We cast the targetDllName to (LPCSTR) since the GetModuleHandleA accepts this type of parameter:
```c
GetModuleHandleA(
    _In_opt_ LPCSTR lpModuleName
    );
```
**We can always CTRL+click on the function's name to see its definition and type parameters.**

### API Hashing - Finding the function via hash
Now this is the part of the juicy code that enumerates through all the DLL's functions and searches for a hash match. In this code, we pre-computed the hash value of the MessageBoxA function of user32.dll. So we basically pass the user32.dll as parameter to the program, and then program tries to find a match of a function inside user32.dll whose hash is the same as the precomputed hardcoded one we compare with.

Let's start analyzing. We first call the GetProcAddressH which is a custom function that passes as arguments the handle of the previously loaded DLL, and the hash of the MessageBoxA (MessageBoxA_HASH) we precomputed:  
```c
#define MessageBoxA_HASH    0xF10E27CA

typedef int (*PfnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main(int argc, wchar_t* argv[])
{
    if (argc != 2) {
        wprintf(L"Usage: %s <target_dll_name>\n", argv[0]);
        return 1;
    }
    // Get the DLL passed as argument, for example user32.dll
    wchar_t* targetDllName = argv[1];

    // Get a handle for this dll
    HMODULE hModule_of_arg_dll = GetModuleHandleA((LPCSTR)targetDllName);

    // If it is not loaded in memory, load it now
    if (hModule_of_arg_dll == NULL) {
        hModule_of_arg_dll = LoadLibraryA(targetDllName);
    }

    // Getting the address of MessageBoxA function using GetProcAddressH
    PfnMessageBoxA pMessageBoxA = (PfnMessageBoxA)GetProcAddressH(hModule_of_arg_dll, MessageBoxA_HASH);
    if (pMessageBoxA == NULL) {
        printf("[!] Couldn't Find Address Of Specified Function \n");
        return -1;
    }
```
We also cast to PfnMessageBoxA. This is because our GetProcAddressH as we will see shortly returns a pointer to the address of the matching hashed function. So since we get back a pointer to an address, we cast to the corresponding type of data this address contains, which is of fnMessageBoxA type.  

One side note here is that the PfnMessageBoxA is not the actual MessageBox. The actual MessageBox has the following struct:
```c
int MessageBox(
  [in, optional] HWND    hWnd,
  [in, optional] LPCTSTR lpText,
  [in, optional] LPCTSTR lpCaption,
  [in]           UINT    uType
);
```
so we just defined our own same data struct.

#### Hash function
Before we finally dive into the GetProcAddressH to see the process of API Hashing, let's see the hash function that will be used first:  
```c
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#define INITIAL_SEED	7	

// Generate JenkinsOneAtATime32Bit hashes from Ascii input string
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenA(String);

    while (Index != Length)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
```
This is just one hash function that can be used. It was taken from [the VX Underground repo](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp). You could use whatever function you want.  

We also define a shorter name for this function, HASHA, which takes as a parameter the API (the function) that the code will hash. We also cast the parameter (API) to (PCHAR) since the ```HashStringJenkinsOneAtATime32BitA``` takes as a parameter a (PCHAR) string.


#### GetProcAddressH - Load, Hash, Compare, Repeat
The code responsible for loading the functions of the given dll, hashing them and comparing with the hardcoded precomputed value, is the following:  
```c
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER         pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS         pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER     ImgOptHdr = pImgNtHdrs->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY   pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    PDWORD  FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD  FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD   FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // Hashing every function name pFunctionName
        // If both hashes are equal then we found the function we want 
        if (dwApiNameHash == HASHA(pFunctionName)) {
            return pFunctionAddress;
        }
    }

    return NULL;
}
```
This code, besides the hashing part, mostly does checks on the PE fields to make sure everything is correct before continuing. This is usually what malwares do to make sure they will definitely run on the victim's machine and would ideally not want to risk running on some error on runtime.  

We can break down the checks and make a short introductory on loading a PE file on memory, but a more [in depth post]() will be posted in the future regarding this.  

**To begin with**, we make sure that neither the handle to the DLL's address nor the Hash of the target function that are passed as parameters are null:
```c
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;
    
    PBYTE pBase = (PBYTE)hModule;
    /* -- more -- */
}
```

**Continuing on**, we cast the pBase (Which is just the handle to the address of the DLL) to ```PIMAGE_DOS_HEADER```:
```c
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;
    
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;


    /* -- more -- */
}
```
Why? Well, the handle just currently points to a memory address. This memory address contains the bytes of the DLL. These bytes are not just "bytes" but they represent fields of a struct - specifically that of an IMAGE_DOS_HEADER, since DLL's such as EXE start with this struct.  
In other words, the address where the pBase has is the memory address of a series of bytes, that when casted to ```PIMAGE_DOS_HEADER``` (since this is the appropriate starting struct for a DLL) gives us access to its fields:  

![does header](/posts/apihashing/apihashing1.png)  

This cast to ```PIMAGE_DOS_HEADER``` which is the top header of the DLL gives us all we need to calculate the addresses of the rest of the headers, as we will see shortly.

The code, after casting to the appropriate data structure, checks if the e_magic is equal to IMAGE_DOS_SIGNATURE. The IMAGE_DOS_SIGNATURE is actually ```MZ```, and thus, the e_magic is always ```MZ``` for an executable/dll file. The full struct of ```IMAGE_DOS_HEADER``` that contains this field is the following:  
```c
typedef struct _IMAGE_DOS_HEADER
{
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

**After the validation for the MZ header**, we use the pBase (the base address of our dll) in combination with a field of the ```IMAGE_DOS_HEADER``` struct to calculate the VA (Virtual Address) of the IMAGE_NT_HEADERS struct, which is the third header seen in the previous image ('NT Headers'):  
```c
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;
    
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    /* -- more -- */
}
```
The field used here from the ```IMAGE_DOS_HEADER``` is the e_lfanew field, which is also known as RVA (Relative Virtual Address). Basically the relationship between the base address, RVA and VA goes as the following:
- **Base address**: This is an address in memory that acts as the starting point. It simply is where something initially was saved at. Here our DLL was loaded at an address which we have stored in our pBase variable.
- **RVA**: Relative Virtual Address is like an offset of some field of our DLL. Basically, the DLL contains many stucts and instead of storing the address of each one, we just use the base address of our DLL (where it starts) and an offset, which is how far away is from the starting point (baseAddress).
- **VA**: Virtual Address is the actual address (starting point) of the field/struct we want to land on.

**In summary: baseAddress + RVA[something] = VA[something]**

So, here the e_lfanew is the offset of the DLL's base address to the NT_HEADER struct. By adding the base address of our DLL with this field, we get the VA (actual address) of the NT_HEADER struct that we can now cast to the corresponding type and gain access to its fields.

The struct of the IMAGE_NT_HEADERS is the following:
```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```
The Signature we are doing the check with is actually the 'PE' that executables and DLL's have. This is just another check the program does before proceeding forward with the API Hashing.

**Moving further**, it is now time to finally get the function names, their addresses and their ordinals (integer numbers representing the functions):
```c
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER         pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS         pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER     ImgOptHdr = pImgNtHdrs->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY   pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    PDWORD  FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD  FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD   FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    /* -- more -- */
```
The code continues with using the ImgOptHdr we previously calculated in order to load the necessary fields and structs that contain the information we are aiming for. But what is the ImgOptHdr and what useful info does it contain?  
It's struct is the following (IMAGE_OPTIONAL_HEADER):  
```c
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

In the code we utilized the DataDirectory table field and specifically the index named 'IMAGE_DIRECTORY_ENTRY_EXPORT'. Taking a look at what the IMAGE_DATA_DIRECTORY struct contains, we see the following:  
```c
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
So basically the DataDirectory field is a table that contains structs with fields a VirtualAddress and Size. In our code we used the index IMAGE_DIRECTORY_ENTRY_EXPORT and that led us to a _IMAGE_DATA_DIRECTORY with a VirtualAddress - since this is what we are taking with the '->' symbol - and Size. But why we used the specific index and why does this can be casted back to IMAGE_EXPORT_DIRECTORY?  
We simply CTRL+click onto the index and see the following:  
```c
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```
So the IMAGE_DIRECTORY_ENTRY_EXPORT is equal to 0 (the first entry) and it basically points to the Export directory. Awesome! That is the reason we cast the result back to IMAGE_EXPORT_DIRECTORY.  

Taking a look at the IMAGE_EXPORT_DIRECTORY struct, we see the following fields:  
```c
 typedef struct _IMAGE_EXPORT_DIRECTORY {
     DWORD   Characteristics;
     DWORD   TimeDateStamp;
     WORD    MajorVersion;
     WORD    MinorVersion;
     DWORD   Name;
     DWORD   Base;
     DWORD   NumberOfFunctions;
     DWORD   NumberOfNames;
     DWORD   AddressOfFunctions;     // RVA from base of image
     DWORD   AddressOfNames;         // RVA from base of image
     DWORD   AddressOfNameOrdinals;  // RVA from base of image
 };
```
As the comments explain, the AddressOfFunctinos, AddressOfNames and AddressOfNameOrdinals are RVA's from the base address. So this is why we once again use pBase plus these to get the VA (the actual address) of these fields.  

**Finally**, we loop through the function names and ordinals of each function, hash each one and compare with our target hash:  
```c
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER         pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS         pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER     ImgOptHdr = pImgNtHdrs->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY   pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    PDWORD  FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD  FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD   FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
    CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
    PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

    // Hashing every function name pFunctionName
    // If both hashes are equal then we found the function we want 
    if (dwApiNameHash == HASHA(pFunctionName)) {
        return pFunctionAddress;
    }
}

return NULL;
```
Things to note here is that the VA of FunctionNameArray and FunctionAddressArray are arrays that contain RVA's, so that's why we again use pBase for the calculations of the actual addresses.  
Finally, we use the hashing of the function's name and comparisson with the target hash.  

The full code is the following:  
```c
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>


#define INITIAL_SEED	7	

// Generate JenkinsOneAtATime32Bit hashes from Ascii input string
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenA(String);

    while (Index != Length)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))

#define MessageBoxA_HASH    0xF10E27CA


typedef int (*PfnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

// this is the ldr struct
/*typedef struct _PEB_LDR_DATA_full
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA_full, * PPEB_LDR_DATA_full;

// this is the ldr module. Basically it refers to the information of a dll entry to ldr_module_table
typedef struct _LDR_MODULE_full {
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   BaseAddress;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;

} LDR_MODULE_full, * PLDR_MODULE_full;*/

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER         pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS         pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER     ImgOptHdr = pImgNtHdrs->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY   pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    PDWORD  FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD  FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD   FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // Hashing every function name pFunctionName
        // If both hashes are equal then we found the function we want 
        if (dwApiNameHash == HASHA(pFunctionName)) {
            return pFunctionAddress;
        }
    }

    return NULL;
}

int main(int argc, wchar_t* argv[])
{
    if (argc != 2) {
        wprintf(L"Usage: %s <target_dll_name>\n", argv[0]);
        return 1;
    }
    // Get the DLL passed as argument, for example user32.dll
    wchar_t* targetDllName = argv[1];

    // Get a handle for this dll
    HMODULE hModule_of_arg_dll = GetModuleHandleA((LPCSTR)targetDllName);

    // If it is not loaded in memory, load it now
    if (hModule_of_arg_dll == NULL) {
        hModule_of_arg_dll = LoadLibraryA(targetDllName);
    }

    // Getting the address of MessageBoxA function using GetProcAddressH
    PfnMessageBoxA pMessageBoxA = (PfnMessageBoxA)GetProcAddressH(hModule_of_arg_dll, MessageBoxA_HASH);
    if (pMessageBoxA == NULL) {
        printf("[!] Couldn't Find Address Of Specified Function \n");
        return -1;
    }

    // Calling MessageBoxA
    pMessageBoxA(NULL, "Avoiding names - executing functions", ":)", MB_OK | MB_ICONEXCLAMATION);

    printf("[#] Press <Enter> To Quit ... ");
    getchar();


    return 0;

}
```

and the result upon execution is:  
![successful msgbox](/posts/apihashing/apihashing1.png)  