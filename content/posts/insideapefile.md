+++
title = "Inside a PE file"
date = 2024-06-12T20:03:02+02:00
draft = false
tags = ["PE"]
categories = ["Windows","Malware"]
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
In this post we will observe the fields a Portable Executable file (PE or also known as Image) has, how are they connected to each other and how can they be utilized to load addresses of functions, names of functions and ordinals - amongst other fields - by writing a program that reads and loads these parts of an executable. The executable we will be disassecting will be mspaint.exe.

A few examples of files that have this PE format are files like .exe, .dll, .sys and .scr.

## Address types
Before proceeding, we need to provide some useful information about different type of addresses:
- ```Raw address```: Raw address is an offset in the PE file. For example, PE[0x3C] will point to some other address.
- ```Base Address```: Base Address is the actual address of where a PE file is loaded.
- ```Relative Virtual Addresses```: Relative Virtual Addresses are relative to the base address of the PE. Instead of storing the actual address of each struct of the PE, we use a smaller address, known as RVA (Relative Virtual Address) which tells us "how far away" this address is from the base address. 
- ```Virtual Address```: Virtual address (VA) is the actual address where a field/struct is loaded in memory. Usually, when you print a pointer, you get back a VA.

Based on the forementioned information, we can state the following computation equations:
- ```baseAddress + RVA = VA```
- ```RVA = VA - baseAddress```

## PE structure
The structure which presents the fields and parts that a PE file contains can be seen in the following simplified picture:  

![](/posts/insideapefile1/insideapefile1.png)  

Every one of these parts is called header, and each header is defined by a structure which holds relevant information about the PE file.  
Let's start breaking down each of these headers to get an idea of what they contain and what relation they have to each other.

### DOS Header
DOS Header is the first header of a PE file, and its struct can be seen below:  
```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // Offset to the NT header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```
A few examples of how the DOS Header can be utilized is:
- Checking if the loaded file in memory is indeed an executable. We can check this via the e_magic field, which should always contain the known 'MZ' header. All PE files start with these two bytes (0x5A4D = 'MZ').
- Using the e_lfanew field to jump to the NT Header we will see shortly. The e_lfanew field is an offset to the start of the NT Header. The e_lfanew is always located at an offset of 0x3C.

We can view the DOS header struct of mspaint.exe by opening it in CFF Explorer:  

![](/posts/insideapefile1/insideapefile2.png)  

We can verify our claims about the e_magic being 0x5A4D and e_lfanew being at offset 0x3C.  
Also, we can see that the e_lfanew is a raw address to NT Header, as the PE[e_lfanew] = PE[0x3C] = 0xFB. If we view the offset of the NT Header at CFF explorer, we will evaluate this claim:  

![](/posts/insideapefile1/insideapefile3.png)  

### DOS Stub
Before proceeding to the NT Header, let's first talk about DOS Stub. This stub is next to the DOS header and is not really relevant. It contains the popular message "This program cannot be run in DOS mode" which has remained over the years. The string can of course be modified at compile time. To clarify, this is not a header, but just a part of a PE file containing the prementioned string.  

### NT Header
The NT Header, apart from containing the signature of a PE file ("PE"), is useful as it incorporates two other important headers:
- the ```FileHeader```
- the ```OptionalHeader```

These headers contain a lot of important info regarding the PE as we will see going forward.  

<fieldset class="fieldset-wrapper">
	<center><legend><b>Note</b></legend></center><br>
	<p><b>To land to the NT Header, we utilized the e_lfanew member of the DOS Header.</b></p>
</fieldset>  


Generally, the struct of NT Header is the following:  
```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```
for 32 bit systems, while for 64bit systems is the following:  
```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

Let's now analyze the File Header and OptionalHeader to see what relevant/juicy information their members contain.

### FileHeader
This header as stated previously can be accessed through the NT Header. It's struct is the following:  
```c
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```
The most important members of this struct are:  
- NumberOfSections: This contains the number of sections contained in the PE file.
- Characteristics: This contains Flags that specify attributes regarding the PE file such as whether it's a DLL or console application.
- SizeOfOptionalHeader: This contains the size of the OptionalHeader.

We can view the Characteristics of our PE by clicking on the corresponding field inside CFF Explorer:  
![](/posts/insideapefile1/insideapefile4.png)  

### OptionalHeader
This header is very important for the execution of a PE file. The word 'Optional' might be misleading. It is named that way because some files (specifically, object files) do not have it.  

As with the NT Header, the OptionalHeader has two versions depending on the system (32/64 bit). The only difference is that in the 32 bit systems, some struct members size is defined as DWORD while in 64 bit systems, the same members are defined as ULONGLONG:  
```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                         Magic;
  BYTE                         MajorLinkerVersion;
  BYTE                         MinorLinkerVersion;
  DWORD                        SizeOfCode;
  DWORD                        SizeOfInitializedData;
  DWORD                        SizeOfUninitializedData;
  DWORD                        AddressOfEntryPoint;
  DWORD                        BaseOfCode;
  ULONGLONG / DWORD            ImageBase;
  DWORD                        SectionAlignment;
  DWORD                        FileAlignment;
  WORD                         MajorOperatingSystemVersion;
  WORD                         MinorOperatingSystemVersion;
  WORD                         MajorImageVersion;
  WORD                         MinorImageVersion;
  WORD                         MajorSubsystemVersion;
  WORD                         MinorSubsystemVersion;
  DWORD                        Win32VersionValue;
  DWORD                        SizeOfImage;
  DWORD                        SizeOfHeaders;
  DWORD                        CheckSum;
  WORD                         Subsystem;
  WORD                         DllCharacteristics;
  ULONGLONG / DWORD            SizeOfStackReserve;
  ULONGLONG / DWORD            SizeOfStackCommit;
  ULONGLONG / DWORD            SizeOfHeapReserve;
  ULONGLONG / DWORD            SizeOfHeapCommit;
  DWORD                        LoaderFlags;
  DWORD                        NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

The optional header contains a ton of information that can be used. Below are some of the struct members that are commonly used:
- ```Magic```: Indicates the state of the image file (32-bit or 64-bit).
- ```SizeOfCode```: The size of the .text section 
- ```AddressOfEntryPoint```: The offset to the file's entry point (typically the main function).
- ```BaseOfCode```: The offset to the beginning of the .text section.
- ```SizeOfImage```: The total size of the image file in bytes.
- ```SizeOfHeaders```: The total size of all the headers.
- ```DllCharacteristics```: This includes various flags, the most useful being "DLL can move," which indicates whether a module is ASLR-enabled (whether it can be relocated or not).
- ```ImageBase```: Specifies the preferred memory address for loading the application when executed. However, due to Windows' memory protection mechanisms like Address Space Layout Randomization (ASLR), it is uncommon for an image to be loaded at its preferred address. The Windows PE Loader usually maps the file to a different address. This random allocation can cause issues in later techniques since some addresses, initially considered constant, are altered. The Windows PE loader will then perform PE relocation to correct these addresses.
- ```DataDirectory```: This is one of the most crucial members in the optional header. It's an array of IMAGE_DATA_DIRECTORY, containing the directories in a PE file (explained below).

We can again view the mentioned fields with the help of CFF Explorer:  

![](/posts/insideapefile1/insideapefile5.png)  

Having loaded the NT Header, we can parse the Optional Header and get some information regarding the PE. Some examples are:
```c
DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;
DWORD size_of_headers = p_NT_HDR->OptionalHeader.SizeOfHeaders;
```
were ```p_NT_HDR``` the pointer to the NT Header.

#### DataDirectory
The Data Directory can be accessed from the OptionalHeader's last member. It's struct is the following:  
```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The Data Directory array is of size IMAGE_NUMBEROF_DIRECTORY_ENTRIES which is a constant value of 15. Each element in the array represents a specific data directory which includes some data about a PE section or a Data Table (the place where specific information about the PE is saved).

A specific data directory can be accessed using its index in the array:
```c
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```
And through CFF Explorer:  
![](/posts/insideapefile1/insideapefile6.png)  

We could also view this inside the  winnt.h header file inside a visual studio project.  
The following two sections will mention two of the most important data directories, the Export Directory and Import Address Table.

##### Export Directory
The Export Directory is a data structure that holds information about functions and variables exported from an executable. It includes the addresses of these exported functions and variables, allowing other executable files to access them. The export directory is typically found in DLLs that export functions, such as user32.dll exporting MessageBoxA. The Export Directory is also utilized in API Hashing to loop through all exported functions of a DLL.

##### Import Address Table
The Import Address Table is a data structure in a PE file that contains the addresses of functions imported from other executable files. These addresses are used to access the functions and data in the external executables, such as an application importing MessageBoxA from user32.dll.

### PE Sections
The PE binary, as well as the memory once loaded, is divided into parts called sections. These sections contain the code and data needed to create an executable program. Each section is uniquely named and typically includes executable code, data, or resource information. The number of PE sections is not fixed, as different compilers can add, remove, or merge sections based on the configuration. Additionally, sections can be manually added later, making the structure dynamic. The IMAGE_FILE_HEADER.NumberOfSections helps determine the number of sections.

The following are the most important PE sections and are present in nearly every PE file:
- ```.text```: Contains the executable code which is the written code.
- ```.data```: Contains initialized data which are variables initialized in the code.
- ```.rdata```: Contains read-only data. These are constant variables prefixed with const.
- ```.idata```: Contains the import tables. These are tables of information related to the functions called using the code. This is used by the Windows PE Loader to determine which DLL files to load to the process, along with what functions are being used from each DLL.
- ```.reloc```: Contains information on how to fix up memory addresses so that the program can be loaded into memory without any errors.
- ```.rsrc```: Used to store resources such as icons and bitmaps.

Each PE section has an associated IMAGE_SECTION_HEADER data structure that provides essential information about that section. These structures are stored beneath the NT headers in a PE file and are arranged sequentially, with each structure representing a different section:  

![](/posts/insideapefile1/insideapefile7.png)  

The IMAGE_SECTION_HEADER structure is as follows:
```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
The ones that we must stand out here are:
- Name: This is the name of the section (for example .text).
- PhysicalAddress, VirtualSize: The size of the section when it is loaded in memory.
- VirtualAddress: Offset of the start of the section in memory.

### Bringing it all together
Now that we have some of the necessary theory covered, we can write a PoC program to print information regarding the DataDirectories after it has parsed the OptionalHeader, but also read through one of the sections, for example the .text one.







####  PoC - Main Function
We start off by specifying the full path of the program we want to read. After that, we utilize the ```fseek``` function to get the size of the mspaint PE file:
```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

int main() {
    // Load the PE file data into memory
    FILE* file = fopen("C:\\Windows\\System32\\mspaint.exe", "rb");
    if (!file) {
        printf("Failed to open file.\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
```
As the comments describe, we basically "count" how many bytes there are from the start to the end of the executable. In a more in depth explanation:
- ```fseek(FILE *stream, long int offset, int whence)```: Its parameters can be described below:
    - ```stream```: A pointer to a FILE object that identifies the stream.
    - ```offset```: The number of bytes to offset from the position specified by whence.
    - ```whence```: The position from where the offset is added. It can take one of the following values:
        - ```SEEK_SET```: Beginning of the file.
        - ```SEEK_CUR```: Current position of the file pointer.
        - ```SEEK_END```: End of the file.
- ```ftell(exe_file)```: Returns the current value of the file position indicator, which is now at the end of the file because of the previous fseek call. This value represents the size of the file in bytes.

Having computed the size of the executable, we go on to allocate the required memory for the exe plus an additional check to make sure everything went smoothly:  
```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

int main() {
    // Load the PE file data into memory
    FILE* file = fopen("C:\\Windows\\System32\\mspaint.exe", "rb");
    if (!file) {
        printf("Failed to open file.\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(fileSize+1);
    if (!buffer) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return -1;
    }

    size_t n_read = fread(buffer, 1, fileSize, file);
    if(n_read != fileSize) {
        printf("reading error (%d)\n", n_read);
        return 1;
    }

    fclose(file);
```

The ```malloc``` allocates a block of memory large enough to hold the entire file plus one additional byte. The additional byte can be used to null-terminate the data if needed (e.g., if the data is to be treated as a string).  

The ```fread(void *ptr, size_t size, size_t nmemb, FILE *stream)``` just reads the *stream file - in our case the exe - to the malloc section previously defined. It will read nmemb bytes which is the size of the exe and the size of each element to be read in bytes is 1 byte.

The ```fread``` returns size, so if the size read into buffer is not the same as the previously computed fileSize (the size of the exe) then something went wrong and we exit. If the sizes are the same, then we can proceed:  
```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

int main() {
    // Load the PE file data into memory
    FILE* file = fopen("C:\\Windows\\System32\\mspaint.exe", "rb");
    if (!file) {
        printf("Failed to open file.\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(fileSize+1);
    if (!buffer) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return -1;
    }

    size_t n_read = fread(buffer, 1, fileSize, file);
    if(n_read != fileSize) {
        printf("reading error (%d)\n", n_read);
        return 1;
    }

    fclose(file);

    // Load the PE file
    load_PE(buffer);
    free(buffer);

    return 0;
}
```
The code continues by calling the function ```load_PE(buffer)``` that will be responsible for loading all the sections of the PE File, eventually landing at the functions it uses.  Let's start developing it.


####  PoC - load_PE function
Now that we have completed the main function, we will start developing the ```load_PE``` function which is the one that will enumerate and parse through the PE file, eventually providing us with the juicy information we aim at.
##### IMAGE_DOS_HEADER
```c
void* load_PE(char* PE_data) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)PE_data;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // more
}
```
We pass the PE_data which is a pointer to the address of the PE file we previously read to a buffer. We cast to ```(PIMAGE_DOS_HEADER)``` in order to tell VS code how these bytes actually look like at that address, since they represend and contain members of a PE file. 

After the cast to ```(PIMAGE_DOS_HEADER)```, we access the e_magic field ('MZ') to see if it is a valid executable. The ```IMAGE_DOS_SIGNATURE``` is hardcoded to 'MZ', so before our code proceeds further, we need to make sure the data we passed to the function is a valid PE file.

##### IMAGE_NT_HEADER
After the first check is successful, we continue by accessing the NT_HEADER:
```c
void* load_PE(char* PE_data) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)PE_data;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(PE_data + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    // more
}
```
As we previously discussed, using the baseAddress of a PE in combination with the e_lfanew member of the ```PIMAGE_DOS_HEADER``` struct, we can access the NT Header. The PE_data used here is not the actual bytes of the PE file but rather a pointer to the address were the data are stored (the starting address of the previously read PE).  

After we have accessed the NT Header, we make a check to see if the ```Signature``` member that is supposed to exist after the casting to ```(PIMAGE_NT_HEADERS)``` is equal to the hardcoded ```IMAGE_NT_SIGNATURE``` value of ```'PE'```. This is just an extra check to make sure we are working with a valid PE file.

##### Optional Header & DataDirectories
Passing this check, we then access the ```OptionalHeader``` member of the NT Header. The reason we do this is to access the Data Directories and its members since the ```OptionalHeader``` is the one containing this info, as discussed previously:
```c
void* load_PE(char* PE_data) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)PE_data;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    printf("PE_data is %p", PE_data);
    return 0;
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(PE_data + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Iterate over the DataDirectory entries (15 in total)
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) { 
        IMAGE_DATA_DIRECTORY dataDirectory = ImgOptHdr.DataDirectory[i];
        printf("DataDirectory %d:\n", i);
        printf("  Value at Virtual Address (RVA): 0x%08lx\n", dataDirectory.VirtualAddress); // Print the RVA
        printf("  Size: 0x%08lx\n", dataDirectory.Size);

        // Calculate the address in the PE data
        if (dataDirectory.VirtualAddress != 0) {
            void* directoryAddress = PE_data + dataDirectory.VirtualAddress;
            printf("  Virtual Address: %p\n", directoryAddress);
        } else {
            printf("  No data at this directory entry.\n");
        }
    }

    // more
```
Inside the loop, we store the current Data Directory at each loop to a variable of type ```IMAGE_DATA_DIRECTORY``` and then proceed to access its two members (```VirtualAddress``` and ```Size```).  

We also try and get the VA of the directory by adding the base address of the PE with the Virtual address of the current dataDir. If there are any data stored in there, we print the address we calculated.  

For anyone wondering what data can be inside the calculated address, if we had passed a DLL with exported functions to the load_PE function, then inside the ```EXPORT DIRECTORY``` there would be information about addresses of functions, addresses of names - amongst other members. See [API Hashing]("https://connar.github.io/posts/apihashing/") for more.  

##### .text section
Finally, we load the data stored in the .text section, printing its relevant information such as pointers to addresses, as well as the raw bytes it contains:
```c
void* load_PE(char* PE_data) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)PE_data;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(PE_data + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Iterate over the DataDirectory entries (15 in total)
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) { 
        IMAGE_DATA_DIRECTORY dataDirectory = ImgOptHdr.DataDirectory[i];
        printf("DataDirectory %d:\n", i);
        printf("  Value at Virtual Address (RVA): 0x%08lx\n", dataDirectory.VirtualAddress); // Print the RVA
        printf("  Size: 0x%08lx\n", dataDirectory.Size);

        // Calculate the address in the PE data
        if (dataDirectory.VirtualAddress != 0) {
            void* directoryAddress = PE_data + dataDirectory.VirtualAddress;
            printf("  Virtual Address: %p\n", directoryAddress);
        } else {
            printf("  No data at this directory entry.\n");
        }
    }

    // Find and read the .text section as a PoC
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImgNtHdrs);
    for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)sectionHeader->Name, ".text", 5) == 0) {
            printf(".text section found.\n");
            printf("  Virtual Address: 0x%08lx\n", sectionHeader->VirtualAddress);
            printf("  Size of Raw Data: 0x%08lx\n", sectionHeader->SizeOfRawData);
            printf("  Pointer to Raw Data: 0x%08lx\n", sectionHeader->PointerToRawData);

            // Read the contents of the .text section
            char* textSectionData = (char*)malloc(sectionHeader->SizeOfRawData);
            if (!textSectionData) {
                printf("Memory allocation failed for .text section data.\n");
                return NULL;
            }

            memcpy(textSectionData, PE_data + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);

            // Print the contents of the .text section
            for (DWORD j = 0; j < sectionHeader->SizeOfRawData; j++) {
                printf("%02x ", (unsigned char)textSectionData[j]);
            }
            printf("\n");

            free(textSectionData);
            break;
        }
        sectionHeader++;
    }

    return NULL;
}

```
We first use the ```IMAGE_FIRST_SECTION``` to get the first section of the NT Header.  
Then, we enumerate through all its sections and compare the first 5 characters of each one to ".text". If we have a match, then we have landed on the .text section.  
Having the correct section, we print its Virtual Address, the Size of its Raw Data and the Pointer to the Raw Data.  

Then, since we want to read the contents of the section, we allocate the right memory space with ```malloc```, based on the previously printed ```SizeOfRawData``` member and then copy the bytes to the ```textSectionData``` buffer with ```memcpy```.

After the copy of the bytes to the textSectionData buffer, we enumerate through each byte and print it. After completing the enumeration of the bytes, we free the buffer.


#### Running the final program
Putting it all together, we are met with the following code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

void* load_PE(char* PE_data) {
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)PE_data;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(PE_data + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Iterate over the DataDirectory entries (15 in total)
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) { 
        IMAGE_DATA_DIRECTORY dataDirectory = ImgOptHdr.DataDirectory[i];
        printf("DataDirectory %d:\n", i);
        printf("  Value at Virtual Address (RVA): 0x%08lx\n", dataDirectory.VirtualAddress); // Print the RVA
        printf("  Size: 0x%08lx\n", dataDirectory.Size);

        // Calculate the address in the PE data
        if (dataDirectory.VirtualAddress != 0) {
            void* directoryAddress = PE_data + dataDirectory.VirtualAddress;
            printf("  Virtual Address: %p\n", directoryAddress);
        } else {
            printf("  No data at this directory entry.\n");
        }
    }

    // Find and read the .text section as a PoC
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImgNtHdrs);
    for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)sectionHeader->Name, ".text", 5) == 0) {
            printf(".text section found.\n");
            printf("  Virtual Address: 0x%08lx\n", sectionHeader->VirtualAddress);
            printf("  Size of Raw Data: 0x%08lx\n", sectionHeader->SizeOfRawData);
            printf("  Pointer to Raw Data: 0x%08lx\n", sectionHeader->PointerToRawData);

            // Read the contents of the .text section
            char* textSectionData = (char*)malloc(sectionHeader->SizeOfRawData);
            if (!textSectionData) {
                printf("Memory allocation failed for .text section data.\n");
                return NULL;
            }

            memcpy(textSectionData, PE_data + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);

            // Print the contents of the .text section
            for (DWORD j = 0; j < sectionHeader->SizeOfRawData; j++) {
                printf("%02x ", (unsigned char)textSectionData[j]);
            }
            printf("\n");

            free(textSectionData);
            break;
        }
        sectionHeader++;
    }

    return NULL;
}

int main() {
    // Load the PE file data into memory
    FILE* file = fopen("C:\\Windows\\System32\\mspaint.exe", "rb");
    if (!file) {
        printf("Failed to open file.\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return -1;
    }

    size_t n_read = fread(buffer, 1, fileSize, file);
    if (n_read != fileSize) {
        printf("reading error (%d)\n", n_read);
        return 1;
    }

    fclose(file);

    // Load the PE file
    load_PE(buffer);
    free(buffer);

    return 0;
}
```
Let's run it and evaluate the results regarding the Data Directories and the .text section:  

![Data Directories](/posts/insideapefile/insideapefile8.png)  

Observing the output, we see we have gotten the correct values compared side by side with CFF explorer. Let's navigate to the Section Headers and click on the .text one:  

![Data Directories](/posts/insideapefile/insideapefile9.png)  

We have successfully evaluated that our code works correctly! 


## Summing up
In this post we loaded a PE file, navigated through its headers and got the information we initially targeted for. The following picture really helps you to remember what to aim for and how to move around inside the PE:  

![PE clearer](/posts/insideapefile/insideapefile11.png) 

So this program was a simple PoC to see how you can move around the headers and how to actually access them. On a more abstruct depiction, our code did the following:  

![Data Directories](/posts/insideapefile/insideapefile10.png)  

*Address of Names added only as a reference to a previous statement I made regarding the Export Directory.*

**References**
<blockquote>
    <ul>
        <li> [1] <a href="https://wirediver.com/tutorial-writing-a-pe-packer-part-1/">WireDiver: <i>Writing a PE packer – Part 1 : load a PE in memory</i></a></li>
        <li> [2] <a href="https://dev.to/wireless90/exploring-the-export-table-windows-pe-internals-4l47">wireless90: <i>Exploring the Export Table [Windows PE Internals]</i></a></li>
</i></a></li>
    </ul>
</blockquote>