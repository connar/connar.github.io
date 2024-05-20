+++
title = "Learning about windows api"
date = 2024-03-11T20:03:02+02:00
draft = false
tags = ["Windows API"]
categories = ["Windows"]
ShowToc = true
author = ["connar"]
+++


### Intro
As I am starting to take a turn of interest into malware analysis and development, I was required to understand what the Windows API really is. So this post is basically my notes on what windows api is and a few examples of it.  


### Was exactly is an API  
When you use a Windows application, have you ever wondered how it seamlessly interacts with the operating system? The magic behind this interaction is the Windows API. Generally, an api allows for two pieces of software to interact upon another. When it comes to programming, it allows your code to interact with the windows operating system.  
Let's dive into what the Windows API is and why it's crucial for software development on the Windows platform - but also for red teamers, threat actors and blue teamers as well.  

The Windows API, or Application Programming Interface, is an extensive collection of functions and procedures supplied by the Microsoft Windows operating system. Imagine it as a toolkit that enables software developers to build applications capable of interacting with the Windows environment. For instance, tasks such as displaying content on the screen, modifying files, or querying the registry can all be accomplished through the Windows API. Microsoft provides thorough documentation for the Windows API, which you can explore(here)[https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list].

Basically, when an application needs to perform an operation, it uses the Win32 API, which translates the request into SYSCALLs. These SYSCALLs are then executed by the kernel to make the necessary changes or perform the desired actions. We can see an overview of this process in the following diagram:  

![windows api overview diagram](/posts/windowsapi/windowsapi1.png)  

More specifically and for giving an example, the function flow of the calls made by a program that just wants to use the FileStream.Read method would be the following:  

![windows api overview diagram](/posts/windowsapi/windowsapi3.png)  

### Layers of the Windows API
Before we dive into the functionality of the API, it's important to understand the layers and terminologies we'll be referring to. The Win32 API, more commonly known as the Windows API, consists of several components that define its structure and organization. To simplify this, we'll break down the Win32 API using a top-down approach: the API itself is the top layer, and the parameters for specific calls are the bottom layer. The table below outlines this top-down structure at a high level, with more detailed explanations to follow:  

![windows api layers](/posts/windowsapi/windowsapi2.png)  

### Header files vs Dll files

#### Header files
Header files contain definitions of functions that make up the API, such as ```ReadProcessMemory```, but they do not include the actual code that implements these functions:  
```c++
#include <windows.h>
#include <iostream>

int main() {
    // Open the process with PROCESS_VM_READ access
    DWORD processID = 1234; // Replace with the target process ID
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processID);

    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Address in the target process to read from
    LPCVOID baseAddress = (LPCVOID)0x7FF6ABCDEF00; // Replace with the actual address
    SIZE_T bytesRead;
    char buffer[256]; // Buffer to store the read data

    // Read memory from the target process
    if (ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(buffer), &bytesRead)) {
        std::cout << "Read " << bytesRead << " bytes from the process." << std::endl;
        // Do something with the data in buffer
    } else {
        std::cerr << "Failed to read process memory. Error: " << GetLastError() << std::endl;
    }

    // Close the handle to the process
    CloseHandle(hProcess);

    return 0;
}
```
Here, we imported the windows.h header file that contains the declarations for all the Windows API functions, including ```ReadProcessMemory```.  
The implementation code is found in DLL files, which stands for Dynamic Link Libraries. A single DLL file can provide the implementations for multiple header files.  

So basically, the windows.h header file includes, amongst others, the declaration of the ```ReadProcessMemory``` function:  
```c++
BOOL ReadProcessMemory(
  HANDLE  hProcess,
  LPCVOID lpBaseAddress,
  LPVOID  lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesRead
);

```  

This declaration tells the compiler what the function looks like, its name, return type, and parameters. However, it does not provide the actual implementation of the function. The code of this function is inside the corresponding dll. 

#### Dll files
When a function like ```ReadProcessMemory``` is called, the system locates the corresponding DLL that contains the implementation of this function. For many Windows API functions, this DLL is kernel32.dll. How is the header file connected with the dll and the function name call is described below:  

##### Linking Process  
1. **Compilation**: During the compilation, the compiler uses the header files to understand the structure and usage of the functions. It ensures that the function calls in our code match the declarations in the header files.  
2. **Linking**: During the linking phase, the linker resolves the references to these functions by linking them to the corresponding DLL files that contain the actual implementation. For ReadProcessMemory, the linker ensures that the call in our code will be linked to the kernel32.dll.  
3. **Runtime**: At runtime, when the program execution reaches a call to ReadProcessMemory, the Windows operating system loads kernel32.dll (if it is not already loaded) and resolves the address of the ReadProcessMemory function. The program then jumps to that address to execute the function.  

So when our previous code calls the ReadProcessMemory, the process that happens can be summorized as:  
1. **Include Header File**: You include windows.h in your source file. This header file contains the declaration of ReadProcessMemory:  
```c++
#include <windows.h>
```
2. **Link to DLL**: The linker ensures that your program is linked with kernel32.dll, where ReadProcessMemory is implemented.  
3. **Call the Function**: When you call ReadProcessMemory in your code, the compiled program contains a placeholder that will be resolved to the actual address of the function in kernel32.dll at runtime:  
```c++
if (ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(buffer), &bytesRead)) {
    // Successfully read memory
}
```
4. **Execution**: At runtime, when ReadProcessMemory is called, the operating system ensures that kernel32.dll is loaded into memory, finds the ReadProcessMemory function within the DLL, and executes it.

