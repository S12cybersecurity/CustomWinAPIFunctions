# UPrimitives
This repository contains custom functions, written in C++ and aimed at exploring and demonstrating alternative approaches to common Windows API operations such as memory allocation, library loading, and process interaction.

## Implementations Overview
#### 1. CustomLoadLibrary
This is a custom implementation of the LoadLibrary function, offering an alternative method for dynamically loading DLLs into a process. It is designed to work in conjunction with other functions like VirtualAlloc and WriteProcessMemory to provide a flexible approach to module handling.

#### 2. VirtualAllocModuleStomping
This implementation provides a custom version of the VirtualAlloc function, specifically tailored for module stomping techniques. It allows for allocating memory and overwriting existing loaded modules in a process's address space, integrating seamlessly with WriteProcessMemory and LoadLibrary for advanced memory manipulation scenarios.

#### 3. WriteProcessMemoryImplementation
A custom take on the WriteProcessMemory function, enabling the writing of data to the virtual address space of another process. This implementation is particularly useful when combined with VirtualAlloc and LoadLibrary, facilitating tasks like injecting code or modifying memory in external processes. It uses the thread description and APCs

#### 4. WriteProcessMemNtQueueApcWrite
A custom implementation of WriteProcessMemory that leverages APC routines to perform remote memory writes. Instead of relying on conventional memory writing APIs, this approach queues APCs to a remote thread, using them as a write primitive to copy arbitrary data into the target process.

#### 5. ReadMemoryRtlQueryDepthSList
A custom implementation for reading memory from a remote process by abusing the thread exit code returned by `NtCreateThreadEx`. The technique combines thread creation with `RtlQueryDepthSList` to build a byte-wise read primitive without relying on traditional memory reading APIs.