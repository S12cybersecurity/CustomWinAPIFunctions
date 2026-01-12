#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <winternl.h>

using namespace std;

typedef NTSTATUS(NTAPI* pLdrLoadDll) (
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
    );

typedef VOID(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

HMODULE MyLoadLibrary(LPCWSTR lpFileName) {
    UNICODE_STRING ustrModule;
    HANDLE hModule = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    RtlInitUnicodeString(&ustrModule, lpFileName);

    pLdrLoadDll myLdrLoadDll = (pLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
    if (!myLdrLoadDll) {
        return NULL;
    }

    NTSTATUS status = myLdrLoadDll(NULL, 0, &ustrModule, &hModule);
    return (HMODULE)hModule;
}

int main(int argc, char** argv) {
    HMODULE dll = MyLoadLibrary(L"C:\\Users\\Public\\DummyDLL.dll");
    if (dll) {
        cout << "loaded library!" << endl;
        FreeLibrary(dll);
    }
    else {
        cout << "failed to load library!" << endl;
    }
    return 0;
}