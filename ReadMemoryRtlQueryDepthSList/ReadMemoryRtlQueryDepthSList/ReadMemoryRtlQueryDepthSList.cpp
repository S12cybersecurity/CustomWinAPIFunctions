#include <iostream>
#include <Windows.h>

using namespace std;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	ULONG_PTR ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
	);


PVOID CustomCopy(PVOID Destination, CONST PVOID Source, SIZE_T Length){
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

// https://trickster0.github.io/posts/Primitive-Injection/
unsigned char* cReadRemoteMemory(HANDLE hProc, LPVOID addrOf, int sizeofVal){
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	PVOID pRtlQueryDepthSList = (PVOID)GetProcAddress(hNtdll, "RtlQueryDepthSList");

	unsigned char* readBytes = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8);
	DWORD dwDataLength = sizeofVal;
	for (DWORD i = 0; i < dwDataLength; i = i + 2)
	{
		HANDLE hThread = NULL;
		NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProc, (PVOID)pRtlQueryDepthSList, (ULONG_PTR*)((BYTE*)addrOf + i), FALSE, NULL, NULL, NULL, NULL);
		DWORD ExitCode = 0;
		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, &ExitCode);
		if (dwDataLength - i == 1)
		{
			CustomCopy((char*)readBytes + i, (PVOID)&ExitCode, 1);
		}
		else
		{
			CustomCopy((char*)readBytes + i, (PVOID)&ExitCode, 2);
		}
		CloseHandle(hThread);
	}
	return readBytes;
}



int main(){
	const char* secretData = "AAAA"; 
	LPVOID addressToRead = (LPVOID)secretData;

	//HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 2133);

	// 2. Get a handle to the process (usually remote process)
	HANDLE hProc = GetCurrentProcess();

	cout << "[+] Target Address: 0x" << hex << addressToRead << endl;
	cout << "[+] Attempting to read 4 bytes via NtCreateThreadEx..." << endl;

	// 3. Call your custom read function
	unsigned char* result = cReadRemoteMemory(hProc, addressToRead, 4);

	// 4. Output the results
	if (result) {
		cout << "[+] Read Successful!" << endl;
		cout << "[+] Data as Hex: ";
		for (int i = 0; i < 4; i++) {
			printf("%02X ", result[i]);
		}
		HeapFree(GetProcessHeap(), 0, result);
		cout << endl;
	}
	else {
		cout << "[-] Failed to read memory." << endl;
	}

	return 0;
}

