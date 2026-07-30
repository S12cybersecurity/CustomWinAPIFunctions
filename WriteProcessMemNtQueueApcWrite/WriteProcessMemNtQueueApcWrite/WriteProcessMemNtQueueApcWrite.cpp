#include <iostream>
#include <Windows.h>
#include <ntstatus.h>
#include <TlHelp32.h>
//#include <ntdef.h>

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

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
	HANDLE ThreadHandle,
	PVOID ApcRoutine,
	PVOID ApcRoutineContext,
	PVOID ApcStatusBlock,
	ULONG ApcReserved
	);


// https://trickster0.github.io/posts/Primitive-Injection/
void WriteRemoteMemory(HANDLE hProc, LPVOID heapAllocation, int sizeofVal, unsigned char* buffer){
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
	LPVOID RtlFillMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFillMemory");
	LPVOID RtlExitUserThread = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlExitUserThread");
	LPVOID RtlInitializeBitMapEx = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitializeBitMapEx");

	HANDLE hThread2 = NULL;
	NtCreateThreadEx(&hThread2, THREAD_ALL_ACCESS, NULL, hProc, RtlExitUserThread, (PVOID)0x00000000, TRUE, NULL, NULL, NULL, NULL);
	int alignmentCheck = sizeofVal % 16; 
	int offsetMax = sizeofVal - alignmentCheck;
	int firCounter = 0; int eightCounter = 0; int secCounter = 0; int mod = 0;

	if (sizeofVal >= 16) {
		for (firCounter = 0; firCounter < offsetMax - 1; firCounter = firCounter + 16) {
			char* heapWriter = (char*)heapAllocation + firCounter;
			NtQueueApcThread(hThread2, (PVOID)RtlInitializeBitMapEx, (PVOID)heapWriter, (PVOID) * (ULONG_PTR*)((char*)buffer + firCounter + 8), (ULONG) * (ULONG_PTR*)((char*)buffer + firCounter));
		}
	}

	if (alignmentCheck >= 8) {
		for (eightCounter = firCounter; (eightCounter + 8) < (firCounter + alignmentCheck - 1); eightCounter = eightCounter + 8) {
			char* heapWriter = (char*)heapAllocation + eightCounter;
			NtQueueApcThread(hThread2, (PVOID)RtlInitializeBitMapEx, (PVOID)heapWriter, NULL, (ULONG) * (ULONG_PTR*)((char*)buffer + eightCounter));
		}
		alignmentCheck -= 8;
	}

	if (alignmentCheck != 0 && alignmentCheck < 8) {
		if ((firCounter != 0 && eightCounter != 0) || (firCounter != 0 && eightCounter != 0)) {
			secCounter = eightCounter;
			mod = eightCounter;
		}
		else if (firCounter != 0 && eightCounter == 0) {
			secCounter = firCounter;
			mod = firCounter;
		}
		for (; secCounter < (mod + alignmentCheck); secCounter++) {
			char* heapWriter = (char*)heapAllocation + secCounter;
			NtQueueApcThread(hThread2, (PVOID)RtlFillMemory, (PVOID)heapWriter, (PVOID)1, (ULONG)buffer[secCounter]);
		}
	}

	ResumeThread(hThread2);
	WaitForSingleObject(hThread2, INFINITE);
}



int main()
{
    std::cout << "Writting Remote Process Memory!\n";

	unsigned char myData[] = "This memory was written using APC routines!";
	int dataSize = sizeof(myData);

	int pid = 3920;
	HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);

	// 3. Allocate memory in the target process (where the APCs will write to)
	LPVOID remoteHeap = VirtualAllocEx(
		hProc,
		NULL,
		dataSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (remoteHeap == NULL) {
		std::cerr << "Failed to allocate remote memory. Error: " << GetLastError() << std::endl;
		return 1;
	}

	std::cout << "Target Memory Address: " << remoteHeap << std::endl;

	WriteRemoteMemory(hProc, remoteHeap, dataSize, myData);

	
	std::cout << "Time of verification.. " << std::endl;
	getchar();
	return 0;
}

