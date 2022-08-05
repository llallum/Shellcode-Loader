// ShellcodeLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	LPVOID (*func)();
	LPVOID shellcode;
	DWORD fSize;
	OVERLAPPED ol = { 0 };
	LPDWORD cbRead = 0;

	if (argc != 2) {
		printf("[-] Error: Shellcode argument is needed!\n");
		return -1;
	}
	HANDLE hFile = CreateFileA(argv[1], 
		GENERIC_READ,
		FILE_SHARE_READ, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);
	if (hFile == (HANDLE)INVALID_HANDLE_VALUE) {
		printf("[-] Error: CreateFile with error code of 0x%08x.\n", GetLastError());
		return -1;
	}
	printf("[+] Opening file [ %s ].\n", argv[1]);
	Sleep(1000);
	fSize = GetFileSize(hFile, 0);
	if (!fSize) {
		printf("[-] Error: Empty file.\n");
		return -1;
	}

	shellcode = VirtualAlloc(0, fSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	printf("[+] Allocating 0x%08x memory size.\n", fSize);
	Sleep(1000);

	if (!ReadFile(hFile, shellcode, fSize, cbRead, &ol)) {
		printf("[-] Error: ReadFile with error code of 0x%08x.\n", GetLastError());
		return -1;
	}
	printf("[+] Reading the shellcode.\n");
	Sleep(1000);
	func = (LPVOID(*)())shellcode;

	printf("[+] Executing the shellcode at memory address 0x%08x.\n", shellcode);
	Sleep(1000);
	func();
}

