#include "stdafx.h"
#include <iostream>

HINSTANCE g_hDllInst;

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

namespace
{
#define PRE_X32SHELLCODE_ARGS_3_TO_1 \
	"\x58"		   /* pop eax   */   \
	"\x59"		   /* pop ecx   */   \
	"\x83\xC4\x08" /* add esp,8 */   \
	"\x51"		   /* push ecx  */   \
	"\x50"		   /* push eax  */

#define PRE_X32SHELLCODE_VIRTUAL_FREE                           \
	"\xFF\x74\x24\x04"		   /* push dword ptr ss:[esp+4]  */ \
	"\xE8\x1E\x00\x00\x00"	   /* call $+1E                  */ \
	"\x85\xC0"				   /* test eax,eax               */ \
	"\x75\x03"				   /* jne $+3                    */ \
	"\xC2\x04\x00"			   /* ret 4                      */ \
	"\x59"					   /* pop ecx                    */ \
	"\x5A"					   /* pop edx                    */ \
	"\x68\x00\x80\x00\x00"	   /* push 8000                  */ \
	"\x6A\x00"				   /* push 0                     */ \
	"\xE8\x00\x00\x00\x00"	   /* call $                     */ \
	"\x66\x81\x24\x24\x00\xF0" /* and word ptr ss:[esp],F000 */ \
	"\x51"					   /* push ecx                   */ \
	"\xFF\xE0"				   /* jmp eax                    */

	// clang-format off
	const BYTE x32APCShellcode[] =
		PRE_X32SHELLCODE_ARGS_3_TO_1
		PRE_X32SHELLCODE_VIRTUAL_FREE
		"\x55\x8B\xEC\x83\xEC\x50\x64\xA1\x30\x00\x00\x00\x33\xC9\x53"
		"\x33\xDB\xC7\x45\xD8\x00\x00\x00\x00\x56\x8B\x50\x0C\x83\xC2"
		"\x14\xC7\x45\xEC\x00\x00\x00\x00\x89\x55\xD0\x57\x89\x4D\xFC"
		"\x8B\x02\x89\x4D\xF8\x89\x5D\xDC\x89\x4D\xE4\x89\x4D\xE8\x89"
		"\x45\xF4\x3B\xC2\x0F\x84\x12\x03\x00\x00\xEB\x03\x8B\x45\xF4"
		"\x8B\x78\x28\x33\xD2\x0F\xB7\x70\x24\x0F\xB6\x07\xC1\xCA\x0D"
		"\x03\xD0\x80\x3F\x61\x72\x03\x83\xC2\xE0\x81\xC6\xFF\xFF\x00"
		"\x00\x47\x66\x85\xF6\x75\xE4\x81\xFA\x5B\xBC\x4A\x6A\x0F\x85"
		"\x20\x01\x00\x00\x8B\x45\xF4\xBB\x08\x00\x00\x00\x8B\x70\x10"
		"\x8B\x46\x3C\x8B\x54\x30\x78\x8B\x44\x32\x20\x03\xD6\x03\xC6"
		"\x89\x55\xD4\x89\x45\xE0\x8B\x4A\x24\x8B\x7A\x18\x03\xCE\x89"
		"\x4D\xF0\x85\xFF\x0F\x84\xEA\x00\x00\x00\x8B\x10\x03\xD6\x33"
		"\xC0\x8A\x0A\xC1\xC8\x0D\x8D\x52\x01\x0F\xBE\xC9\x03\xC1\x8A"
		"\x0A\x84\xC9\x75\xEF\x3D\xA4\x4E\x0E\xEC\x74\x2E\x3D\xAA\xFC"
		"\x0D\x7C\x74\x27\x3D\xAC\x33\x06\x03\x74\x20\x3D\x66\x19\xDA"
		"\x75\x74\x19\x3D\xBC\x22\x0D\x47\x74\x12\x3D\xFB\x97\xFD\x0F"
		"\x74\x0B\x3D\x7C\xC4\x22\x59\x0F\x85\x85\x00\x00\x00\x8B\x4D"
		"\xF0\x0F\xB7\x11\x8B\x4D\xD4\x8B\x49\x1C\x8D\x0C\x91\x03\xCE"
		"\x3D\xA4\x4E\x0E\xEC\x75\x09\x8B\x01\x03\xC6\x89\x45\xD8\xEB"
		"\x5E\x3D\xAA\xFC\x0D\x7C\x75\x09\x8B\x01\x03\xC6\x89\x45\xEC"
		"\xEB\x4E\x3D\xAC\x33\x06\x03\x75\x09\x8B\x01\x03\xC6\x89\x45"
		"\xFC\xEB\x3E\x3D\x66\x19\xDA\x75\x75\x09\x8B\x01\x03\xC6\x89"
		"\x45\xF8\xEB\x2E\x3D\xBC\x22\x0D\x47\x75\x09\x8B\x01\x03\xC6"
		"\x89\x45\xDC\xEB\x1E\x3D\xFB\x97\xFD\x0F\x75\x09\x8B\x01\x03"
		"\xC6\x89\x45\xE4\xEB\x0E\x3D\x7C\xC4\x22\x59\x75\x07\x8B\x01"
		"\x03\xC6\x89\x45\xE8\x81\xC3\xFF\xFF\x00\x00\x8B\x45\xE0\x4F"
		"\x83\x45\xF0\x02\x83\xC0\x04\x89\x45\xE0\x66\x85\xDB\x0F\x85"
		"\x0E\xFF\xFF\xFF\x8B\x5D\xDC\x8B\x7D\xD8\x8B\x55\xEC\x8B\x45"
		"\xFC\x8B\x4D\xF8\x85\xFF\x74\x1D\x85\xD2\x74\x19\x85\xC0\x74"
		"\x15\x85\xC9\x74\x11\x85\xDB\x74\x0D\x83\x7D\xE4\x00\x74\x07"
		"\x8B\x75\xE8\x85\xF6\x75\x4E\x8B\x75\xF4\x8B\x36\x3B\x75\xD0"
		"\x89\x75\xF4\x8B\x75\xE8\x0F\x85\x6B\xFE\xFF\xFF\x85\xFF\x0F"
		"\x84\x70\x01\x00\x00\x85\xD2\x0F\x84\x68\x01\x00\x00\x85\xC0"
		"\x0F\x84\x60\x01\x00\x00\x85\xC9\x0F\x84\x58\x01\x00\x00\x85"
		"\xDB\x0F\x84\x50\x01\x00\x00\x83\x7D\xE4\x00\x0F\x84\x46\x01"
		"\x00\x00\x85\xF6\x0F\x84\x3E\x01\x00\x00\x8D\x45\xD0\x50\x6A"
		"\x01\xFF\xD6\x8D\x45\xC4\xC7\x45\xC4\x5B\x57\x48\x5D\x50\xC7"
		"\x45\xC8\x20\x4C\x4C\x0A\xC6\x45\xCC\x00\xFF\xD3\xFF\x75\x08"
		"\xFF\xD7\x85\xC0\x74\x2D\x8D\x45\xB8\xC7\x45\xB8\x5B\x57\x48"
		"\x5D\x50\xC7\x45\xBC\x20\x47\x50\x41\x66\xC7\x45\xC0\x0A\x00"
		"\xFF\xD3\x6A\x00\xFF\x75\xD0\xFF\xD6\x8B\x45\xFC\x5F\x5E\x5B"
		"\x8B\xE5\x5D\xC2\x04\x00";

	constexpr SIZE_T x32APCShellcodeSize = sizeof(x32APCShellcode) - 1;

	const BYTE *x32Shellcode = x32APCShellcode + sizeof(PRE_X32SHELLCODE_ARGS_3_TO_1) - 1;
	constexpr SIZE_T x32ShellcodeSize = (sizeof(x32APCShellcode) - 1) - (sizeof(PRE_X32SHELLCODE_ARGS_3_TO_1) - 1);

#define PRE_X64SHELLCODE_VIRTUAL_FREE                             \
	"\x48\x83\xEC\x28"			   /* sub rsp,28               */ \
	"\xE8\x20\x00\x00\x00"		   /* call $+20                */ \
	"\x48\x83\xC4\x28"			   /* add rsp,28               */ \
	"\x48\x85\xC0"				   /* test rax,rax             */ \
	"\x75\x01"					   /* jne $+1                  */ \
	"\xC3"						   /* ret                      */ \
	"\x48\x8D\x0D\x00\x00\x00\x00" /* lea rcx,qword ptr ds:[$] */ \
	"\x66\x81\xE1\x00\xF0"		   /* and cx,F000              */ \
	"\x33\xD2"					   /* xor edx,edx              */ \
	"\x41\xB8\x00\x80\x00\x00"	   /* mov r8d,8000             */ \
	"\xFF\xE0"					   /* jmp rax                  */

	// The 64-bit InjectShellcode function from the project in the inject-shellcode subfolder.
	const BYTE x64Shellcode[] =
		PRE_X64SHELLCODE_VIRTUAL_FREE
		"\x48\x89\x4C\x24\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56"
		"\x41\x57\x48\x8B\xEC\x48\x83\xEC\x58\x33\xDB\x45\x33\xD2\x48"
		"\x89\x5D\x50\x45\x33\xE4\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
		"\x45\x33\xED\x45\x33\xF6\x4C\x89\x55\x58\x33\xF6\x45\x33\xFF"
		"\x48\x8B\x78\x18\x48\x83\xC7\x20\x48\x89\x7D\x60\x4C\x8B\x1F"
		"\x4C\x89\x5D\xC8\x4C\x3B\xDF\x0F\x84\x3B\x03\x00\x00\x0F\x1F"
		"\x84\x00\x00\x00\x00\x00\x4D\x8B\x43\x50\x33\xC0\x45\x0F\xB7"
		"\x4B\x48\xBF\xFF\xFF\x00\x00\x41\x0F\xB6\x10\x4D\x8D\x40\x01"
		"\xC1\xC8\x0D\x8B\xC8\x48\x03\xCA\x80\xFA\x61\x48\x8D\x41\xE0"
		"\x48\x0F\x42\xC1\x66\x44\x03\xCF\x75\xDF\x48\x8B\x7D\x60\x3D"
		"\x5B\xBC\x4A\x6A\x0F\x85\x47\x01\x00\x00\x4D\x8B\x4B\x20\xBF"
		"\x08\x00\x00\x00\x49\x63\x41\x3C\x42\x8B\x84\x08\x88\x00\x00"
		"\x00\x49\x03\xC1\x48\x89\x45\xE0\x44\x8B\x50\x20\x44\x8B\x58"
		"\x24\x4D\x03\xD1\x8B\x58\x18\x4D\x03\xD9\x0F\x1F\x00\x85\xDB"
		"\x0F\x84\xFF\x00\x00\x00\x41\x8B\x12\x49\x03\xD1\x33\xC0\x0F"
		"\xB6\x0A\x0F\x1F\x40\x00\x66\x0F\x1F\x84\x00\x00\x00\x00\x00"
		"\xC1\xC8\x0D\x48\x8D\x52\x01\x0F\xBE\xC9\x03\xC1\x0F\xB6\x0A"
		"\x84\xC9\x75\xED\x3D\xA4\x4E\x0E\xEC\x74\x2E\x3D\xAA\xFC\x0D"
		"\x7C\x74\x27\x3D\xAC\x33\x06\x03\x74\x20\x3D\x66\x19\xDA\x75"
		"\x74\x19\x3D\xBC\x22\x0D\x47\x74\x12\x3D\xFB\x97\xFD\x0F\x74"
		"\x0B\x3D\x7C\xC4\x22\x59\x0F\x85\x8C\x00\x00\x00\x48\x8B\x4D"
		"\xE0\x45\x0F\xB7\x03\x8B\x51\x1C\x49\x03\xD1\x3D\xA4\x4E\x0E"
		"\xEC\x75\x09\x46\x8B\x24\x82\x4D\x03\xE1\xEB\x66\x3D\xAA\xFC"
		"\x0D\x7C\x75\x09\x46\x8B\x2C\x82\x4D\x03\xE9\xEB\x56\x3D\xAC"
		"\x33\x06\x03\x75\x09\x46\x8B\x34\x82\x4D\x03\xF1\xEB\x46\x3D"
		"\x66\x19\xDA\x75\x75\x0D\x42\x8B\x04\x82\x49\x03\xC1\x48\x89"
		"\x45\x50\xEB\x32\x3D\xBC\x22\x0D\x47\x75\x09\x42\x8B\x34\x82"
		"\x49\x03\xF1\xEB\x22\x3D\xFB\x97\xFD\x0F\x75\x0D\x42\x8B\x04"
		"\x82\x49\x03\xC1\x48\x89\x45\x58\xEB\x0E\x3D\x7C\xC4\x22\x59"
		"\x75\x07\x46\x8B\x3C\x82\x4D\x03\xF9\xB8\xFF\xFF\x00\x00\x66"
		"\x03\xF8\x49\x83\xC2\x04\x49\x83\xC3\x02\xFF\xCB\x66\x85\xFF"
		"\x0F\x85\xF9\xFE\xFF\xFF\x48\x8B\x5D\x50\x4C\x8B\x55\x58\x4C"
		"\x8B\x5D\xC8\x48\x8B\x7D\x60\x4D\x85\xE4\x74\x1E\x4D\x85\xED"
		"\x74\x19\x4D\x85\xF6\x74\x14\x48\x85\xDB\x74\x0F\x48\x85\xF6"
		"\x74\x0A\x4D\x85\xD2\x74\x05\x4D\x85\xFF\x75\x4F\x4D\x8B\x1B"
		"\x4C\x89\x5D\xC8\x4C\x3B\xDF\x0F\x85\x46\xFE\xFF\xFF\x4D\x85"
		"\xE4\x0F\x84\x70\x01\x00\x00\x4D\x85\xED\x0F\x84\x67\x01\x00"
		"\x00\x4D\x85\xF6\x0F\x84\x5E\x01\x00\x00\x48\x85\xDB\x0F\x84"
		"\x55\x01\x00\x00\x48\x85\xF6\x0F\x84\x4C\x01\x00\x00\x4D\x85"
		"\xD2\x0F\x84\x43\x01\x00\x00\x4D\x85\xFF\x0F\x84\x3A\x01\x00"
		"\x00\x48\x8D\x55\x50\xB9\x01\x00\x00\x00\x41\xFF\xD7\x48\x8D"
		"\x4D\xE0\xC7\x45\xE0\x5B\x57\x48\x5D\xC7\x45\xE4\x20\x4C\x4C"
		"\x0A\xC6\x45\xE8\x00\xFF\xD6\x48\x8B\x4D\x48\x41\xFF\xD4\x48"
		"\x85\xC0\x74\x1D\xC7\x45\xC8\x5B\x57\x48\x5D\x48\x8D\x4D\xC8"
		"\xC7\x45\xCC\x20\x47\x50\x41\x66\xC7\x45\xD0\x0A\x00\xE9\xE3"
		"\x00\x00\x00\xFF\xD3\x8B\xC8\xC7\x45\xC8\x5B\x57\x48\x5D\x83"
		"\xE1\x0F\xC7\x45\xCC\x20\x45\x52\x52\x83\xF9\x0A\x66\xC7\x45"
		"\xD0\x3A\x20\x44\x8B\xC0\x66\xC7\x45\xDA\x0A\x00\xBA\x30\x00"
		"\x00\x00\x41\xB9\x37\x00\x00\x00\x8B\xC2\x41\x0F\x43\xC1\x41"
		"\xC1\xE8\x04\x02\xC1\x41\x8B\xC8\x83\xE1\x0F\x88\x45\xD9\x83"
		"\xF9\x0A\x8B\xC2\x41\x0F\x43\xC1\x41\xC1\xE8\x04\x02\xC1\x41"
		"\x8B\xC8\x83\xE1\x0F\x88\x45\xD8\x83\xF9\x0A\x8B\xC2\x41\x0F"
		"\x43\xC1\x41\xC1\xE8\x04\x02\xC1\x41\x8B\xC8\x83\xE1\x0F\x88"
		"\x45\xD7\x83\xF9\x0A\x8B\xC2\x41\x0F\x43\xC1\x41\xC1\xE8\x04"
		"\x02\xC1\x41\x8B\xC8\x83\xE1\x0F\x88\x45\xD6\x83\xF9\x0A\x8B"
		"\xC2\x41\x0F\x43\xC1\x41\xC1\xE8\x04\x02\xC1\x41\x8B\xC8\x83"
		"\xE1\x0F\x88\x45\xD5\x83\xF9\x0A\x8B\xC2\x41\x0F\x43\xC1\x41"
		"\xC1\xE8\x04\x02\xC1\x41\x8B\xC8\x83\xE1\x0F\x88\x45\xD4\x83"
		"\xF9\x0A\x8B\xC2\x41\x0F\x43\xC1\x41\xC1\xE8\x04\x02\xC1\x48"
		"\x8D\x4D\xC8\x41\x83\xF8\x0A\x88\x45\xD3\x41\x0F\x43\xD1\x41"
		"\x02\xD0\x88\x55\xD2\xFF\xD6\x8B\x4D\x50\x33\xD2\x41\xFF\xD7"
		"\x49\x8B\xC6\x48\x83\xC4\x58\x41\x5F\x41\x5E\x41\x5D\x41\x5C"
		"\x5F\x5E\x5B\x5D\xC3";

	constexpr SIZE_T x64ShellcodeSize = sizeof(x64Shellcode) - 1;

	
	constexpr ACCESS_MASK ProcessAccess = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE;

	//
	// https://docs.microsoft.com/en-us/windows/win32/sysinfo/verifying-the-system-version
	//
	BOOL CheckWindowsVersion(DWORD dwMajorVersion, DWORD dwMinorVersion,
		WORD wServicePackMajor, WORD wServicePackMinor, int op)
	{
		// Initialize the OSVERSIONINFOEX structure
		OSVERSIONINFOEX osvi;

		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		osvi.dwMajorVersion = dwMajorVersion;
		osvi.dwMinorVersion = dwMinorVersion;
		osvi.wServicePackMajor = wServicePackMajor;
		osvi.wServicePackMinor = wServicePackMinor;

		// Initialize the type mask
		DWORD dwTypeMask = VER_MAJORVERSION | VER_MINORVERSION |
			VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR;

		// Initialize the condition mask
		DWORDLONG dwlConditionMask = 0;

		VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);
		VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, op);
		VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, op);
		VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMINOR, op);

		// Perform the test
		return VerifyVersionInfo(&osvi, dwTypeMask, dwlConditionMask);
	}

	//
	// Based on:
	// http://securityxploded.com/ntcreatethreadex.php
	//
	HANDLE MyCreateRemoteThread(HANDLE hProcess,
								LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, USHORT targetProcessArch)
	{
#ifndef _WIN64
		if (targetProcessArch == IMAGE_FILE_MACHINE_AMD64)
		{
			// WOW64 to x64 native, use heaven's gate.
			return (HANDLE)CreateRemoteThread64(
				HANDLE_TO_DWORD64(hProcess), PTR_TO_DWORD64(lpStartAddress), PTR_TO_DWORD64(lpParameter));
		}
#endif // _WIN64

		using NtCreateThreadEx_t = NTSTATUS(WINAPI *)(
			OUT PHANDLE hThread,
			IN ACCESS_MASK DesiredAccess,
			IN LPVOID ObjectAttributes,
			IN HANDLE ProcessHandle,
			IN LPTHREAD_START_ROUTINE lpStartAddress,
			IN LPVOID lpParameter,
			IN BOOL CreateSuspended,
			IN ULONG_PTR StackZeroBits,
			IN ULONG_PTR SizeOfStackCommit,
			IN ULONG_PTR SizeOfStackReserve,
			OUT LPVOID lpBytesBuffer);

		static NtCreateThreadEx_t pNtCreateThreadEx = []()
		{
			// Only needed for Windows Vista and 7.
			if (CheckWindowsVersion(6, 0, 0, 0, VER_GREATER_EQUAL) &&
				!CheckWindowsVersion(6, 2, 0, 0, VER_GREATER_EQUAL))
			{
				HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
				if (hNtdll)
				{
					return (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
				}
			}

			return (NtCreateThreadEx_t) nullptr;
		}();

		LPSECURITY_ATTRIBUTES lpThreadAttributes = nullptr;
		DWORD dwCreationFlags = 0;

		if (pNtCreateThreadEx)
		{
			HANDLE hThread;
			ULONG_PTR bOutBuffer1[2];
			ULONG_PTR bOutBuffer2[1];
			struct
			{
				ULONG_PTR Size;
				ULONG_PTR Unknown1;
				ULONG_PTR nBuf1Size;
				void *pBuf1;
				ULONG_PTR Unknown2;
				ULONG_PTR Unknown3;
				ULONG_PTR nBuf2Size;
				void *pBuf2;
				ULONG_PTR Unknown4;
			} param = {sizeof(param), 0x10003, sizeof(ULONG_PTR) * 2, bOutBuffer1, 0, 0x10004, sizeof(ULONG_PTR), bOutBuffer2, 0};

			NTSTATUS result = pNtCreateThreadEx(&hThread, 0x1FFFFF, lpThreadAttributes,
												hProcess, lpStartAddress, lpParameter, (dwCreationFlags & CREATE_SUSPENDED) ? TRUE : FALSE, 0, 0, 0, &param);
			if (result < 0)
			{
				SetLastError(LsaNtStatusToWinError(result));
				return nullptr;
			}

			return hThread;
		}

		return CreateRemoteThread(hProcess, lpThreadAttributes, 0, lpStartAddress, lpParameter, dwCreationFlags, nullptr);
	}

	//
	// Based on:
	// https://github.com/m417z/global-inject-demo
	//
	ULONG_PTR EncodeWow64ApcRoutine(ULONG_PTR ApcRoutine)
	{
		return (ULONG64)((-(INT64)ApcRoutine) << 2);
	}

	//
	// Based on: https://github.com/m417z/global-inject-demo
	//
	BOOL MyQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData, USHORT targetProcessArch)
	{
#ifndef _WIN64
		if (targetProcessArch == IMAGE_FILE_MACHINE_AMD64) {
			// WOW64 to x64 native, use heaven's gate.
			//
			// "Microsoft added a validation to prevent a programming error:
			// If you try to queue an APC from a 32 bit process to a 64 bit
			// process and you use a 32 bit address, you'll get this status code:
			// [...] STATUS_INVALID_HANDLE"
			// https://repnz.github.io/posts/apc/wow64-user-apc/
			return NtQueueApcThread64(
				HANDLE_TO_DWORD64(hThread), PTR_TO_DWORD64(pfnAPC), (DWORD64)dwData, 0, 0);
		}
#endif // _WIN64

		using NtQueueApcThread_t = DWORD(WINAPI*)(
			IN HANDLE ThreadHandle,
			IN PVOID ApcDispatchRoutine,
			IN ULONG_PTR SystemArgument1,
			IN ULONG_PTR SystemArgument2,
			IN ULONG_PTR SystemArgument3
			);

		static NtQueueApcThread_t pNtQueueApcThread = []() {
			HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
			if (hNtdll) {
				return (NtQueueApcThread_t)GetProcAddress(hNtdll, "NtQueueApcThread");
			}

			return (NtQueueApcThread_t)nullptr;
		}();

		if (!pNtQueueApcThread) {
			SetLastError(ERROR_PROC_NOT_FOUND);
			return FALSE;
		}

#ifdef _WIN64
		if (targetProcessArch == IMAGE_FILE_MACHINE_I386) {
			// x64 native to WOW64, encode address.
			pfnAPC = (PAPCFUNC)EncodeWow64ApcRoutine((ULONG64)pfnAPC);
		}
#endif // _WIN64

		NTSTATUS result = pNtQueueApcThread(hThread, pfnAPC, dwData, 0, 0);
		if (result < 0) {
			SetLastError(LsaNtStatusToWinError(result));
			return FALSE;
		}

		return TRUE;
	}

	USHORT GetProcessArch(HANDLE hProcess)
	{
		// For now, only IMAGE_FILE_MACHINE_I386 and IMAGE_FILE_MACHINE_AMD64.
		// TODO: Use IsWow64Process2 if available.

#ifndef _WIN64
		SYSTEM_INFO siSystemInfo;
		GetNativeSystemInfo(&siSystemInfo);
		if (siSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		{
			// 32-bit machine, only one option.
			return IMAGE_FILE_MACHINE_I386;
		}
#endif // _WIN64

		BOOL bIsWow64Process;
		if (IsWow64Process(hProcess, &bIsWow64Process) && bIsWow64Process)
		{
			return IMAGE_FILE_MACHINE_I386;
		}

		return IMAGE_FILE_MACHINE_AMD64;
	}

}

DWORD InjectDllEx(HANDLE hProcess, HANDLE hThreadForAPC, wchar_t *dll32Path, wchar_t *dll64Path)
{
	const BYTE *shellcode;
	size_t shellcodeSize;
	std::wstring dllPath;

	USHORT targetProcessArch = GetProcessArch(hProcess);

	switch (targetProcessArch)
	{
	case IMAGE_FILE_MACHINE_I386:
		if (hThreadForAPC) {
			shellcode = x32APCShellcode;
			shellcodeSize = x32APCShellcodeSize;
		}
		else {
			shellcode = x32Shellcode;
			shellcodeSize = x32ShellcodeSize;
		}
		dllPath = std::wstring(dll32Path);
		break;

	case IMAGE_FILE_MACHINE_AMD64:
		shellcode = x64Shellcode;
		shellcodeSize = x64ShellcodeSize;
		dllPath = std::wstring(dll64Path);
		break;

	default:
		return ERROR_INVALID_PARAMETER;
	}

	size_t dllPathBytesSize = (dllPath.length() + 1) * sizeof(WCHAR);
	size_t shellcodeSizeAligned = (shellcodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);

	// Allocate enough memory in the remote process's address space
	// to hold the shellcode and the dll path.
	void *pRemoteCode = VirtualAllocEx(
		hProcess, nullptr, shellcodeSizeAligned + dllPathBytesSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemoteCode == nullptr)
	{
		return GetLastError();
	}

	auto remoteCodeCleanup = wil::scope_exit([hProcess, pRemoteCode]
												{ VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE); });

	// Write our shellcode into the remote process.
	if (!WriteProcessMemory(hProcess, pRemoteCode, shellcode, shellcodeSize, nullptr))
	{
		return GetLastError();
	}

	// Write the DLL path directly after the shellcode
	void *pRemoteDllPath = reinterpret_cast<BYTE *>(pRemoteCode) + shellcodeSizeAligned;
	if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath.c_str(), dllPathBytesSize, nullptr))
	{
		return GetLastError();
	}

	// Mark shellcode as executable.
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, pRemoteCode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect))
	{
		return GetLastError();
	}

	if (hThreadForAPC) {
		// Queue the APC to the target thread
		// The APC will execute when the thread enters an alertable wait state
		if (!MyQueueUserAPC(reinterpret_cast<PAPCFUNC>(pRemoteCode), hThreadForAPC, reinterpret_cast<ULONG_PTR>(pRemoteDllPath), targetProcessArch))
		{
			return GetLastError();
		}
	} else {
		wil::unique_process_handle hRemoteThread(MyCreateRemoteThread(hProcess,
																	reinterpret_cast<LPTHREAD_START_ROUTINE>(pRemoteCode), pRemoteDllPath, targetProcessArch));
		if (!hRemoteThread)
		{
			return GetLastError();
		}

		WaitForSingleObject(hRemoteThread.get(), INFINITE);
	}

	remoteCodeCleanup.release();

	return ERROR_SUCCESS;
}

// Exported
extern "C"
{
	DWORD __declspec(dllexport) InjectDll(HANDLE hProcess, wchar_t *dll32Path, wchar_t *dll64Path)
	{

		// We check whether the process began running or not. If it didn't, it's
		// supposed to have only one thread which has its instruction pointer at
		// RtlUserThreadStart. For other cases, we assume the main thread was
		// resumed.
		//
		// If the process didn't begin running, creating a remote thread might be
		// too early and unsafe. One known problem with this is with console apps -
		// if we trigger console initialization (KERNELBASE!ConsoleCommitState)
		// before the parent process notified csrss.exe (KERNELBASE!CsrClientCallServer),
		// csrss.exe returns an access denied error and the parent's CreateProcess
		// call fails.

#ifndef _WIN64
		Wow64ExtInitialize();
#endif // _WIN64

		// ==================
		// Find and initialize the function pointers
		// ==================

		HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
		THROW_LAST_ERROR_IF_NULL(hNtdll);

		using NtGetNextThread_t = NTSTATUS(NTAPI*)(
			_In_ HANDLE ProcessHandle,
			_In_opt_ HANDLE ThreadHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ ULONG HandleAttributes,
			_In_ ULONG Flags,
			_Out_ PHANDLE NewThreadHandle
		);

		NtGetNextThread_t NtGetNextThread = (NtGetNextThread_t)GetProcAddress(hNtdll, "NtGetNextThread");
		THROW_LAST_ERROR_IF_NULL(NtGetNextThread);

		DWORD64 pRtlUserThreadStart;
#ifdef _WIN64
		pRtlUserThreadStart = (DWORD64)GetProcAddress(hNtdll, "RtlUserThreadStart");
#else // !_WIN64
		SYSTEM_INFO siSystemInfo;
		GetNativeSystemInfo(&siSystemInfo);
		if (siSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
			// 32-bit machine.
			pRtlUserThreadStart = PTR_TO_DWORD64(GetProcAddress(hNtdll, "RtlUserThreadStart"));
		}
		else {
			DWORD64 hNtdll64 = GetModuleHandle64(L"ntdll.dll");
			if (hNtdll64 == 0) {
				THROW_WIN32(ERROR_MOD_NOT_FOUND);
			}

			pRtlUserThreadStart = GetProcAddress64(hNtdll64, "RtlUserThreadStart");
		}
#endif // _WIN64
		THROW_LAST_ERROR_IF(pRtlUserThreadStart == 0);

		// ===================
		// Try to find a thread in the target process that we can suspend and use for our APC injection.
		// ===================
		wil::unique_process_handle suspendedThread;

		DWORD processAccess = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | ProcessAccess;

		wil::unique_process_handle thread1;
		THROW_IF_NTSTATUS_FAILED(NtGetNextThread(hProcess, nullptr, processAccess, 0, 0, &thread1));

		wil::unique_process_handle thread2;
		NTSTATUS status = NtGetNextThread(hProcess, thread1.get(), processAccess, 0, 0, &thread2);

		if (status == STATUS_NO_MORE_ENTRIES) {
			// Exactly one thread.
			DWORD previousSuspendCount = SuspendThread(thread1.get());
			THROW_LAST_ERROR_IF(previousSuspendCount == (DWORD)-1);

			if (previousSuspendCount == 0) {
				// The thread was already running.
				ResumeThread(thread1.get());
			}
			else {
				suspendedThread = std::move(thread1);
			}
		}
		else {
			THROW_IF_NTSTATUS_FAILED(status);
		}

		if (suspendedThread) {
			auto suspendThreadCleanup = wil::scope_exit([&suspendedThread] {
				ResumeThread(suspendedThread.get());
			});

			bool threadNotStartedYet = false;

#ifdef _WIN64
			CONTEXT c;
			c.ContextFlags = CONTEXT_CONTROL;
			THROW_IF_WIN32_BOOL_FALSE(GetThreadContext(suspendedThread.get(), &c));
			if (c.Rip == pRtlUserThreadStart) {
				threadNotStartedYet = true;
			}
#else // !_WIN64
			SYSTEM_INFO siSystemInfo;
			GetNativeSystemInfo(&siSystemInfo);
			if (siSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
				// 32-bit machine.
				CONTEXT c;
				c.ContextFlags = CONTEXT_CONTROL;
				THROW_IF_WIN32_BOOL_FALSE(GetThreadContext(suspendedThread.get(), &c));
				if (c.Eip == pRtlUserThreadStart) {
					threadNotStartedYet = true;
				}
			}
			else {
				_CONTEXT64 c;
				c.ContextFlags = CONTEXT64_CONTROL;
				THROW_IF_WIN32_BOOL_FALSE(GetThreadContext64(suspendedThread.get(), &c));
				if (c.Rip == pRtlUserThreadStart) {
					threadNotStartedYet = true;
				}
			}
#endif // _WIN64

			if (threadNotStartedYet) {
				return InjectDllEx(hProcess, suspendedThread.get(), dll32Path, dll64Path);
			}
		}


		// ===================
		// Inject the DLL without APC as we couldn't find a suitable thread
		// ===================
		return InjectDllEx(hProcess, nullptr, dll32Path, dll64Path);
	}
}
