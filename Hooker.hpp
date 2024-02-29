#pragma once
#include <cstdint>
#include <fstream>

static_assert(sizeof(uintptr_t) == 8, "Is this a x64 build?");

extern std::ofstream file;

namespace Hooker
{
	inline void LogShellcode(const LPWSABUF buf, const DWORD bufferCount)
	{
		if (!buf) return;

		for (DWORD currBufIndex{ 0 }; currBufIndex < bufferCount; currBufIndex++)
		{
			const LPWSABUF currBuff{ &buf[currBufIndex] };
			if (!currBuff) continue;
			if (currBuff->len <= 0) continue;

			if (currBufIndex == 0
				&& currBuff->len == 2
				&& (currBuff->buf[0] == 0x00 || currBuff->buf[0] == 0x10 || currBuff->buf[0] == 0x20 || currBuff->buf[0] == 0x30)
				&& currBuff->buf[1] == 0x00)
				return; // skip this heartbeat thingy

			if (bufferCount == 2
				&& currBuff->len == 4)
				return; // skip the timer? these packets just increment

			if (currBufIndex < 4) continue;

			printf("[%ld/%ld][%02lu] ", currBufIndex + 1, bufferCount, currBuff->len);
			for (size_t i{ 0 }; i < currBuff->len; i++)
			{
				printf("%02hhX ", currBuff->buf[i]);
			}

			printf("\n");

			file.write(currBuff->buf, currBuff->len);
		}
	}

	namespace WsaSend
	{
		inline unsigned char trampolineShellcode[]{
			0x51,                                           // push rcx
			0x53,                                           // push rbx
			0x52,                                           // push rdx
			0x41, 0x50,                                     // push r8
			0x48, 0x8B, 0xCA,                               // mov rcx, rdx
			0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00,       // sub rsp, 0x100
			0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, // call procedure
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Placeholder for LogShellcode address
			0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00,       // add rsp, 0x100
			0x41, 0x58,                                     // pop r8
			0x5A,                                           // pop rdx
			0x5B,                                           // pop rbx
			0x59,                                           // pop rcx
			0x48, 0x89, 0x5C, 0x24, 0x08,                   // mov [rsp+0x8], rbx
			0x48, 0x89, 0x6C, 0x24, 0x10,                   // mov [rsp+0x10], rbp
			0x48, 0x89, 0x74, 0x24, 0x18,                   // mov [rsp+0x18], rsi
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp qword ptr [rip + 0x0]
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Address placeholder for return after hook
		};

		inline constexpr unsigned char originalBytes[]{
			0x48, 0x89, 0x5C, 0x24, 0x08,                   // mov [rsp+08], rbx
			0x48, 0x89, 0x6C, 0x24, 0x10,                   // mov [rsp+10], rbp
			0x48, 0x89, 0x74, 0x24, 0x18                    // mov [rsp+18], rsi
		};

		inline unsigned char hookBytes[]{
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp qword ptr [rip + 0x0]
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Address placeholder
			0x90                                            // nop
		};

		static_assert(sizeof(originalBytes) == sizeof(hookBytes), "Hook bytes size differs from original bytes size");

		inline void UnHook(void* const pHookAddress)
		{
			DWORD oldProtect;
			VirtualProtect(pHookAddress, sizeof(originalBytes), PAGE_READWRITE, &oldProtect);

			memcpy(pHookAddress, originalBytes, sizeof originalBytes);

			static DWORD unused;
			VirtualProtect(pHookAddress, sizeof(originalBytes), oldProtect, &unused);
		}

		inline void Hook(void* const pHookAddress)
		{
			DWORD oldProtect;
			VirtualProtect(pHookAddress, sizeof(originalBytes), PAGE_READWRITE, &oldProtect);

			memcpy(pHookAddress, hookBytes, sizeof hookBytes);

			static DWORD unused;
			VirtualProtect(pHookAddress, sizeof(originalBytes), oldProtect, &unused);
		}
	}

	namespace WsaSendTo
	{
		inline unsigned char trampolineShellcode[]{
			0x50,                                           // push rax
			0x51,                                           // push rcx
			0x53,                                           // push rbx
			0x52,                                           // push rdx
			0x41, 0x50,                                     // push r8
			0x48, 0x8B, 0xCA,                               // mov rcx, rdx     first argument for log func
			0x49, 0x8B, 0xD0,                               // mov rdx, r8      second argument for log func
			0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00,       // sub rsp, 0x100
			0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,             // call qword ptr [rip+0x02]
			0xEB, 0x08,                                     // jmp short (to next instruction + 0x08)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Address placeholder
			0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00,       // add rsp, 0x100
			0x41, 0x58,                                     // pop r8
			0x5A,                                           // pop rdx
			0x5B,                                           // pop rbx
			0x59,                                           // pop rcx
			0x58,                                           // pop rax
			0x48, 0x8B, 0xC4,                               // mov rax, rsp
			0x48, 0x89, 0x58, 0x08,                         // mov [rax+0x8], rbx
			0x48, 0x89, 0x68, 0x10,                         // mov [rax+0x10], rbp
			0x48, 0x89, 0x70, 0x18,                         // mov [rax+0x18], rsi
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp qword ptr [rip+0x00]
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Address placeholder
		};

		inline constexpr unsigned char originalBytes[]{
			0x48, 0x8B, 0xC4,                               // mov rax, rsp
			0x48, 0x89, 0x58, 0x08,                         // mov [rax+0x8], rbx
			0x48, 0x89, 0x68, 0x10,                         // mov [rax+0x10], rbp
			0x48, 0x89, 0x70, 0x18                          // mov [rax+0x18], rsi
		};

		inline unsigned char hookBytes[]{
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp qword ptr [rip+0x00]
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Address placeholder
			0x90                                            // nop (No Operation, used for padding/instruction alignment)
		};

		static_assert(sizeof originalBytes == sizeof hookBytes, "Hook bytes size differs from original bytes size");

		inline void UnHook(void* const pHookAddress)
		{
			DWORD oldProtect;
			VirtualProtect(pHookAddress, sizeof(originalBytes), PAGE_READWRITE, &oldProtect);

			memcpy(pHookAddress, originalBytes, sizeof originalBytes);

			static DWORD unused;
			VirtualProtect(pHookAddress, sizeof(originalBytes), oldProtect, &unused);
		}

		inline void Hook(void* const pHookAddress)
		{
			DWORD oldProtect;
			VirtualProtect(pHookAddress, sizeof(originalBytes), PAGE_READWRITE, &oldProtect);

			memcpy(pHookAddress, hookBytes, sizeof hookBytes);

			static DWORD unused;
			VirtualProtect(pHookAddress, sizeof(originalBytes), oldProtect, &unused);
		}
	}
}
