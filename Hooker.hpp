#pragma once
#include <cstdint>

static_assert(sizeof(uintptr_t) == 8, "Is this a x64 build?");

namespace Hooker
{
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

        inline void LogShellcode(const WSABUF* const buf)
        {
            if (!buf) return;
            if (!buf->buf) return;

            for (size_t i{ 0 }; i < buf->len; i++)
            {
                printf("%02hhX ", buf->buf[i]);
            }
            printf("\n\n");
        }

        inline void UnHook(void* const pWsaSendFuncAddr)
        {
            DWORD oldProtect;
            VirtualProtect(pWsaSendFuncAddr, sizeof(originalBytes), PAGE_READWRITE, &oldProtect);

            memcpy(pWsaSendFuncAddr, originalBytes, sizeof originalBytes);

            static DWORD unused;
            VirtualProtect(pWsaSendFuncAddr, sizeof(originalBytes), oldProtect, &unused);
        }

        inline void Hook(void* const pWsaSendFuncAddr)
        {
            DWORD oldProtect;
            VirtualProtect(pWsaSendFuncAddr, sizeof(originalBytes), PAGE_READWRITE, &oldProtect);

            memcpy(pWsaSendFuncAddr, hookBytes, sizeof hookBytes);

            static DWORD unused;
            VirtualProtect(pWsaSendFuncAddr, sizeof(originalBytes), oldProtect, &unused);
        }
    }
}
