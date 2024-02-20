#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include "XorStr.hpp"
#include <string>
#include <sstream>
#include "Hooker.hpp"

void HandleError(const std::string& msg);
DWORD WINAPI StartRoutine(LPVOID lpParam);

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        //(void)MessageBox(NULL, XorStr("DLL_PROCESS_ATTACH"), XorStr("Success"), MB_OK);
        CreateThread(NULL, NULL, StartRoutine, hinstDLL, NULL, NULL);
        break;

    case DLL_THREAD_ATTACH:
        //(void)MessageBox(NULL, XorStr("DLL_THREAD_ATTACH"), XorStr("Success"), MB_OK);
        break;

    case DLL_THREAD_DETACH:
        //(void)MessageBox(NULL, XorStr("DLL_THREAD_DETACH"), XorStr("Success"), MB_OK);
        break;

    case DLL_PROCESS_DETACH:
        //(void)MessageBox(NULL, XorStr("DLL_PROCESS_DETACH"), XorStr("Success"), MB_OK);
        break;
    }
    return TRUE;
}

void HandleError(const std::string& msg)
{
    std::ostringstream s;
    s << msg << XorStr("\nError code: ") << GetLastError();

    if (GetConsoleWindow())
    {
        std::cout << s.str();
    }
    else
    {
        MessageBox(NULL, s.str().c_str(), XorStr("Error"), MB_OK);
    }
}

DWORD WINAPI StartRoutine(LPVOID lpParam)
{
    //MessageBox(NULL, XorStr("Routine"), XorStr("Work"), MB_OK);

    if (!AllocConsole())
    {
        HandleError(XorStr("Failed to attach console!"));
        // TODO: this is potentially bad since we definitely did not manually map in a perfect way like the Windows loader does, so we can't rely on it to unload
        // It definitely does not work currently and the bytes are left in memory.
        FreeLibraryAndExitThread(static_cast<HMODULE>(lpParam), 0);
    }
    (void)freopen_s(reinterpret_cast<FILE**>(stdout), XorStr("CONOUT$"), "w", stdout);
    (void)freopen_s(reinterpret_cast<FILE**>(stderr), XorStr("CONOUT$"), "w", stderr);
    std::cout << XorStr("Console initialized!\n");

    bool bHookWsaSend{ false };

    const auto* pWsaSendFuncAddr{ (uintptr_t*)((uintptr_t)GetModuleHandle("WS2_32.dll") + 0x1F60) };
    const auto* pLogShellcodeAddr{ (uintptr_t*)Hooker::WsaSend::LogShellcode };
    const auto* pWsaSendRetAddr{ (uintptr_t*)((char*)pWsaSendFuncAddr + 0xF) };
    void* pTrampolineBlock{ VirtualAlloc(nullptr, 0xFF, MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

    memcpy(&Hooker::WsaSend::trampolineShellcode[23], &pLogShellcodeAddr, sizeof(pLogShellcodeAddr));
    memcpy(&Hooker::WsaSend::trampolineShellcode[sizeof(Hooker::WsaSend::trampolineShellcode) - 8], &pWsaSendRetAddr, sizeof(pWsaSendFuncAddr));
    memcpy(pTrampolineBlock, Hooker::WsaSend::trampolineShellcode, sizeof(Hooker::WsaSend::trampolineShellcode));
    memcpy(&Hooker::WsaSend::hookBytes[6], &pTrampolineBlock, sizeof(pTrampolineBlock));

    std::cout << XorStr("Base addr: ") << std::hex << std::uppercase << lpParam << XorStr(" press INS to exit\n");
    std::cout << XorStr("Log Shellcode addr: ") << std::hex << std::uppercase << pLogShellcodeAddr << '\n';
    std::cout << XorStr("Trampoline Shellcode addr: ") << std::hex << std::uppercase << pTrampolineBlock << '\n';
    std::cout << XorStr("WSASend addr: ") << std::hex << std::uppercase << pWsaSendFuncAddr << '\n';
    std::cout << XorStr("WSASend ret addr: ") << std::hex << std::uppercase << pWsaSendRetAddr << '\n';
    std::cout << "\n";

    while (!(GetAsyncKeyState(VK_INSERT) & 0x1))
    {
        if (GetAsyncKeyState(VK_F1) & 0x1)
        {
            std::cout << (bHookWsaSend ? "Removing hook...\n" : "Placing hook...\n");

            bHookWsaSend = !bHookWsaSend;

            if (bHookWsaSend)
            {
                Hooker::WsaSend::Hook((void*)pWsaSendFuncAddr);
            }
            else
            {
                Hooker::WsaSend::UnHook((void*)pWsaSendFuncAddr);
            }

            Sleep(100);
        }

        Sleep(10);
    }

    // TODO Hooker class that will unhook once it goes out of scope, and make its scope tighter around the while loop
    Hooker::WsaSend::UnHook((void*)pWsaSendFuncAddr);

    if (!VirtualFree(pTrampolineBlock, 0, MEM_RELEASE))
    {
        HandleError(XorStr("VirtualFree pTrampolineBlock failed!"));
    }

    (void)fclose(stdout);
    (void)fclose(stderr);

    if (!FreeConsole())
    {
        HandleError(XorStr("Failed to free console!"));
    }

    // TODO: this is potentially bad since we definitely did not manually map in a perfect way like the Windows loader does, so we can't rely on it to unload
    // It definitely does not work currently and the bytes are left in memory.
    FreeLibraryAndExitThread(static_cast<HMODULE>(lpParam), 0);
}