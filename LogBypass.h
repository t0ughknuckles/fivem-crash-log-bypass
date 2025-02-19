#pragma once
#include <windows.h>
#include <cstdarg>

#include "detours.h"
#pragma comment(lib, "detours-x64.lib")

typedef const char** (__fastcall* sub_func)(const char**, const char*, ...);

uintptr_t baseAddress = (uintptr_t)GetModuleHandle(0);
sub_func function = (sub_func)(baseAddress + 0x6E4A0);

const char** __fastcall Hook(const char** a1, const char* a2, ...)
{
    va_list args;
    va_start(args, a2);

    if (strstr(a2, "https://crash-ingress.fivem.net")) 
        a2 = "https://google.com/";

    const char* modified_args[] = { a2, va_arg(args, const char*) };
    const char** result = function(a1, modified_args[0], modified_args[1]);
    va_end(args);
    return result;
}

DWORD WINAPI InitLogBypass() 
{
    DWORD old;
    if (!VirtualProtect(function, 1, PAGE_EXECUTE_READWRITE, &old))
    {
        MessageBoxA(0, "failed to change mem protection", "err", MB_OK | MB_ICONERROR);
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (DetourAttach(&(PVOID&)function, Hook) != NO_ERROR)
    {
        MessageBoxA(0, "failed to hook function", "err", MB_OK | MB_ICONERROR);
        DetourTransactionAbort();
        return 1;
    }

    if (DetourTransactionCommit() != NO_ERROR) 
    {
        MessageBoxA(0, "failed to commit hook", "err", MB_OK | MB_ICONERROR);
        return 1;
    }

    return 0;
}
